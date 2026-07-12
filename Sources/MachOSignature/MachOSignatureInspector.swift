//
//  MachOSignatureInspector.swift
//  MachOSignature
//
//  Created by Osama Almanasra on 08/07/2026.
//
//  https://www.linkedin.com/in/osamamanasra
//
//  A dependency-free, pure-Swift reader for the code-signing information
//  embedded in a Mach-O binary. It memory-maps the file, parses the Mach-O
//  (thin or FAT / arm64), walks the load commands to LC_CODE_SIGNATURE,
//  parses the embedded code-signature SuperBlob → CodeDirectory, and reports
//  the signing identifier, Team ID, and whether a CMS (distribution)
//  signature is present.
//
//  This type only *reads* facts — it makes no security decisions. For the
//  "is this the build I shipped?" check, see `SignaturePolicy`.
//

import Foundation

/// The code-signing facts read out of a Mach-O binary.
public struct MachOCodeSignature: Equatable {
    /// The signing identifier from the CodeDirectory (typically the bundle id,
    /// e.g. `com.example.app`). `nil` if the field couldn't be read.
    public let identifier: String?

    /// The 10-character Apple Developer Team ID, present on CodeDirectory
    /// version 0x20200+ signatures. `nil` for ad-hoc / platform binaries or
    /// if the field couldn't be read.
    public let teamID: String?

    /// `true` if the binary carries a non-empty CMS (BlobWrapper) blob — the
    /// signature Apple adds for App Store / TestFlight / Developer ID
    /// distribution. Ad-hoc signatures (including a locally re-signed,
    /// repackaged app) don't have one.
    public let hasCMSSignature: Bool

    /// Convenience: an otherwise well-formed signature with no CMS blob is the
    /// hallmark of an ad-hoc signature.
    public var isAdHocSigned: Bool { !hasCMSSignature }

    public init(identifier: String?, teamID: String?, hasCMSSignature: Bool) {
        self.identifier = identifier
        self.teamID = teamID
        self.hasCMSSignature = hasCMSSignature
    }
}

/// Reasons inspection can fail. These describe *structural* problems (bad
/// input, an unsigned binary) — not policy verdicts.
public enum MachOSignatureError: Error, Equatable {
    /// `Bundle.main.executablePath` was nil.
    case noExecutablePath
    /// The file couldn't be read / memory-mapped.
    case cannotReadFile
    /// The data isn't a Mach-O or FAT binary this inspector recognizes.
    case unrecognizedFormat
    /// A read ran past the end of the data (truncated or malformed input).
    case truncated(String)
    /// The binary has no `LC_CODE_SIGNATURE` load command — it is unsigned.
    case noCodeSignature
    /// `LC_CODE_SIGNATURE` was present but its blob structure was invalid.
    case malformedSignature(String)
    /// The embedded signature SuperBlob contained no CodeDirectory.
    case noCodeDirectory
}

public enum MachOSignatureInspector {

    // MARK: - Mach-O / code-signing magic constants

    private static let MH_MAGIC_64: UInt32 = 0xfeed_facf
    private static let MH_CIGAM_64: UInt32 = 0xcffa_edfe
    private static let MH_MAGIC_32: UInt32 = 0xfeed_face
    private static let MH_CIGAM_32: UInt32 = 0xcefa_edfe
    private static let FAT_MAGIC: UInt32   = 0xcafe_babe
    private static let FAT_CIGAM: UInt32   = 0xbeba_feca

    private static let LC_CODE_SIGNATURE: UInt32 = 0x1d

    // Embedded code-signature blob magics (big-endian on disk).
    private static let CSMAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xfade_0cc0
    private static let CSMAGIC_CODEDIRECTORY: UInt32       = 0xfade_0c02
    private static let CSMAGIC_BLOBWRAPPER: UInt32         = 0xfade_0b01   // CMS signature
    private static let CSSLOT_CODEDIRECTORY: UInt32        = 0
    private static let CSSLOT_SIGNATURESLOT: UInt32        = 0x10000

    private static let CPU_TYPE_ARM64: UInt32 = 0x0100_000c

    // MARK: - Entry points

    /// Inspects the running app's own main executable.
    public static func inspectMainExecutable() throws -> MachOCodeSignature {
        guard let path = Bundle.main.executablePath else {
            throw MachOSignatureError.noExecutablePath
        }
        return try inspect(url: URL(fileURLWithPath: path))
    }

    /// Inspects the Mach-O binary at `url`.
    public static func inspect(url: URL) throws -> MachOCodeSignature {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            throw MachOSignatureError.cannotReadFile
        }
        return try inspect(data: data)
    }

    /// Inspects a Mach-O binary already loaded into memory.
    public static func inspect(data: Data) throws -> MachOCodeSignature {
        guard let magic = readU32(data, 0, bigEndian: false) else {
            throw MachOSignatureError.truncated("header")
        }
        switch magic {
        case FAT_MAGIC, FAT_CIGAM:
            return try inspectFat(data)
        case MH_MAGIC_64, MH_MAGIC_32:
            return try inspectThin(data, sliceOffset: 0, bigEndian: false)
        case MH_CIGAM_64, MH_CIGAM_32:
            return try inspectThin(data, sliceOffset: 0, bigEndian: true)
        default:
            throw MachOSignatureError.unrecognizedFormat
        }
    }

    // MARK: - FAT slice selection

    private static func inspectFat(_ data: Data) throws -> MachOCodeSignature {
        // FAT headers are always big-endian.
        guard let nArch = readU32(data, 4, bigEndian: true) else {
            throw MachOSignatureError.truncated("fat header")
        }
        var chosenOffset: Int?
        var offset = 8
        for _ in 0..<Int(nArch) {
            guard let cpuType = readU32(data, offset, bigEndian: true),
                  let sliceOff = readU32(data, offset + 8, bigEndian: true) else {
                throw MachOSignatureError.truncated("fat_arch")
            }
            if cpuType == CPU_TYPE_ARM64 {
                chosenOffset = Int(sliceOff)
                break
            }
            if chosenOffset == nil { chosenOffset = Int(sliceOff) } // fallback: first slice
            offset += 20 // sizeof(fat_arch)
        }
        guard let sliceOffset = chosenOffset,
              let sliceMagic = readU32(data, sliceOffset, bigEndian: false) else {
            throw MachOSignatureError.truncated("fat slice")
        }
        let bigEndian = (sliceMagic == MH_CIGAM_64 || sliceMagic == MH_CIGAM_32)
        return try inspectThin(data, sliceOffset: sliceOffset, bigEndian: bigEndian)
    }

    // MARK: - Thin Mach-O walk

    private static func inspectThin(_ data: Data, sliceOffset: Int, bigEndian: Bool) throws -> MachOCodeSignature {
        guard let magic = readU32(data, sliceOffset, bigEndian: false) else {
            throw MachOSignatureError.truncated("slice header")
        }
        let is64 = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
        let headerSize = is64 ? 32 : 28

        guard let ncmds = readU32(data, sliceOffset + 16, bigEndian: bigEndian) else {
            throw MachOSignatureError.truncated("mach header")
        }

        var cmdOffset = sliceOffset + headerSize
        for _ in 0..<Int(ncmds) {
            guard let cmd = readU32(data, cmdOffset, bigEndian: bigEndian),
                  let cmdSize = readU32(data, cmdOffset + 4, bigEndian: bigEndian),
                  cmdSize >= 8 else {
                throw MachOSignatureError.truncated("load command")
            }
            if cmd == LC_CODE_SIGNATURE {
                guard let dataOff = readU32(data, cmdOffset + 8, bigEndian: bigEndian) else {
                    throw MachOSignatureError.truncated("LC_CODE_SIGNATURE")
                }
                // `dataoff` is relative to the start of this slice.
                return try parseSignature(data, at: sliceOffset + Int(dataOff))
            }
            cmdOffset += Int(cmdSize)
        }
        throw MachOSignatureError.noCodeSignature
    }

    // MARK: - Code-signature SuperBlob

    private static func parseSignature(_ data: Data, at start: Int) throws -> MachOCodeSignature {
        // SuperBlob fields are big-endian.
        guard let magic = readU32(data, start, bigEndian: true),
              magic == CSMAGIC_EMBEDDED_SIGNATURE,
              let count = readU32(data, start + 8, bigEndian: true) else {
            throw MachOSignatureError.malformedSignature("no embedded signature superblob")
        }

        var codeDirectoryOffset: Int?
        var hasNonEmptyCMS = false

        var indexOffset = start + 12
        for _ in 0..<Int(count) {
            guard let type = readU32(data, indexOffset, bigEndian: true),
                  let blobOff = readU32(data, indexOffset + 4, bigEndian: true) else {
                throw MachOSignatureError.truncated("blob index")
            }
            let blobStart = start + Int(blobOff)
            guard let blobMagic = readU32(data, blobStart, bigEndian: true),
                  let blobLen = readU32(data, blobStart + 4, bigEndian: true) else {
                throw MachOSignatureError.truncated("blob")
            }

            if type == CSSLOT_CODEDIRECTORY || blobMagic == CSMAGIC_CODEDIRECTORY {
                if codeDirectoryOffset == nil { codeDirectoryOffset = blobStart }
            }
            if type == CSSLOT_SIGNATURESLOT || blobMagic == CSMAGIC_BLOBWRAPPER {
                // A CMS BlobWrapper longer than its 8-byte header means a real
                // (non-empty) distribution signature is present.
                if blobLen > 8 { hasNonEmptyCMS = true }
            }
            indexOffset += 8
        }

        guard let cdOffset = codeDirectoryOffset else {
            throw MachOSignatureError.noCodeDirectory
        }

        return try readCodeDirectory(data, at: cdOffset, hasNonEmptyCMS: hasNonEmptyCMS)
    }

    // MARK: - CodeDirectory

    private static func readCodeDirectory(_ data: Data, at cd: Int, hasNonEmptyCMS: Bool) throws -> MachOCodeSignature {
        // CodeDirectory fields are big-endian.
        guard let version = readU32(data, cd + 8, bigEndian: true),
              let identOffset = readU32(data, cd + 20, bigEndian: true) else {
            throw MachOSignatureError.truncated("code directory")
        }

        // Signing identifier: C-string at (cd + identOffset).
        let identifier = readCString(data, cd + Int(identOffset))

        // Team ID exists only on version >= 0x20200 (teamOffset at cd + 48).
        var teamID: String?
        if version >= 0x0002_0200 {
            if let teamOffset = readU32(data, cd + 48, bigEndian: true), teamOffset != 0 {
                teamID = readCString(data, cd + Int(teamOffset))
            }
        }

        return MachOCodeSignature(identifier: identifier,
                                  teamID: teamID,
                                  hasCMSSignature: hasNonEmptyCMS)
    }

    // MARK: - Bounds-checked readers

    /// Reads a big-endian or host-order `UInt32` at `offset`, or `nil` if the
    /// read would run past the end of `data`.
    private static func readU32(_ data: Data, _ offset: Int, bigEndian: Bool) -> UInt32? {
        guard offset >= 0, offset + 4 <= data.count else { return nil }
        let base = data.startIndex + offset
        var value: UInt32 = 0
        for i in 0..<4 {
            value = (value << 8) | UInt32(data[base + i])
        }
        // The loop assembled the bytes big-endian. Swap if host order requested.
        return bigEndian ? value : value.byteSwapped
    }

    /// Reads a NUL-terminated C-string at `offset`, bounded to 512 bytes.
    private static func readCString(_ data: Data, _ offset: Int) -> String? {
        guard offset >= 0, offset < data.count else { return nil }
        var bytes: [UInt8] = []
        var i = data.startIndex + offset
        let end = data.endIndex
        while i < end {
            let byte = data[i]
            if byte == 0 { break }
            bytes.append(byte)
            if bytes.count > 512 { return nil } // sanity bound
            i += 1
        }
        return String(bytes: bytes, encoding: .utf8)
    }
}
