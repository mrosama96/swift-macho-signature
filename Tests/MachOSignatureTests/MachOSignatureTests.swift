//
//  MachOSignatureTests.swift
//  MachOSignatureTests
//
//  Created by Osama Almanasra on 08/07/2026.
//
//  https://www.linkedin.com/in/osamamanasra
//

import XCTest
@testable import MachOSignature

final class MachOSignatureInspectorTests: XCTestCase {

    // MARK: - Malformed / edge-case input

    func testEmptyDataThrowsTruncated() {
        XCTAssertThrowsError(try MachOSignatureInspector.inspect(data: Data())) { error in
            XCTAssertEqual(error as? MachOSignatureError, .truncated("header"))
        }
    }

    func testTooShortForMagicThrowsTruncated() {
        XCTAssertThrowsError(try MachOSignatureInspector.inspect(data: Data([0x01, 0x02]))) { error in
            XCTAssertEqual(error as? MachOSignatureError, .truncated("header"))
        }
    }

    func testUnknownMagicThrowsUnrecognized() {
        // Four bytes that decode to no known Mach-O / FAT magic.
        XCTAssertThrowsError(try MachOSignatureInspector.inspect(data: Data([0x00, 0x00, 0x00, 0x00]))) { error in
            XCTAssertEqual(error as? MachOSignatureError, .unrecognizedFormat)
        }
    }

    func testValidThinMagicButTruncatedHeader() {
        // MH_MAGIC_64 (0xFEEDFACF) as little-endian on disk: CF FA ED FE.
        // Recognized as a 64-bit thin Mach-O, then runs out of bytes reading ncmds.
        let data = Data([0xCF, 0xFA, 0xED, 0xFE])
        XCTAssertThrowsError(try MachOSignatureInspector.inspect(data: data)) { error in
            XCTAssertEqual(error as? MachOSignatureError, .truncated("mach header"))
        }
    }

    // MARK: - Real binary (macOS host)

    /// Parses an actual signed system binary end-to-end. Runs on the macOS
    /// test host; skipped elsewhere.
    func testInspectsRealSystemBinary() throws {
        let path = "/bin/ls"
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("System binary not present on this host")
        }
        let signature = try MachOSignatureInspector.inspect(url: URL(fileURLWithPath: path))
        // A signed binary always carries a CodeDirectory with an identifier.
        XCTAssertNotNil(signature.identifier)
        XCTAssertFalse(signature.identifier?.isEmpty ?? true)
    }

    // MARK: - Policy layer

    private func sig(id: String?, team: String?, cms: Bool) -> MachOCodeSignature {
        MachOCodeSignature(identifier: id, teamID: team, hasCMSSignature: cms)
    }

    func testPolicyValidWhenEverythingMatches() {
        let verdict = MachOSignatureInspector.evaluate(
            sig(id: "com.example.app", team: "ABCDE12345", cms: true),
            expectedIdentifierPrefix: "com.example.app",
            expectedTeamID: "ABCDE12345")
        XCTAssertEqual(verdict, .valid)
    }

    func testPolicyValidForExtensionIdentifierPrefix() {
        let verdict = MachOSignatureInspector.evaluate(
            sig(id: "com.example.app.share", team: "ABCDE12345", cms: true),
            expectedIdentifierPrefix: "com.example.app",
            expectedTeamID: "ABCDE12345")
        XCTAssertEqual(verdict, .valid)
    }

    func testPolicyTamperedOnIdentifierMismatch() {
        let verdict = MachOSignatureInspector.evaluate(
            sig(id: "com.attacker.repack", team: "ABCDE12345", cms: true),
            expectedIdentifierPrefix: "com.example.app",
            expectedTeamID: "ABCDE12345")
        XCTAssertEqual(verdict, .tampered(reason: "identifier mismatch: com.attacker.repack"))
    }

    func testPolicyTamperedOnTeamMismatch() {
        let verdict = MachOSignatureInspector.evaluate(
            sig(id: "com.example.app", team: "ZZZZZ99999", cms: true),
            expectedIdentifierPrefix: "com.example.app",
            expectedTeamID: "ABCDE12345")
        XCTAssertEqual(verdict, .tampered(reason: "team id mismatch: ZZZZZ99999"))
    }

    func testPolicyTamperedOnAdHocResign() {
        let verdict = MachOSignatureInspector.evaluate(
            sig(id: "com.example.app", team: "ABCDE12345", cms: false),
            expectedIdentifierPrefix: "com.example.app",
            expectedTeamID: "ABCDE12345")
        XCTAssertEqual(verdict, .tampered(reason: "missing CMS signature (ad-hoc re-sign)"))
    }

    func testIsAdHocSignedConvenience() {
        XCTAssertTrue(sig(id: "x", team: nil, cms: false).isAdHocSigned)
        XCTAssertFalse(sig(id: "x", team: "ABCDE12345", cms: true).isAdHocSigned)
    }
}
