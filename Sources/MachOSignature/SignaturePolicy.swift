//
//  SignaturePolicy.swift
//  MachOSignature
//
//  Created by Osama Almanasra on 08/07/2026.
//
//  https://www.linkedin.com/in/osamamanasra
//
//  A thin policy layer over `MachOSignatureInspector` for the common
//  anti-repackaging check: "is this binary still the build I shipped, signed
//  by my team, and not ad-hoc re-signed?"
//

import Foundation

/// The verdict of a signature policy check.
public enum SignatureVerdict: Equatable {
    /// Identifier and Team ID matched and a distribution (CMS) signature is present.
    case valid
    /// A *proven* mismatch — wrong identifier, wrong Team ID, unsigned, or
    /// ad-hoc re-signed. `reason` is a short, non-localized description.
    case tampered(reason: String)
    /// The binary couldn't be inspected conclusively (unreadable, truncated,
    /// unexpected layout). Deliberately *not* treated as tampering so a quirk
    /// on some device never bricks a legitimate build.
    case inconclusive(reason: String)
}

public extension MachOSignatureInspector {

    /// Checks the running app's main executable against your expected signing
    /// identity.
    ///
    /// - Parameters:
    ///   - expectedIdentifierPrefix: your app's bundle id (matched by prefix,
    ///     so app-extension identifiers like `com.example.app.share` also pass).
    ///   - expectedTeamID: your 10-character Apple Developer Team ID.
    ///
    /// Policy: fails **closed** (`.tampered`) only on a proven mismatch; any
    /// parse ambiguity yields `.inconclusive`. Gate enforcement to release
    /// builds on real devices so Simulator / debug builds are never affected.
    static func verifyMainExecutable(
        expectedIdentifierPrefix: String,
        expectedTeamID: String
    ) -> SignatureVerdict {
        do {
            let signature = try inspectMainExecutable()
            return evaluate(signature,
                            expectedIdentifierPrefix: expectedIdentifierPrefix,
                            expectedTeamID: expectedTeamID)
        } catch MachOSignatureError.noCodeSignature {
            return .tampered(reason: "binary is unsigned")
        } catch {
            return .inconclusive(reason: String(describing: error))
        }
    }

    /// Applies the policy to an already-inspected signature.
    static func evaluate(
        _ signature: MachOCodeSignature,
        expectedIdentifierPrefix: String,
        expectedTeamID: String
    ) -> SignatureVerdict {
        if let identifier = signature.identifier, !identifier.hasPrefix(expectedIdentifierPrefix) {
            return .tampered(reason: "identifier mismatch: \(identifier)")
        }
        if let teamID = signature.teamID, teamID != expectedTeamID {
            return .tampered(reason: "team id mismatch: \(teamID)")
        }
        guard signature.hasCMSSignature else {
            return .tampered(reason: "missing CMS signature (ad-hoc re-sign)")
        }
        return .valid
    }
}
