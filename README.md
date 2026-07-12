# MachOSignature

Read the code-signing identity of a Mach-O binary — signing **identifier**,
**Team ID**, and whether it carries a real distribution (CMS) signature — in
pure Swift. No `codesign`, no shelling out, no external dependencies.

## Install

### Xcode

1. **File → Add Package Dependencies…**
2. Paste the repo URL:
   ```
   https://github.com/mrosama96/swift-macho-signature.git
   ```
3. Choose **Up to Next Major Version** starting from `1.0.0`, and add the
   **MachOSignature** library to your app target.

### Swift Package Manager

```swift
.package(url: "https://github.com/mrosama96/swift-macho-signature.git", from: "1.0.0")
```

Then `import MachOSignature`.

## How to use

### Read your app's signing identity

```swift
import MachOSignature

let sig = try MachOSignatureInspector.inspectMainExecutable()
print(sig.identifier)       // e.g. "com.example.app"
print(sig.teamID)           // e.g. "ABCDE12345" (nil for platform/ad-hoc binaries)
print(sig.hasCMSSignature)  // true for App Store / TestFlight / Developer ID builds
print(sig.isAdHocSigned)    // true when re-signed ad-hoc (a repackaging tell)
```

### Inspect any Mach-O, not just your own app

```swift
let ls = try MachOSignatureInspector.inspect(url: URL(fileURLWithPath: "/bin/ls"))
// ls.identifier == "com.apple.ls"
```

### Detect a repackaged app

A common iOS attack is to unzip an `.ipa`, patch it, re-sign it ad-hoc, and
repackage it. A re-signed build has a **different Team ID / identifier** and
**loses its CMS signature**. The built-in policy layer checks for exactly
that:

```swift
switch MachOSignatureInspector.verifyMainExecutable(
    expectedIdentifierPrefix: "com.example.app",
    expectedTeamID: "ABCDE12345"
) {
case .valid:
    break
case .tampered(let reason):
    // Wrong team, wrong id, unsigned, or ad-hoc re-signed.
    // Enforce however you like — but only in release, on a real device.
    #if !DEBUG && !targetEnvironment(simulator)
    abort()
    #endif
case .inconclusive(let reason):
    // Couldn't parse conclusively — do NOT treat as tampering.
    break
}
```

**Policy fails closed only on a *proven* mismatch.** Anything ambiguous
(unreadable, truncated, unexpected layout) returns `.inconclusive`, so a quirk
on some device can never brick a legitimate install. Gate enforcement to
release builds on physical devices — Simulator and debug builds are ad-hoc
signed and would otherwise trip the check.

> This is one layer, not a silver bullet. A determined attacker can patch out
> the check itself. Treat it as a deterrent, best combined with other runtime
> integrity signals — not as your only defense.

## How it works

Every iOS/macOS app ships its code-signing identity *inside* the binary, in
the Mach-O `LC_CODE_SIGNATURE` load command. Reading it normally means the
`codesign` command-line tool — which you can't run from inside a sandboxed
app on device. This package parses that structure directly:

```
FAT header ─▶ arch slice ─▶ Mach-O header ─▶ load commands
                                                  └─▶ LC_CODE_SIGNATURE
                                                        └─▶ SuperBlob
                                                              ├─▶ CodeDirectory  → identifier, Team ID
                                                              └─▶ CMS BlobWrapper → distribution signature?
```

Handles thin and FAT binaries, 32/64-bit, and both byte orders, with every
read bounds-checked (malformed input throws, it never crashes or reads out of
bounds).

## API

```swift
struct MachOCodeSignature {
    let identifier: String?      // signing identifier (usually the bundle id)
    let teamID: String?          // Apple Developer Team ID (CodeDirectory v2.2+)
    let hasCMSSignature: Bool    // has a non-empty CMS (distribution) blob
    var isAdHocSigned: Bool      // == !hasCMSSignature
}

enum MachOSignatureInspector {
    static func inspectMainExecutable() throws -> MachOCodeSignature
    static func inspect(url: URL) throws -> MachOCodeSignature
    static func inspect(data: Data) throws -> MachOCodeSignature

    // Policy layer
    static func verifyMainExecutable(expectedIdentifierPrefix: String,
                                     expectedTeamID: String) -> SignatureVerdict
    static func evaluate(_ signature: MachOCodeSignature,
                         expectedIdentifierPrefix: String,
                         expectedTeamID: String) -> SignatureVerdict
}
```

`inspect(...)` throws `MachOSignatureError` on structural problems
(`.unrecognizedFormat`, `.truncated`, `.noCodeSignature`, …). The policy
methods never throw — they fold errors into `.inconclusive`.

## Requirements

- Swift 5.9+
- iOS 13+ / macOS 11+ / tvOS 13+ / watchOS 6+

## License

MIT — see [LICENSE](LICENSE).

## LinkedIn

https://www.linkedin.com/in/osamamanasra
