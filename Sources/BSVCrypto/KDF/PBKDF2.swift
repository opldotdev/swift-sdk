import Crypto
import CryptoExtras

/// The fixed PBKDF2 profile required by BIP-39.
///
/// This deliberately does not expose configurable rounds, digest selection, or
/// output length. BIP-39 mandates parameters that are below contemporary
/// password-storage guidance, so callers outside the package must not be able
/// to repurpose this compatibility path as a general password KDF.
package enum BIP39PBKDF2 {
    package static func deriveSeed(
        mnemonicUTF8: [UInt8],
        saltUTF8: [UInt8]
    ) throws -> [UInt8] {
        let key = try KDF.Insecure.PBKDF2.deriveKey(
            from: mnemonicUTF8,
            salt: saltUTF8,
            using: .sha512,
            outputByteCount: 64,
            unsafeUncheckedRounds: 2_048
        )
        return key.withUnsafeBytes { Array($0) }
    }
}
