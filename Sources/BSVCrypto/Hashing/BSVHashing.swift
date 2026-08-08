import BSVCore
import Crypto

/// Bitcoin-oriented one-shot hashes, HMACs, and authentication-code validation.
public enum BSVHashing {
    /// Computes SHA-256 and preserves its raw digest byte order.
    public static func sha256(_ bytes: [UInt8]) -> Hash256 {
        Hash256(exactDigestBytesGuaranteed: Array(SHA256.hash(data: bytes)))
    }

    /// Computes SHA-256 twice and preserves the second digest's raw byte order.
    public static func sha256d(_ bytes: [UInt8]) -> Hash256 {
        sha256(sha256(bytes).bytes)
    }

    /// Computes SHA-512 and preserves its raw digest byte order.
    public static func sha512(_ bytes: [UInt8]) -> Hash512 {
        Hash512(exactDigestBytesGuaranteed: Array(SHA512.hash(data: bytes)))
    }

    /// Computes legacy SHA-1 for Bitcoin Script's `OP_SHA1`.
    ///
    /// SHA-1 is exposed only for protocol compatibility and must not be used
    /// as a new signature or authentication construction.
    public static func sha1(_ bytes: [UInt8]) -> Hash160 {
        Hash160(exactDigestBytesGuaranteed: Array(Insecure.SHA1.hash(data: bytes)))
    }

    /// Computes RIPEMD-160 and preserves its raw digest byte order.
    public static func ripemd160(_ bytes: [UInt8]) -> Hash160 {
        Hash160(exactDigestBytesGuaranteed: RIPEMD160.digest(bytes))
    }

    /// Computes RIPEMD-160 over SHA-256 and preserves the raw digest byte order.
    public static func hash160(_ bytes: [UInt8]) -> Hash160 {
        ripemd160(sha256(bytes).bytes)
    }

    /// Computes HMAC-SHA256 for a message and key.
    public static func hmacSHA256(_ message: [UInt8], key: [UInt8]) -> Hash256 {
        let code = HMAC<SHA256>.authenticationCode(
            for: message,
            using: Crypto.SymmetricKey(data: key)
        )
        return Hash256(exactDigestBytesGuaranteed: Array(code))
    }

    /// Computes HMAC-SHA512 for a message and key.
    public static func hmacSHA512(_ message: [UInt8], key: [UInt8]) -> Hash512 {
        let code = HMAC<SHA512>.authenticationCode(
            for: message,
            using: Crypto.SymmetricKey(data: key)
        )
        return Hash512(exactDigestBytesGuaranteed: Array(code))
    }

    /// Validates an exact HMAC-SHA256 code using Swift Crypto's authentication check.
    public static func isValidHMACSHA256(
        _ authenticationCode: [UInt8],
        authenticating message: [UInt8],
        key: [UInt8]
    ) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(
            authenticationCode,
            authenticating: message,
            using: Crypto.SymmetricKey(data: key)
        )
    }

    /// Validates an exact HMAC-SHA512 code using Swift Crypto's authentication check.
    public static func isValidHMACSHA512(
        _ authenticationCode: [UInt8],
        authenticating message: [UInt8],
        key: [UInt8]
    ) -> Bool {
        HMAC<SHA512>.isValidAuthenticationCode(
            authenticationCode,
            authenticating: message,
            using: Crypto.SymmetricKey(data: key)
        )
    }
}
