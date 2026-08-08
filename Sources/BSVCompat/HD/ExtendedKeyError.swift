import BSVKeys

/// The kind of key carried by a BIP-32 extended-key serialization.
public enum ExtendedKeyKind: Hashable, Sendable {
    case privateKey
    case publicKey
}

/// Stable failures produced by BIP-32 key, child-number, and path operations.
public enum ExtendedKeyError: Error, Equatable, Sendable {
    /// BIP-32 seeds are intentionally restricted to the standard's 128...512-bit range.
    case invalidSeedByteCount(Int)
    /// HMAC-SHA512 produced an invalid master scalar.
    case invalidMasterKey
    /// Bounded Base58Check decoding failed.
    case invalidEncoding(Base58CheckError)
    /// Extended-key text was not exactly 111 UTF-8 bytes.
    case invalidSerializedTextLength
    /// The decoded extended-key payload was not exactly 78 bytes.
    case invalidPayloadByteCount(Int)
    /// The four-byte extended-key version is not a standard xprv/xpub/tprv/tpub version.
    case unknownVersion(UInt32)
    /// The serialization contains a different key kind than the requested type.
    case unexpectedKeyKind(expected: ExtendedKeyKind, actual: ExtendedKeyKind)
    /// Extended private key data did not begin with the required zero marker.
    case invalidPrivateKeyMarker(UInt8)
    /// Extended private key data did not contain a valid secp256k1 scalar.
    case invalidPrivateKey
    /// Extended public key data did not contain a compressed secp256k1 point.
    case invalidPublicKey
    /// A depth-zero serialization had a nonzero parent fingerprint or child number.
    case inconsistentRootMetadata
    /// A semantic child index was outside `0...(2^31 - 1)`.
    case invalidChildIndex(UInt32)
    /// A child could not be produced at the exact requested serialized child number.
    case derivationFailed(childNumber: UInt32)
    /// A depth-255 extended key cannot have another serialized descendant.
    case depthExhausted
    /// Public child derivation is undefined for hardened child numbers.
    case hardenedPublicDerivation(childNumber: UInt32)
    /// A path was not a bounded canonical `m`/`M` path with decimal components.
    case invalidPath
    /// The path root does not match the receiver's private/public key kind.
    case pathRootMismatch(expected: ExtendedKeyKind, actual: ExtendedKeyKind)
    /// Absolute `m`/`M` path derivation requires a depth-zero receiver.
    case pathRequiresRootKey
}
