/// Stable errors produced while validating secp256k1 key encodings.
public enum Secp256k1KeyError: Error, Equatable, Sendable {
    case invalidPrivateKeyByteCount(Int)
    case invalidPrivateKey
    case invalidPublicKeyByteCount(Int)
    case invalidPublicKeyPrefix(UInt8)
    case invalidHybridParity
    case invalidPublicKey
}
