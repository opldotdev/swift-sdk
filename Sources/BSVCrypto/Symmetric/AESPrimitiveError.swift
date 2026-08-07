/// Stable validation and authenticated-decryption failures for AES primitives.
public enum AESPrimitiveError: Error, Equatable, Sendable {
    case invalidKeyByteCount(Int)
    case invalidInitializationVectorByteCount(Int)
    case invalidNonceByteCount(minimum: Int, actual: Int)
    case invalidAuthenticationTagByteCount(Int)
    case invalidCiphertextByteCount(Int)
    case invalidPadding
    case authenticationFailed
    case encryptionFailed
}
