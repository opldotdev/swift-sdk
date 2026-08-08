/// Stable failures produced by BRC-77 signed messages and BRC-78 encrypted messages.
public enum PortableMessageError: Error, Equatable, Sendable {
    /// A resource limit is negative or cannot represent its derived bounds.
    case invalidLimit(name: String, value: Int)

    /// An external message exceeds the configured hashing or encryption bound.
    case messageByteCountLimitExceeded(actual: Int, maximum: Int)

    /// A wire envelope exceeds the configured parsing bound.
    case envelopeByteCountLimitExceeded(actual: Int, maximum: Int)

    /// An encrypted payload exceeds the configured authenticated-opening bound.
    case encryptedPayloadByteCountLimitExceeded(actual: Int, maximum: Int)

    /// The packet is too short to contain every required field.
    case invalidEnvelopeByteCount(Int)

    /// The packet does not contain the protocol's exact four-byte version marker.
    case invalidVersion

    /// The embedded sender key is not one canonical compressed SEC1 public key.
    case invalidSenderPublicKey

    /// The embedded recipient key is not one canonical compressed SEC1 public key.
    case invalidRecipientPublicKey

    /// The signed-message suffix is not one complete canonical DER signature.
    case invalidSignature

    /// Recipient-specific verification requires the corresponding private key.
    case recipientPrivateKeyRequired

    /// The supplied private key does not match the packet's recipient public key.
    case recipientPublicKeyMismatch

    /// A random source failed or returned a byte count other than the requested count.
    case randomGenerationFailed

    /// BRC-42 child-key derivation failed.
    case keyDerivationFailed

    /// ECDH shared-point derivation failed.
    case keyAgreementFailed

    /// ECDSA signing failed.
    case signingFailed

    /// AES-GCM encryption failed after randomness was obtained.
    case encryptionFailed

    /// AES-GCM authentication failed while opening an encrypted message.
    case authenticationFailed
}
