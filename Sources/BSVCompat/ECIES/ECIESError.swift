import BSVKeys

/// Stable failures produced by the Electrum and Bitcore ECIES codecs.
public enum ECIESError: Error, Equatable, Sendable {
    /// The complete packet cannot contain the required framing fields.
    case invalidEnvelopeByteCount(Int)

    /// An Electrum packet did not begin with the ASCII marker `BIE1`.
    case invalidMagic

    /// A packet's compressed sender key was not valid SEC1 data.
    case invalidSenderPublicKey

    /// The embedded Electrum sender key differed from the expected sender.
    case senderPublicKeyMismatch

    /// A deterministic Bitcore encryption call did not receive exactly 16 IV bytes.
    case invalidInitializationVectorByteCount(Int)

    /// The encrypted portion was empty or was not AES block aligned.
    case invalidCiphertextByteCount(Int)

    /// Packet authentication failed. No CBC decryption was attempted.
    case authenticationFailed

    /// Authentication succeeded, but the PKCS#7 padding was invalid.
    case invalidPadding

    /// ECDH could not derive the shared curve point.
    case keyAgreementFailed

    /// AES-CBC encryption failed.
    case encryptionFailed

    /// A random source failed, returned the wrong byte count, or exhausted scalar retries.
    case randomGenerationFailed

    /// The supplied text was not canonical RFC 4648 Base64.
    case invalidBase64
}
