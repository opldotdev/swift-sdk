/// Resource bounds applied at every public BRC-77 and BRC-78 boundary.
public struct PortableMessageLimits: Hashable, Sendable {
    private static let encryptedPayloadOverheadByteCount = 48
    private static let encryptedEnvelopeOverheadByteCount = 150
    private static let maximumSignedEnvelopeByteCount = 174

    /// A bounded one-mebibyte message profile for general-purpose use.
    public static let standard = PortableMessageLimits(
        validatedMessage: 1_048_576,
        encryptedPayload: 1_048_624,
        envelope: 1_048_726
    )

    /// The largest message that may be hashed, signed, verified, or encrypted.
    public let maximumMessageByteCount: Int

    /// The largest `nonce || ciphertext || tag` payload that may be opened.
    public let maximumEncryptedPayloadByteCount: Int

    /// The largest complete BRC-77 or BRC-78 wire envelope that may be parsed.
    public let maximumEnvelopeByteCount: Int

    /// Creates exact message and derived wire-format resource bounds.
    ///
    /// The encrypted-payload maximum includes the 32-byte nonce and 16-byte
    /// authentication tag. The envelope maximum additionally includes the
    /// 102-byte BRC-78 header and is never smaller than the 174-byte maximum
    /// canonical BRC-77 envelope.
    public init(maximumMessageByteCount: Int = 1_048_576) throws {
        guard maximumMessageByteCount >= 0 else {
            throw PortableMessageError.invalidLimit(
                name: "maximumMessageByteCount",
                value: maximumMessageByteCount
            )
        }

        let (encryptedPayload, payloadOverflow) = maximumMessageByteCount
            .addingReportingOverflow(Self.encryptedPayloadOverheadByteCount)
        let (encryptedEnvelope, envelopeOverflow) = maximumMessageByteCount
            .addingReportingOverflow(Self.encryptedEnvelopeOverheadByteCount)
        guard !payloadOverflow, !envelopeOverflow else {
            throw PortableMessageError.invalidLimit(
                name: "maximumMessageByteCount",
                value: maximumMessageByteCount
            )
        }

        self.init(
            validatedMessage: maximumMessageByteCount,
            encryptedPayload: encryptedPayload,
            envelope: max(Self.maximumSignedEnvelopeByteCount, encryptedEnvelope)
        )
    }

    private init(validatedMessage: Int, encryptedPayload: Int, envelope: Int) {
        self.maximumMessageByteCount = validatedMessage
        self.maximumEncryptedPayloadByteCount = encryptedPayload
        self.maximumEnvelopeByteCount = envelope
    }

    func validateMessageByteCount(_ actual: Int) throws {
        guard actual <= maximumMessageByteCount else {
            throw PortableMessageError.messageByteCountLimitExceeded(
                actual: actual,
                maximum: maximumMessageByteCount
            )
        }
    }

    func validateEnvelopeByteCount(_ actual: Int) throws {
        guard actual <= maximumEnvelopeByteCount else {
            throw PortableMessageError.envelopeByteCountLimitExceeded(
                actual: actual,
                maximum: maximumEnvelopeByteCount
            )
        }
    }

    func validateEncryptedPayloadByteCount(_ actual: Int) throws {
        guard actual <= maximumEncryptedPayloadByteCount else {
            throw PortableMessageError.encryptedPayloadByteCountLimitExceeded(
                actual: actual,
                maximum: maximumEncryptedPayloadByteCount
            )
        }
    }
}
