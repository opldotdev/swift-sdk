import BSVMessage
import Testing

@Suite("PortableMessage resource limits")
struct PortableMessageLimitsTests {
    @Test("standard and custom bounds are exact")
    func exactBounds() throws {
        #expect(PortableMessageLimits.standard.maximumMessageByteCount == 1_048_576)
        #expect(
            PortableMessageLimits.standard.maximumEncryptedPayloadByteCount
                == 1_048_624
        )
        #expect(PortableMessageLimits.standard.maximumEnvelopeByteCount == 1_048_726)

        let empty = try PortableMessageLimits(maximumMessageByteCount: 0)
        #expect(empty.maximumMessageByteCount == 0)
        #expect(empty.maximumEncryptedPayloadByteCount == 48)
        #expect(empty.maximumEnvelopeByteCount == 174)

        let beyondSignedEnvelope = try PortableMessageLimits(
            maximumMessageByteCount: 25
        )
        #expect(beyondSignedEnvelope.maximumEncryptedPayloadByteCount == 73)
        #expect(beyondSignedEnvelope.maximumEnvelopeByteCount == 175)
    }

    @Test("negative and overflowing limits are rejected exactly")
    func invalidConstruction() {
        #expect(
            throws: PortableMessageError.invalidLimit(
                name: "maximumMessageByteCount",
                value: -1
            )
        ) {
            try PortableMessageLimits(maximumMessageByteCount: -1)
        }

        let overflowing = Int.max - 149
        #expect(
            throws: PortableMessageError.invalidLimit(
                name: "maximumMessageByteCount",
                value: overflowing
            )
        ) {
            try PortableMessageLimits(maximumMessageByteCount: overflowing)
        }
    }
}
