public struct WalletCryptoLimits: Hashable, Sendable {
    public static let standard = WalletCryptoLimits(
        validatedPayload: 1_048_576,
        ciphertext: 1_048_624,
        json: 8_388_608
    )

    public let maximumPayloadByteCount: Int
    public let maximumCiphertextByteCount: Int
    public let maximumJSONByteCount: Int

    public init(
        maximumPayloadByteCount: Int = 1_048_576,
        maximumJSONByteCount: Int = 8_388_608
    ) throws {
        guard maximumPayloadByteCount >= 0 else {
            throw WalletValidationError.invalidLimit(
                name: "maximumPayloadByteCount",
                value: maximumPayloadByteCount
            )
        }
        guard maximumJSONByteCount >= 0 else {
            throw WalletValidationError.invalidLimit(
                name: "maximumJSONByteCount",
                value: maximumJSONByteCount
            )
        }
        let (ciphertextCount, overflow) = maximumPayloadByteCount.addingReportingOverflow(48)
        guard !overflow else {
            throw WalletValidationError.invalidLimit(
                name: "maximumPayloadByteCount",
                value: maximumPayloadByteCount
            )
        }
        self.init(
            validatedPayload: maximumPayloadByteCount,
            ciphertext: ciphertextCount,
            json: maximumJSONByteCount
        )
    }

    private init(validatedPayload: Int, ciphertext: Int, json: Int) {
        self.maximumPayloadByteCount = validatedPayload
        self.maximumCiphertextByteCount = ciphertext
        self.maximumJSONByteCount = json
    }
}

public enum WalletCryptoError: Error, Equatable, Sendable {
    case permissionPolicyUnavailable
    case payloadTooLarge(actual: Int, maximum: Int)
    case ciphertextTooShort(actual: Int, minimum: Int)
    case ciphertextTooLarge(actual: Int, maximum: Int)
    case keyDerivationFailed
    case randomGenerationFailed
    case encryptionFailed
    case authenticationFailed
    case signingFailed
    case invalidJSON
    case jsonTooLarge(actual: Int, maximum: Int)
    case encodedJSONTooLarge(actual: Int, maximum: Int)
}
