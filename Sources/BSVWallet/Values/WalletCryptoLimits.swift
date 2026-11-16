/// Bounds on what the wallet's own cryptography reads.
///
/// `maximumPayloadByteCount` bounds the data signed, verified, HMACed or encrypted. The default is
/// `defaultPayloadByteCount`, 16 MiB plus 512 KiB: the TypeScript `ProtoWallet` sets no bound of
/// its own, and BRC-103 signs each general message's whole payload, which over HTTP is a body of up
/// to 16 MiB plus the 512 KiB of framing the TypeScript `AuthFetch` allows for
/// (`clients/AuthFetch.ts:147`, `:571`). `AuthLimits.defaultPayloadBytes` in BSVAuth is this same
/// value, so a payload BSVAuth accepts by default can always be signed and verified. At 1 MiB, an
/// authenticated request or response over 1 MiB could not be signed or verified.
public struct WalletCryptoLimits: Hashable, Sendable {
    /// The default payload bound: 16 MiB plus 512 KiB.
    public static let defaultPayloadByteCount = (16 << 20) + (512 << 10)

    public static let standard = WalletCryptoLimits(
        validatedPayload: defaultPayloadByteCount,
        ciphertext: defaultPayloadByteCount + 48,
        json: 8_388_608
    )

    public let maximumPayloadByteCount: Int
    public let maximumCiphertextByteCount: Int
    public let maximumJSONByteCount: Int

    public init(
        maximumPayloadByteCount: Int = WalletCryptoLimits.defaultPayloadByteCount,
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
    case counterpartySelfLinkageForbidden
    case payloadTooLarge(actual: Int, maximum: Int)
    case ciphertextTooShort(actual: Int, minimum: Int)
    case ciphertextTooLarge(actual: Int, maximum: Int)
    case keyDerivationFailed
    case randomGenerationFailed
    case encryptionFailed
    case authenticationFailed
    case signingFailed
    case proofGenerationFailed
    case invalidJSON
    case jsonTooLarge(actual: Int, maximum: Int)
    case encodedJSONTooLarge(actual: Int, maximum: Int)
}
