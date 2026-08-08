import BSVKeys
import BSVScript

/// Strict codec for the one-field PushDrop token used by the pinned Go
/// `kvstore` package.
public enum KVStoreTokenCodec {
    /// Encodes a token with the pinned Go SDK's explicit lock-before layout.
    public static func lockingScript(
        for token: KVStoreToken,
        limits: KVStoreLimits = .standard
    ) throws -> Script {
        try validate(token: token, limits: limits)
        let pushDropLimits = try makeEncodingPushDropLimits(limits)
        do {
            return try PushDrop.lockingScript(
                fields: [token.value],
                publicKey: token.lockingPublicKey,
                lockPosition: .beforeCompatibility,
                limits: pushDropLimits
            )
        } catch let error as PushDropError {
            throw KVStoreError.invalidLockingScript(error)
        }
    }

    /// Decodes exactly one field from a pinned Go-compatible lock-before
    /// PushDrop script.
    public static func decode(
        _ lockingScript: Script,
        limits: KVStoreLimits = .standard
    ) throws -> KVStoreToken {
        guard lockingScript.bytes.count <= limits.maximumScriptByteCount else {
            throw KVStoreError.invalidLockingScript(
                .scriptByteCountExceedsLimit(
                    actual: lockingScript.bytes.count,
                    maximum: limits.maximumScriptByteCount
                )
            )
        }

        // Decode one extra field so the public error can distinguish a
        // well-formed multi-field script from a malformed PushDrop script.
        // Field bytes remain bounded by the already checked script ceiling.
        let pushDropLimits = try makeDecodingPushDropLimits(limits)
        let decoded: PushDropDecoded
        do {
            decoded = try PushDrop.decode(
                lockingScript,
                lockPosition: .beforeCompatibility,
                limits: pushDropLimits
            )
        } catch let error as PushDropError {
            throw normalizedDecodingError(error, limits: limits)
        }

        guard decoded.fields.count == 1 else {
            throw KVStoreError.invalidTokenFieldCount(actual: decoded.fields.count)
        }
        return try KVStoreToken(
            value: decoded.fields[0],
            lockingPublicKey: decoded.publicKey,
            limits: limits
        )
    }

    private static func validate(token: KVStoreToken, limits: KVStoreLimits) throws {
        guard token.value.count <= limits.maximumValueByteCount else {
            throw KVStoreError.valueByteCountExceedsLimit(
                actual: token.value.count,
                maximum: limits.maximumValueByteCount
            )
        }
        let requiredScriptByteCount = try KVStoreLimits.maximumTokenScriptByteCount(
            forValueByteCount: token.value.count
        )
        guard requiredScriptByteCount <= limits.maximumScriptByteCount else {
            throw KVStoreError.invalidLockingScript(
                .scriptByteCountExceedsLimit(
                    actual: requiredScriptByteCount,
                    maximum: limits.maximumScriptByteCount
                )
            )
        }
    }

    private static func makeEncodingPushDropLimits(_ limits: KVStoreLimits) throws -> PushDropLimits {
        try PushDropLimits(
            maximumFieldCount: 1,
            maximumFieldByteCount: limits.maximumValueByteCount,
            maximumScriptByteCount: limits.maximumScriptByteCount
        )
    }

    private static func makeDecodingPushDropLimits(_ limits: KVStoreLimits) throws -> PushDropLimits {
        try PushDropLimits(
            maximumFieldCount: 2,
            maximumFieldByteCount: limits.maximumScriptByteCount,
            maximumScriptByteCount: limits.maximumScriptByteCount
        )
    }

    private static func normalizedDecodingError(
        _ error: PushDropError,
        limits: KVStoreLimits
    ) -> KVStoreError {
        switch error {
        case .fieldCountExceedsLimit(let actual, _):
            .invalidTokenFieldCount(actual: actual)
        case .fieldByteCountExceedsLimit(let index, let actual, _)
            where index == 0 && actual > limits.maximumValueByteCount:
            .valueByteCountExceedsLimit(
                actual: actual,
                maximum: limits.maximumValueByteCount
            )
        default:
            .invalidLockingScript(error)
        }
    }
}
