import BSVKeys
import BSVScript
import BSVWallet

/// Codec for the `LocalKVStore` token of `@bsv/sdk` 4.1.1.
///
/// The token is a lock-before PushDrop script with exactly two fields: the
/// value (plain or wallet ciphertext) and a DER signature over the value.
/// The locking key and the signing key are the owner's BRC-42 key for
/// protocol `[2, context]`, key ID `key`, counterparty self
/// (`kvstore/LocalKVStore.ts`: `pushdrop.lock([value], protocol, key, "self")`
/// to write, `decodeCanonicalPushDrop(..., { fieldCount: 2 })` and
/// `verifySignature(..., counterparty: "self")` to read).
public enum KVStoreTokenCodec {
    /// Encodes a token that already carries its signature.
    public static func lockingScript(
        for token: KVStoreToken,
        limits: KVStoreLimits = .standard
    ) throws -> Script {
        try validate(valueByteCount: token.value.count, limits: limits)
        do {
            return try PushDrop.lockingScript(
                fields: [token.value, token.signature.derBytes],
                publicKey: token.lockingPublicKey,
                lockPosition: .beforeCompatibility,
                limits: try makeEncodingPushDropLimits(limits)
            )
        } catch let error as PushDropError {
            throw KVStoreError.invalidLockingScript(error)
        }
    }

    /// Writes and signs a token with the owner's wallet, as TypeScript
    /// `LocalKVStore.set` does. The script is decoded and its signature
    /// verified before it is returned.
    public static func lockingScript(
        value: [UInt8],
        locator: KVStoreLocator,
        using wallet: any WalletPublicKeyProviding & WalletSignatureOperations,
        limits: KVStoreLimits = .standard
    ) async throws -> Script {
        guard !value.isEmpty else { throw KVStoreError.emptyValue }
        try validate(valueByteCount: value.count, limits: limits)
        let script: Script
        do {
            script = try await PushDrop.lockingScript(
                fields: [value],
                using: wallet,
                protocolID: try locator.walletProtocolID(),
                keyID: try locator.walletKeyID(),
                counterparty: .self,
                forSelf: false,
                includeSignature: true,
                lockPosition: .beforeCompatibility,
                limits: try makeEncodingPushDropLimits(limits)
            )
        } catch let error as PushDropError {
            throw KVStoreError.invalidLockingScript(error)
        }
        _ = try decode(script, limits: limits)
        return script
    }

    /// Decodes a two-field token and verifies its signature under the
    /// locking key. It does not check who owns the locking key; use
    /// `decode(_:locator:using:limits:)` for that.
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

        let decoded: PushDropDecoded
        do {
            decoded = try PushDrop.decode(
                lockingScript,
                lockPosition: .beforeCompatibility,
                limits: try makeDecodingPushDropLimits(limits)
            )
        } catch let error as PushDropError {
            throw normalizedDecodingError(error, limits: limits)
        }

        guard decoded.fields.count == 2 else {
            throw KVStoreError.invalidTokenFieldCount(actual: decoded.fields.count)
        }
        let signatureField = decoded.fields[1]
        guard signatureField.count <= KVStoreLimits.maximumSignatureByteCount,
            let signature = try? ECDSASignature(derBytes: signatureField),
            signature.derBytes == signatureField
        else {
            throw KVStoreError.invalidSignatureEncoding
        }
        return try KVStoreToken(
            value: decoded.fields[0],
            lockingPublicKey: decoded.publicKey,
            signature: signature,
            limits: limits
        )
    }

    /// Decodes a token and checks that its locking key is the wallet's key
    /// for `locator`, as TypeScript `LocalKVStore` does before it trusts an
    /// output.
    public static func decode(
        _ lockingScript: Script,
        locator: KVStoreLocator,
        using wallet: any WalletPublicKeyProviding,
        limits: KVStoreLimits = .standard
    ) async throws -> KVStoreToken {
        let token = try decode(lockingScript, limits: limits)
        let expected = try await wallet.getPublicKey(.init(
            selection: .derived(
                protocolID: try locator.walletProtocolID(),
                keyID: try locator.walletKeyID(),
                counterparty: .self,
                forSelf: false
            )
        )).publicKey
        guard expected == token.lockingPublicKey else {
            throw KVStoreError.lockingKeyMismatch
        }
        return token
    }

    private static func validate(valueByteCount: Int, limits: KVStoreLimits) throws {
        guard valueByteCount <= limits.maximumValueByteCount else {
            throw KVStoreError.valueByteCountExceedsLimit(
                actual: valueByteCount,
                maximum: limits.maximumValueByteCount
            )
        }
        let requiredScriptByteCount = try KVStoreLimits.maximumTokenScriptByteCount(
            forValueByteCount: valueByteCount
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
            maximumFieldCount: 2,
            maximumFieldByteCount: max(
                limits.maximumValueByteCount,
                KVStoreLimits.maximumSignatureByteCount
            ),
            maximumScriptByteCount: limits.maximumScriptByteCount
        )
    }

    private static func makeDecodingPushDropLimits(_ limits: KVStoreLimits) throws -> PushDropLimits {
        // Decode one extra field so the public error can distinguish a
        // well-formed three-field script from a malformed PushDrop script.
        // Field bytes remain bounded by the already checked script ceiling.
        try PushDropLimits(
            maximumFieldCount: 3,
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
