import BSVCore
import BSVCrypto
import BSVKeys

/// A policy-free, offline BRC-100 cryptographic kernel. It stores immutable
/// values only. Swift cannot guarantee zeroization of copied key material.
public struct ProtoWallet:
    WalletKeyOperations,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    private let keyDeriver: WalletKeyDeriver
    private let limits: WalletCryptoLimits
    private let randomSource: any SecureRandomSource

    public init(rootKey: PrivateKey, limits: WalletCryptoLimits = .standard) {
        self.init(
            keyDeriver: WalletKeyDeriver(rootKey: rootKey),
            limits: limits,
            randomSource: SystemSecureRandomSource()
        )
    }

    public init(keyDeriver: WalletKeyDeriver, limits: WalletCryptoLimits = .standard) {
        self.init(
            keyDeriver: keyDeriver,
            limits: limits,
            randomSource: SystemSecureRandomSource()
        )
    }

    package init(
        rootKey: PrivateKey,
        limits: WalletCryptoLimits = .standard,
        randomSource: any SecureRandomSource & Sendable
    ) {
        self.init(
            keyDeriver: WalletKeyDeriver(rootKey: rootKey),
            limits: limits,
            randomSource: randomSource
        )
    }

    package init(
        keyDeriver: WalletKeyDeriver,
        limits: WalletCryptoLimits = .standard,
        randomSource: any SecureRandomSource & Sendable
    ) {
        self.keyDeriver = keyDeriver
        self.limits = limits
        self.randomSource = randomSource
    }

    public static func anyone(limits: WalletCryptoLimits = .standard) throws -> ProtoWallet {
        ProtoWallet(keyDeriver: try .anyone(), limits: limits)
    }

    public func getPublicKey(
        _ request: WalletGetPublicKeyRequest
    ) async throws -> WalletGetPublicKeyResult {
        try requireStandardAccess(request.access)
        switch request.selection {
        case .identity:
            return WalletGetPublicKeyResult(publicKey: keyDeriver.identityKey)
        case .derived(let protocolID, let keyID, let counterparty, let forSelf):
            let key = try keyDeriver.derivePublicKey(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: counterparty,
                forSelf: forSelf
            )
            return WalletGetPublicKeyResult(publicKey: key)
        }
    }

    public func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult {
        try requireStandardAccess(request.access)
        try walletRequirePayloadLimit(request.plaintext.count, limits: limits)
        let key = try keyDeriver.deriveSymmetricKey(
            protocolID: request.protocolID,
            keyID: request.keyID,
            counterparty: request.counterparty
        )
        do {
            return WalletEncryptResult(
                ciphertext: try key.seal(request.plaintext, using: randomSource)
            )
        } catch SymmetricKeyError.randomGenerationFailed {
            throw WalletCryptoError.randomGenerationFailed
        } catch {
            throw WalletCryptoError.encryptionFailed
        }
    }

    public func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult {
        try requireStandardAccess(request.access)
        try walletRequireCiphertextLimit(request.ciphertext.count, limits: limits)
        let key = try keyDeriver.deriveSymmetricKey(
            protocolID: request.protocolID,
            keyID: request.keyID,
            counterparty: request.counterparty
        )
        do {
            let plaintext = try key.open(request.ciphertext)
            try walletRequirePayloadLimit(plaintext.count, limits: limits)
            return WalletDecryptResult(plaintext: plaintext)
        } catch let error as WalletCryptoError {
            throw error
        } catch {
            throw WalletCryptoError.authenticationFailed
        }
    }

    public func createHMAC(_ request: WalletCreateHMACRequest) async throws -> WalletCreateHMACResult {
        try requireStandardAccess(request.access)
        try walletRequirePayloadLimit(request.data.count, limits: limits)
        let key = try keyDeriver.deriveSymmetricKey(
            protocolID: request.protocolID,
            keyID: request.keyID,
            counterparty: request.counterparty
        )
        let code = BSVHashing.hmacSHA256(request.data, key: key.bytes)
        do {
            return WalletCreateHMACResult(hmac: try WalletHMAC(bytes: code.bytes))
        } catch {
            throw WalletCryptoError.keyDerivationFailed
        }
    }

    public func verifyHMAC(_ request: WalletVerifyHMACRequest) async throws -> WalletVerifyHMACResult {
        try requireStandardAccess(request.access)
        try walletRequirePayloadLimit(request.data.count, limits: limits)
        let key = try keyDeriver.deriveSymmetricKey(
            protocolID: request.protocolID,
            keyID: request.keyID,
            counterparty: request.counterparty
        )
        return WalletVerifyHMACResult(valid: BSVHashing.isValidHMACSHA256(
            request.hmac.bytes,
            authenticating: request.data,
            key: key.bytes
        ))
    }

    public func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        try requireStandardAccess(request.access)
        let digest = try signatureDigest(request.payload)
        let key = try keyDeriver.derivePrivateKey(
            protocolID: request.protocolID,
            keyID: request.keyID,
            counterparty: request.counterparty
        )
        do {
            return WalletCreateSignatureResult(signature: try key.sign(digest: digest))
        } catch {
            throw WalletCryptoError.signingFailed
        }
    }

    public func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        try requireStandardAccess(request.access)
        let digest = try signatureDigest(request.payload)
        let key = try keyDeriver.derivePublicKey(
            protocolID: request.protocolID,
            keyID: request.keyID,
            counterparty: request.counterparty,
            forSelf: request.forSelf
        )
        return WalletVerifySignatureResult(valid: key.verify(request.signature, digest: digest))
    }

    private func requireStandardAccess(_ access: WalletKeyAccess) throws {
        guard access == .standard else {
            throw WalletCryptoError.permissionPolicyUnavailable
        }
    }

    private func signatureDigest(_ payload: WalletSignaturePayload) throws -> Hash256 {
        switch payload {
        case .data(let data):
            try walletRequirePayloadLimit(data.count, limits: limits)
            return BSVHashing.sha256(data)
        case .digest(let digest):
            return digest
        }
    }

    public var description: String { "<redacted proto wallet>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}
