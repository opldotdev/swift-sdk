import BSVCore
import BSVCrypto
import BSVKeys
import Foundation

/// A policy-free, offline BRC-100 cryptographic kernel. It stores immutable
/// values only. Swift cannot guarantee zeroization of copied key material.
public struct ProtoWallet:
    WalletKeyOperations,
    WalletLinkageOperations,
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

    public func revealCounterpartyKeyLinkage(
        _ request: WalletRevealCounterpartyKeyLinkageRequest
    ) async throws -> WalletRevealCounterpartyKeyLinkageResult {
        try await revealCounterpartyKeyLinkage(
            request,
            revelationTime: walletCurrentISO8601Timestamp(),
            proofNonce: nil
        )
    }

    package func revealCounterpartyKeyLinkage(
        _ request: WalletRevealCounterpartyKeyLinkageRequest,
        revelationTime: String,
        proofNonce: PrivateKey?
    ) async throws -> WalletRevealCounterpartyKeyLinkageResult {
        try requireStandardPrivilege(request.privilege)
        let linkage = try keyDeriver.revealCounterpartySecret(request.counterparty)
        let proof = try keyDeriver.counterpartySecretProof(
            for: request.counterparty,
            nonce: proofNonce
        )
        // R(33) || S'(33) || z(32): TypeScript 4.x (`ProtoWallet.ts`
        // `z.toArray('be', 32)`) and Go both pad z to 32 bytes, so the proof
        // is always 98 bytes and verifiers may slice fixed offsets.
        let proofBytes = proof.noncePublicKey.compressedBytes
            + proof.nonceSharedSecret.compressedBytes
            + proof.response
        let protocolID = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: "counterparty linkage revelation"
        )
        let keyID = try WalletKeyID(revelationTime)
        let encryptedLinkage = try await encrypt(WalletEncryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(request.verifier),
            plaintext: linkage.compressedBytes
        ))
        let encryptedProof = try await encrypt(WalletEncryptRequest(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(request.verifier),
            plaintext: proofBytes
        ))
        return try WalletRevealCounterpartyKeyLinkageResult(
            prover: keyDeriver.identityKey,
            counterparty: request.counterparty,
            verifier: request.verifier,
            revelationTime: revelationTime,
            encryptedLinkage: WalletLinkageCiphertext(encryptedLinkage.ciphertext),
            encryptedLinkageProof: WalletLinkageCiphertext(encryptedProof.ciphertext)
        )
    }

    public func revealSpecificKeyLinkage(
        _ request: WalletRevealSpecificKeyLinkageRequest
    ) async throws -> WalletRevealSpecificKeyLinkageResult {
        try requireStandardPrivilege(request.privilege)
        // TypeScript 4.x resolves `self` to the identity key and `anyone` to the
        // public key of private key 1, and its clients reject any other answer.
        let counterparty = try keyDeriver.resolvedCounterparty(request.counterparty)
        let linkage = try keyDeriver.revealSpecificSecret(
            counterparty: request.counterparty,
            protocolID: request.protocolID,
            keyID: request.keyID
        )
        let revelationProtocol = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: "specific linkage revelation "
                + "\(request.protocolID.securityLevel.rawValue) \(request.protocolID.name)"
        )
        let encryptedLinkage = try await encrypt(WalletEncryptRequest(
            protocolID: revelationProtocol,
            keyID: request.keyID,
            counterparty: .publicKey(request.verifier),
            plaintext: linkage
        ))
        let proofType: UInt8 = 0
        let encryptedProof = try await encrypt(WalletEncryptRequest(
            protocolID: revelationProtocol,
            keyID: request.keyID,
            counterparty: .publicKey(request.verifier),
            plaintext: [proofType]
        ))
        return try WalletRevealSpecificKeyLinkageResult(
            encryptedLinkage: WalletLinkageCiphertext(encryptedLinkage.ciphertext),
            encryptedLinkageProof: WalletLinkageCiphertext(encryptedProof.ciphertext),
            prover: keyDeriver.identityKey,
            verifier: request.verifier,
            counterparty: counterparty,
            protocolID: request.protocolID,
            keyID: request.keyID,
            proofType: proofType
        )
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
        let code = BSVHashing.hmacSHA256(request.data, key: walletHMACKey(key.bytes))
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
        // Tags from TypeScript wallets and from current Swift use the minimal
        // key; tags Swift created before the switch used the padded 32-byte
        // key. Both stay valid. The two keys differ only when the shared X
        // coordinate has a leading zero byte.
        let minimalKey = walletHMACKey(key.bytes)
        let valid = BSVHashing.isValidHMACSHA256(
            request.hmac.bytes,
            authenticating: request.data,
            key: minimalKey
        ) || (minimalKey.count != key.bytes.count && BSVHashing.isValidHMACSHA256(
            request.hmac.bytes,
            authenticating: request.data,
            key: key.bytes
        ))
        return WalletVerifyHMACResult(valid: valid)
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
        guard access.privileged != true, access.privilegedReason == nil else {
            throw WalletCryptoError.permissionPolicyUnavailable
        }
    }

    private func requireStandardPrivilege(_ privilege: WalletPrivilege) throws {
        guard privilege.privileged != true, privilege.privilegedReason == nil else {
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

/// The BRC-56 HMAC key: the shared X coordinate as its minimal big-endian
/// integer (leading zero bytes removed; zero is one `00` byte). This matches
/// TypeScript `@bsv/sdk` 4.1.1 `ProtoWallet.createHmac`, which keys HMAC-SHA256
/// with `SymmetricKey.toArray()`. BRC-2 encryption keeps the 32-byte key.
func walletHMACKey(_ paddedKey: [UInt8]) -> [UInt8] {
    let minimal = Array(paddedKey.drop(while: { $0 == 0 }))
    return minimal.isEmpty ? [0] : minimal
}

private func walletCurrentISO8601Timestamp() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
}
