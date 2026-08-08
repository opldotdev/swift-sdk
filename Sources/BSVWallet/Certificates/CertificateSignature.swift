import BSVCrypto
import BSVKeys

public enum CertificateProtocols {
    public static var signature: WalletProtocolID {
        get throws {
            try WalletProtocolID(
                securityLevel: .everyAppAndCounterparty,
                name: "certificate signature"
            )
        }
    }
    public static var fieldEncryption: WalletProtocolID {
        get throws {
            try WalletProtocolID(
                securityLevel: .everyAppAndCounterparty,
                name: "certificate field encryption"
            )
        }
    }

    public static func masterFieldKeyID(_ field: CertificateFieldName) throws -> WalletKeyID {
        try WalletKeyID(field.value)
    }

    public static func verifierFieldKeyID(
        serialNumber: CertificateSerialNumber,
        field: CertificateFieldName
    ) throws -> WalletKeyID {
        try WalletKeyID(serialNumber.base64 + " " + field.value)
    }
}

extension Certificate {
    /// Signs the canonical unsigned binary using public/`anyone` BRC-100 semantics.
    public func signed(
        using wallet: any CertificateSignatureWallet,
        limits: CertificateLimits = .standard
    ) async throws -> Certificate {
        guard signature == nil else { throw CertificateError.alreadySigned }
        let preimage = try binary(includingSignature: false, limits: limits)
        let identity = try await wallet.getPublicKey(.init(selection: .identity)).publicKey
        guard identity == certifier else { throw CertificateError.walletIdentityMismatch }
        let result = try await wallet.createSignature(.init(
            protocolID: try CertificateProtocols.signature,
            keyID: try WalletKeyID(signatureKeyID),
            counterparty: .anyone,
            payload: .digest(BSVHashing.sha256(preimage))
        ))
        let signed = try replacingSignature(result.signature, limits: limits)
        _ = try signed.binary(includingSignature: true, limits: limits)
        return signed
    }

    /// Cryptographically verifies with an `anyone` ProtoWallet and the certifier
    /// as counterparty. This does not establish trust or check revocation status;
    /// chain-aware callers must perform those policy checks separately. High-S
    /// signatures return `false` under Swift's strict non-malleability policy.
    public func verifySignature(
        limits: CertificateLimits = .standard
    ) async throws -> Bool {
        guard let signature else { throw CertificateError.missingSignature }
        _ = try binary(includingSignature: true, limits: limits)
        let preimage = try binary(includingSignature: false, limits: limits)
        let verifier = try ProtoWallet.anyone()
        return try await verifier.verifySignature(.init(
            protocolID: try CertificateProtocols.signature,
            keyID: try WalletKeyID(signatureKeyID),
            counterparty: .publicKey(certifier),
            payload: .digest(BSVHashing.sha256(preimage)),
            signature: signature
        )).valid
    }
}
