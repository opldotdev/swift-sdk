import BSVCore
import BSVCrypto
import BSVKeys
import Foundation

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
    /// Signs the unsigned binary using public/`anyone` BRC-100 semantics, as
    /// `Certificate.sign` does in `@bsv/sdk` 4.1.1: the fields are in
    /// JavaScript `localeCompare` order (`auth/certificates/Certificate.ts:290`
    /// and `:473`), so TypeScript verifies the result.
    ///
    /// Field names must use only printable ASCII and accented Latin letters,
    /// the characters whose `localeCompare` order this SDK reproduces exactly.
    /// Another name throws `CertificateFieldNameError.unsupportedCharacter`
    /// rather than sign an order TypeScript may not verify.
    public func signed(
        using wallet: any CertificateSignatureWallet,
        limits: CertificateLimits = .standard
    ) async throws -> Certificate {
        guard signature == nil else { throw CertificateError.alreadySigned }
        if let name = Self.fieldNameWithoutExactOrder(in: fields.keys) {
            WalletLog.error(
                "Certificate signing: a field name of \(name.utf8Bytes.count) bytes has a character "
                    + "whose localeCompare order is not reproduced; reported as "
                    + String(reflecting: CertificateFieldNameError.unsupportedCharacter))
            throw CertificateFieldNameError.unsupportedCharacter
        }
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
    ///
    /// The signature is checked over the fields in JavaScript `localeCompare`
    /// order, as `@bsv/sdk` 4.1.1 `Certificate.verify` checks it
    /// (`auth/certificates/Certificate.ts:437-458`), and, when that order
    /// differs, over raw UTF-8 byte order, which the Go SDK and earlier
    /// releases of this SDK sign.
    public func verifySignature(
        limits: CertificateLimits = .standard
    ) async throws -> Bool {
        guard signature != nil else { throw CertificateError.missingSignature }
        _ = try binary(includingSignature: true, limits: limits)
        let localeOrder = try binary(includingSignature: false, limits: limits)
        if try await verifySignature(over: localeOrder) { return true }
        let byteOrder = try binary(
            includingSignature: false, limits: limits, fieldOrder: .utf8Bytes)
        guard byteOrder != localeOrder else { return false }
        return try await verifySignature(over: byteOrder)
    }

    private func verifySignature(over preimage: [UInt8]) async throws -> Bool {
        guard let signature else { throw CertificateError.missingSignature }
        let verifier = try ProtoWallet.anyone()
        return try await verifier.verifySignature(.init(
            protocolID: try CertificateProtocols.signature,
            keyID: try WalletKeyID(signatureKeyID),
            counterparty: .publicKey(certifier),
            payload: .digest(BSVHashing.sha256(preimage)),
            signature: signature
        )).valid
    }

    /// The first name, if any, with a character whose `localeCompare` order
    /// this SDK does not reproduce exactly: anything but printable ASCII and
    /// the precomposed accented Latin letters `LocaleCompareOrder` covers.
    package static func fieldNameWithoutExactOrder(
        in names: some Sequence<CertificateFieldName>
    ) -> CertificateFieldName? {
        names.first { !LocaleCompareOrder.isExact($0.value) }
    }
}

/// A certificate field name this SDK will not sign.
///
/// `@bsv/sdk` orders signed field names with `localeCompare`, the ICU root
/// collation. `LocaleCompareOrder` reproduces it exactly for printable ASCII
/// and precomposed accented Latin letters such as `é` and `Å`, so
/// `Certificate.signed` and `CertificateEngine.issue` refuse other names,
/// including control characters, decomposed accents and other scripts, rather
/// than sign a certificate TypeScript may not verify. Certificates with such
/// names signed elsewhere are still verified (COMP-041).
public enum CertificateFieldNameError: Error, Equatable, Sendable, LocalizedError {
    case unsupportedCharacter

    public var errorDescription: String? {
        switch self {
        case .unsupportedCharacter:
            "Certificate field names must use only plain ASCII letters, digits, spaces and "
                + "symbols, and accented Latin letters."
        }
    }
}
