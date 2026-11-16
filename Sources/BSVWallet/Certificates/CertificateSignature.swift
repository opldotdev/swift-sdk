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
    /// `localeCompare` takes its order from the TypeScript host's default
    /// locale, which Bun always resolves to `en-US` and Node takes from
    /// `LC_ALL` or `LANG`. This SDK signs the `en-US` order, the untailored ICU
    /// root collation. A TypeScript verifier on a host with a tailored
    /// collation, such as Danish, where `aa` sorts after `z` and capitals come
    /// first, or Czech, where `ch` sorts after `h`, reorders some names and
    /// does not verify the certificate; neither does it verify one signed by
    /// TypeScript on an `en-US` host (COMP-041).
    ///
    /// When there are two fields or more, their names must use only printable
    /// ASCII and accented Latin letters, the characters whose `localeCompare`
    /// order this SDK reproduces exactly. Another name throws
    /// `CertificateFieldNameError.unsupportedCharacter` rather than sign an
    /// order TypeScript may not verify. A certificate with no field or one has
    /// only one order, so any name is signed.
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
    /// The signature is checked over the fields in each order a signer may have
    /// used, as long as the orders differ:
    ///
    /// 1. JavaScript `localeCompare` order on an `en-US` host, as `@bsv/sdk`
    ///    4.1.1 `Certificate.verify` checks it
    ///    (`auth/certificates/Certificate.ts:437-458`);
    /// 2. raw UTF-8 byte order, which the Go SDK and earlier releases of this
    ///    SDK sign;
    /// 3. for a certificate read with `init(binary:)`, the order its fields
    ///    arrived in, which is the order its signer wrote and signed.
    ///
    /// The preimage is length-prefixed, so each order commits to the same
    /// field names and values; only their order differs. The third covers
    /// names this SDK cannot order as `localeCompare` does, such as `ß`,
    /// Cyrillic or CJK, and TypeScript hosts with a tailored collation such as
    /// Danish. A certificate with such names read from JSON has no received
    /// order, so it verifies only when one of the first two orders matches.
    ///
    /// A match by the second or third order, and a failure where a name is
    /// outside the characters `localeCompare` order is reproduced for, are
    /// written to the `BSVWallet` log with the field count and name length,
    /// never a field name or value.
    public func verifySignature(
        limits: CertificateLimits = .standard
    ) async throws -> Bool {
        guard signature != nil else { throw CertificateError.missingSignature }
        _ = try binary(includingSignature: true, limits: limits)
        let localeOrder = try binary(includingSignature: false, limits: limits)
        if try await verifySignature(over: localeOrder) { return true }
        var tried = [localeOrder]

        let byteOrder = try binary(
            includingSignature: false, limits: limits, fieldOrder: .utf8Bytes)
        if !tried.contains(byteOrder) {
            if try await verifySignature(over: byteOrder) {
                WalletLog.error(
                    "Certificate verification: the signature covers its \(fields.count) fields in "
                        + "UTF-8 byte order, as the Go SDK signs, not in localeCompare order")
                return true
            }
            tried.append(byteOrder)
        }

        if receivedFieldOrder != nil {
            let received = try binary(
                includingSignature: false, limits: limits, fieldOrder: .received)
            if !tried.contains(received), try await verifySignature(over: received) {
                WalletLog.error(
                    "Certificate verification: the signature covers its \(fields.count) fields in "
                        + "the order they were received, which is neither localeCompare order on an "
                        + "en-US host nor UTF-8 byte order")
                return true
            }
        }

        if let name = Self.fieldNameWithoutExactOrder(in: fields.keys) {
            WalletLog.error(
                "Certificate verification: the signature did not verify; a field name of "
                    + "\(name.utf8Bytes.count) bytes has a character whose localeCompare order is not "
                    + "reproduced, so a certificate signed in TypeScript verifies only when read from "
                    + "its binary form")
        }
        return false
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
    /// With fewer than two names there is only one order, so none is returned.
    package static func fieldNameWithoutExactOrder(
        in names: some Collection<CertificateFieldName>
    ) -> CertificateFieldName? {
        guard names.count > 1 else { return nil }
        return names.first { !LocaleCompareOrder.isExact($0.value) }
    }
}

/// A certificate field name this SDK will not sign.
///
/// `@bsv/sdk` orders signed field names with `localeCompare`, which on an
/// `en-US` host is the ICU root collation. `LocaleCompareOrder` reproduces it
/// exactly for printable ASCII and precomposed accented Latin letters such as
/// `é` and `Å`, so when a certificate has two fields or more,
/// `Certificate.signed` and `CertificateEngine.issue` refuse other names,
/// including control characters, decomposed accents and other scripts, rather
/// than sign a certificate TypeScript may not verify. Certificates with such
/// names signed elsewhere still verify when read from their binary form
/// (COMP-041).
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
