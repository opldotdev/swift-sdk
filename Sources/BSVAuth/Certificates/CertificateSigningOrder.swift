import BSVCore
import BSVCrypto
import BSVKeys
import BSVWallet

/// BRC-52 certificate signatures with fields in `localeCompare` order.
///
/// `@bsv/sdk` signs and verifies the certificate binary with its fields sorted
/// by `localeCompare` (`certificates/Certificate.ts:290`). The Go SDK and
/// `Certificate.binary` sort them by UTF-8 bytes. The two orders agree for
/// lowercase ASCII names and differ for mixed case and some punctuation, for
/// example `age, Zip` against `Zip, age`. This SDK signs in the TypeScript order
/// and accepts a signature over either order.
extension Certificate {
    /// The unsigned BRC-52 binary with fields in `LocaleCompareOrder`.
    package func localeOrderSigningPreimage(limits: CertificateLimits) throws -> [UInt8] {
        let byteOrder = try binary(includingSignature: false, limits: limits)
        var records: [CertificateFieldName: [UInt8]] = [:]
        var recordBytes = 0
        for (name, value) in fields {
            let record =
                CompactSize.encodeVarBytes(name.utf8Bytes)
                + CompactSize.encodeVarBytes(Array(value.base64.utf8))
            records[name] = record
            recordBytes += record.count
        }
        guard recordBytes <= byteOrder.count else { throw CertificateError.fieldNotFound }
        var preimage = Array(byteOrder.prefix(byteOrder.count - recordBytes))
        let names = fields.keys.sorted {
            LocaleCompareOrder.areInIncreasingOrder($0.value, $1.value)
        }
        for name in names {
            guard let record = records[name] else { throw CertificateError.fieldNotFound }
            preimage += record
        }
        return preimage
    }

    /// Signs the `localeCompare`-ordered preimage with the certifier wallet,
    /// as `Certificate.sign` does in `@bsv/sdk`.
    package func signedInLocaleOrder(
        using wallet: any CertificateSignatureWallet,
        limits: CertificateLimits
    ) async throws -> Certificate {
        guard signature == nil else { throw CertificateError.alreadySigned }
        let preimage = try localeOrderSigningPreimage(limits: limits)
        let identity = try await wallet.getPublicKey(.init(selection: .identity)).publicKey
        guard identity == certifier else { throw CertificateError.walletIdentityMismatch }
        let result = try await wallet.createSignature(
            .init(
                protocolID: try CertificateProtocols.signature,
                keyID: try WalletKeyID(signatureKeyID),
                counterparty: .anyone,
                payload: .digest(BSVHashing.sha256(preimage))
            ))
        let signed = try replacingSignature(result.signature, limits: limits)
        _ = try signed.binary(includingSignature: true, limits: limits)
        return signed
    }

    /// Verifies the certifier signature over the `localeCompare`-ordered
    /// preimage, or over the UTF-8 byte-ordered preimage that the Go SDK and
    /// earlier releases of this SDK sign.
    package func verifySignatureInEitherFieldOrder(limits: CertificateLimits) async throws -> Bool {
        guard let signature else { throw CertificateError.missingSignature }
        _ = try binary(includingSignature: true, limits: limits)
        let preimage = try localeOrderSigningPreimage(limits: limits)
        let verifier = try ProtoWallet.anyone()
        let valid = try await verifier.verifySignature(
            .init(
                protocolID: try CertificateProtocols.signature,
                keyID: try WalletKeyID(signatureKeyID),
                counterparty: .publicKey(certifier),
                payload: .digest(BSVHashing.sha256(preimage)),
                signature: signature
            )
        ).valid
        if valid { return true }
        guard try preimage != binary(includingSignature: false, limits: limits) else {
            return false
        }
        return try await verifySignature(limits: limits)
    }
}
