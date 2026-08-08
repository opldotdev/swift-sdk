import BSVCore
import BSVKeys
import BSVTransaction

extension Certificate {
    /// Canonical BRC-52 binary form. The revocation transaction ID is written in
    /// human-display byte order, matching BRC-52 and the pinned Go v1.3.3 SDK.
    public func binary(
        includingSignature: Bool,
        limits: CertificateLimits = .standard
    ) throws -> [UInt8] {
        if includingSignature && signature == nil { throw CertificateError.missingSignature }
        guard fields.count <= limits.maximumFieldCount else {
            throw CertificateError.tooManyFields(actual: fields.count, maximum: limits.maximumFieldCount)
        }
        let names = fields.keys.sorted()
        var total = 162
        try certificateCheckedAdd(CompactSize.encodedLength(of: UInt64(revocationOutpoint.outputIndex)), to: &total)
        try certificateCheckedAdd(CompactSize.encodedLength(of: UInt64(names.count)), to: &total)
        for name in names {
            guard name.utf8Bytes.count <= limits.maximumFieldNameUTF8ByteCount else {
                throw CertificateError.fieldNameTooLong(
                    actual: name.utf8Bytes.count,
                    maximum: limits.maximumFieldNameUTF8ByteCount
                )
            }
            guard let value = fields[name] else { throw CertificateError.fieldNotFound }
            guard value.bytes.count <= limits.maximumFieldCiphertextByteCount else {
                throw CertificateError.fieldValueTooLarge(
                    actual: value.bytes.count,
                    maximum: limits.maximumFieldCiphertextByteCount
                )
            }
            let encodedCount = try certificateBase64EncodedByteCount(value.bytes.count)
            try certificateCheckedAdd(CompactSize.encodedLength(of: UInt64(name.utf8Bytes.count)), to: &total)
            try certificateCheckedAdd(name.utf8Bytes.count, to: &total)
            try certificateCheckedAdd(CompactSize.encodedLength(of: UInt64(encodedCount)), to: &total)
            try certificateCheckedAdd(encodedCount, to: &total)
        }
        if includingSignature, let signature {
            try certificateCheckedAdd(signature.derBytes.count, to: &total)
        }
        guard total <= limits.maximumBinaryByteCount else {
            throw CertificateError.certificateTooLarge(actual: total, maximum: limits.maximumBinaryByteCount)
        }

        var writer = ByteWriter(capacity: total)
        writer.write(type.bytes)
        writer.write(serialNumber.bytes)
        writer.write(subject.compressedBytes)
        writer.write(certifier.compressedBytes)
        writer.write(revocationOutpoint.transactionID.displayBytes)
        writer.writeCompactSize(UInt64(revocationOutpoint.outputIndex))
        writer.writeCompactSize(UInt64(names.count))
        for name in names {
            guard let value = fields[name] else { throw CertificateError.fieldNotFound }
            writer.writeVarBytes(name.utf8Bytes)
            writer.writeVarBytes(Array(value.base64.utf8))
        }
        if includingSignature, let signature { writer.write(signature.derBytes) }
        return writer.bytes
    }

    /// Parses one complete canonical BRC-52 binary certificate.
    ///
    /// Unlike the pinned Go decoder, this rejects nonminimal CompactSize values,
    /// unsorted fields, duplicate names, high-width vouts, noncanonical Base64,
    /// noncanonical DER, and DER trailing bytes.
    public init(binary bytes: [UInt8], limits: CertificateLimits = .standard) throws {
        guard bytes.count <= limits.maximumBinaryByteCount else {
            throw CertificateError.certificateTooLarge(actual: bytes.count, maximum: limits.maximumBinaryByteCount)
        }
        do {
            var cursor = ByteCursor(bytes)
            let type = try CertificateTypeID(cursor.read(count: 32))
            let serial = try CertificateSerialNumber(cursor.read(count: 32))
            let subject = try PublicKey(cursor.read(count: 33))
            let certifier = try PublicKey(cursor.read(count: 33))
            let txid = try TransactionID(displayHex: Hex.encode(cursor.read(count: 32)))
            let output = try cursor.readCompactSize(canonicality: .required).value
            guard output <= UInt64(UInt32.max) else { throw CertificateError.invalidOutputIndex }
            let outpoint = Outpoint(transactionID: txid, outputIndex: UInt32(output))
            let fieldCount = try cursor.readCompactSize(canonicality: .required).value
            guard fieldCount <= UInt64(limits.maximumFieldCount) else {
                throw CertificateError.tooManyFields(actual: Int(clamping: fieldCount), maximum: limits.maximumFieldCount)
            }
            var fields: [CertificateFieldName: CertificateCiphertext] = [:]
            var previous: [UInt8]?
            for _ in 0..<Int(fieldCount) {
                let nameBytes = try cursor.readVarBytes(
                    maximumLength: UInt64(limits.maximumFieldNameUTF8ByteCount),
                    canonicality: .required
                ).bytes
                guard let nameText = String(bytes: nameBytes, encoding: .utf8),
                      Array(nameText.utf8) == nameBytes else { throw CertificateError.invalidUTF8 }
                if let previous, !previous.lexicographicallyPrecedes(nameBytes) {
                    throw previous == nameBytes ? CertificateError.duplicateFieldName : CertificateError.fieldsNotInCanonicalOrder
                }
                previous = nameBytes
                let valueBytes = try cursor.readVarBytes(
                    maximumLength: UInt64(limits.maximumFieldCiphertextBase64UTF8ByteCount),
                    canonicality: .required
                ).bytes
                guard let valueText = String(bytes: valueBytes, encoding: .utf8),
                      Array(valueText.utf8) == valueBytes else { throw CertificateError.invalidUTF8 }
                let name = try CertificateFieldName(nameText, limits: limits)
                let value = try CertificateCiphertext(base64: valueText, maximumByteCount: limits.maximumFieldCiphertextByteCount)
                fields[name] = value
            }
            let signature: ECDSASignature?
            if cursor.remaining == 0 {
                signature = nil
            } else {
                guard cursor.remaining <= 72 else { throw CertificateError.invalidSignature }
                let der = try cursor.read(count: cursor.remaining)
                let parsed = try ECDSASignature(derBytes: der)
                guard parsed.derBytes == der else { throw CertificateError.invalidSignature }
                signature = parsed
            }
            try cursor.requireFinished()
            try self.init(type: type, serialNumber: serial, subject: subject, certifier: certifier, revocationOutpoint: outpoint, fields: fields, signature: signature, limits: limits)
        } catch let error as CertificateError {
            throw error
        } catch BinaryDecodingError.nonCanonicalCompactSize {
            throw CertificateError.nonCanonicalCompactSize
        } catch is BinaryDecodingError {
            throw CertificateError.truncatedCertificate
        } catch is ECDSASignatureError {
            throw CertificateError.invalidSignature
        } catch {
            throw CertificateError.invalidPublicKey
        }
    }
}
