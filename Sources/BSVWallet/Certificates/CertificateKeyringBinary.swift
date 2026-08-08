import BSVCore

/// A bounded BRC-52 map of encrypted field revelation keys.
public struct CertificateKeyring:
    Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let entries: [CertificateFieldName: CertificateCiphertext]

    public init(
        _ entries: [CertificateFieldName: CertificateCiphertext],
        limits: CertificateLimits = .standard
    ) throws {
        guard entries.count <= limits.maximumFieldCount else {
            throw CertificateError.tooManyFields(actual: entries.count, maximum: limits.maximumFieldCount)
        }
        for (name, value) in entries {
            _ = try CertificateFieldName(name.value, limits: limits)
            guard value.bytes.count <= limits.maximumKeyringCiphertextByteCount else {
                throw CertificateError.keyringValueTooLarge(
                    actual: value.bytes.count,
                    maximum: limits.maximumKeyringCiphertextByteCount
                )
            }
        }
        self.entries = entries
    }

    public var description: String { "<redacted certificate keyring>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    /// Canonical `KeyringMapBinary`; values are Base64-decoded in this envelope.
    public func binary(limits: CertificateLimits = .standard) throws -> [UInt8] {
        let names = entries.keys.sorted()
        guard names.count <= limits.maximumFieldCount else {
            throw CertificateError.tooManyFields(actual: names.count, maximum: limits.maximumFieldCount)
        }
        var total = CompactSize.encodedLength(of: UInt64(names.count))
        for name in names {
            guard name.utf8Bytes.count <= limits.maximumFieldNameUTF8ByteCount else {
                throw CertificateError.fieldNameTooLong(
                    actual: name.utf8Bytes.count,
                    maximum: limits.maximumFieldNameUTF8ByteCount
                )
            }
            guard let value = entries[name] else { throw CertificateError.fieldNotFound }
            guard value.bytes.count <= limits.maximumKeyringCiphertextByteCount else {
                throw CertificateError.keyringValueTooLarge(
                    actual: value.bytes.count,
                    maximum: limits.maximumKeyringCiphertextByteCount
                )
            }
            try certificateCheckedAdd(CompactSize.encodedLength(of: UInt64(name.utf8Bytes.count)), to: &total)
            try certificateCheckedAdd(name.utf8Bytes.count, to: &total)
            try certificateCheckedAdd(CompactSize.encodedLength(of: UInt64(value.bytes.count)), to: &total)
            try certificateCheckedAdd(value.bytes.count, to: &total)
        }
        guard total <= limits.maximumBinaryByteCount else {
            throw CertificateError.certificateTooLarge(actual: total, maximum: limits.maximumBinaryByteCount)
        }
        var writer = ByteWriter(capacity: total)
        writer.writeCompactSize(UInt64(names.count))
        for name in names {
            guard let value = entries[name] else { throw CertificateError.fieldNotFound }
            writer.writeVarBytes(name.utf8Bytes)
            writer.writeVarBytes(value.bytes)
        }
        return writer.bytes
    }

    public init(binary bytes: [UInt8], limits: CertificateLimits = .standard) throws {
        guard bytes.count <= limits.maximumBinaryByteCount else {
            throw CertificateError.certificateTooLarge(actual: bytes.count, maximum: limits.maximumBinaryByteCount)
        }
        do {
            var cursor = ByteCursor(bytes)
            let count = try cursor.readCompactSize(canonicality: .required).value
            guard count <= UInt64(limits.maximumFieldCount) else {
                throw CertificateError.tooManyFields(actual: Int(clamping: count), maximum: limits.maximumFieldCount)
            }
            var entries: [CertificateFieldName: CertificateCiphertext] = [:]
            var previous: [UInt8]?
            for _ in 0..<Int(count) {
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
                let value = try cursor.readVarBytes(
                    maximumLength: UInt64(limits.maximumKeyringCiphertextByteCount),
                    canonicality: .required
                ).bytes
                entries[try CertificateFieldName(nameText, limits: limits)] = try CertificateCiphertext(
                    value,
                    maximumByteCount: limits.maximumKeyringCiphertextByteCount
                )
            }
            try cursor.requireFinished()
            try self.init(entries, limits: limits)
        } catch let error as CertificateError {
            throw error
        } catch BinaryDecodingError.nonCanonicalCompactSize {
            throw CertificateError.nonCanonicalCompactSize
        } catch {
            throw CertificateError.truncatedCertificate
        }
    }
}

/// The unsigned envelope carrying a complete signed core certificate and keyring.
public struct CertificateWithKeyringBinary:
    Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let certificate: Certificate
    public let keyring: CertificateKeyring

    public init(certificate: Certificate, keyring: CertificateKeyring) throws {
        guard certificate.signature != nil else { throw CertificateError.missingSignature }
        self.certificate = certificate
        self.keyring = keyring
    }

    public var description: String { "<redacted certificate-with-keyring envelope>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    public func binary(limits: CertificateLimits = .standard) throws -> [UInt8] {
        let certificateBytes = try certificate.binary(includingSignature: true, limits: limits)
        let keyringBytes = try keyring.binary(limits: limits)
        var total = CompactSize.encodedLength(of: UInt64(certificateBytes.count))
        try certificateCheckedAdd(certificateBytes.count, to: &total)
        try certificateCheckedAdd(keyringBytes.count, to: &total)
        guard total <= limits.maximumBinaryByteCount else {
            throw CertificateError.certificateTooLarge(actual: total, maximum: limits.maximumBinaryByteCount)
        }
        var writer = ByteWriter(capacity: total)
        writer.writeVarBytes(certificateBytes)
        writer.write(keyringBytes)
        return writer.bytes
    }

    public init(binary bytes: [UInt8], limits: CertificateLimits = .standard) throws {
        guard bytes.count <= limits.maximumBinaryByteCount else {
            throw CertificateError.certificateTooLarge(actual: bytes.count, maximum: limits.maximumBinaryByteCount)
        }
        do {
            var cursor = ByteCursor(bytes)
            let certificateBytes = try cursor.readVarBytes(
                maximumLength: UInt64(limits.maximumBinaryByteCount),
                canonicality: .required
            ).bytes
            let keyringBytes = try cursor.read(count: cursor.remaining)
            let certificate = try Certificate(binary: certificateBytes, limits: limits)
            guard certificate.signature != nil else { throw CertificateError.missingSignature }
            try self.init(
                certificate: certificate,
                keyring: CertificateKeyring(binary: keyringBytes, limits: limits)
            )
        } catch let error as CertificateError {
            throw error
        } catch BinaryDecodingError.nonCanonicalCompactSize {
            throw CertificateError.nonCanonicalCompactSize
        } catch {
            throw CertificateError.truncatedCertificate
        }
    }
}
