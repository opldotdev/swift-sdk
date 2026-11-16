import BSVKeys

extension WalletWireWriter {
    mutating func writeCertificatePublicKey(_ value: PublicKey) {
        writeBytes(value.compressedBytes)
    }
}

extension WalletWireReader {
    mutating func readCertificatePublicKey(kind: String) throws -> PublicKey {
        let encoded = try readBytes(count: 33)
        do {
            let key = try PublicKey(encoded)
            guard key.compressedBytes == encoded else { throw WalletWireError.invalidPublicKey }
            return key
        } catch {
            throw WalletWireError.invalidPublicKey
        }
    }

    mutating func readCertificateSignature(
        optional: Bool,
        kind: String
    ) throws -> ECDSASignature? {
        let encoded = try readVarBytes(maximum: 72, kind: kind)
        if encoded.isEmpty, optional { return nil }
        guard !encoded.isEmpty else { throw WalletWireError.invalidSignature }
        do {
            let signature = try ECDSASignature(derBytes: encoded)
            guard signature.derBytes == encoded else { throw WalletWireError.invalidSignature }
            try walletWireRequireLowSSignature(signature)
            return signature
        } catch let error as WalletWireError {
            throw error
        } catch {
            throw WalletWireError.invalidSignature
        }
    }
}

func walletWireEncodePrivilege(
    _ privilege: WalletPrivilege,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    writer.writeOptionalBoolean(privilege.privileged)
    guard let reason = privilege.privilegedReason else {
        writer.writeByte(0xff)
        return
    }
    guard !reason.isEmpty else {
        throw WalletWireError.nonRoundTrippableValue(kind: "empty privileged reason")
    }
    try walletWireWriteText(reason, kind: "privileged reason", to: &writer, limits: limits)
}

func walletWireDecodePrivilege(
    from reader: inout WalletWireReader,
    limits: WalletWireLimits
) throws -> WalletPrivilege {
    let privileged = try reader.readOptionalBoolean(kind: "privileged")
    let reason = try reader.readOptionalReason(maximum: walletWireMaximumText(limits))
    do {
        return try WalletPrivilege(
            privileged: privileged,
            privilegedReason: reason,
            limits: limits.abiLimits
        )
    } catch let error as WalletABIError {
        throw walletWireMapABIError(error)
    }
}

func walletWireSortedCertificateNames<Value>(
    _ values: [CertificateFieldName: Value]
) -> [CertificateFieldName] {
    values.keys.sorted()
}

func walletWireWriteTextMap(
    _ values: [CertificateFieldName: String],
    kind: String,
    to writer: inout WalletWireWriter,
    certificateLimits: CertificateLimits,
    limits: WalletWireLimits
) throws {
    let maximum = min(
        certificateLimits.maximumFieldCount,
        limits.abiLimits.maximumCollectionCount
    )
    guard values.count <= maximum else {
        throw WalletWireError.countLimitExceeded(
            kind: kind,
            actual: UInt64(values.count),
            maximum: maximum
        )
    }
    let names = walletWireSortedCertificateNames(values)
    writer.writeCompactSize(UInt64(names.count))
    for name in names {
        guard let value = values[name] else {
            throw WalletWireError.nonRoundTrippableValue(kind: kind)
        }
        guard name.utf8Bytes.count <= certificateLimits.maximumFieldNameUTF8ByteCount else {
            throw WalletWireError.byteLimitExceeded(
                kind: "\(kind) name",
                actual: name.utf8Bytes.count,
                maximum: certificateLimits.maximumFieldNameUTF8ByteCount
            )
        }
        try writer.writeString(name.value)
        try walletWireWriteText(value, kind: kind, to: &writer, limits: limits)
    }
}

func walletWireReadTextMap(
    from reader: inout WalletWireReader,
    kind: String,
    certificateLimits: CertificateLimits,
    limits: WalletWireLimits
) throws -> [CertificateFieldName: String] {
    let count = try reader.readCount(
        maximum: min(
            certificateLimits.maximumFieldCount,
            limits.abiLimits.maximumCollectionCount
        ),
        kind: kind
    )
    var result: [CertificateFieldName: String] = [:]
    result.reserveCapacity(min(count, reader.remainingCount / 2))
    var previous = Set<[UInt8]>()
    for _ in 0..<count {
        let nameBytes = try reader.readVarBytes(
            maximum: certificateLimits.maximumFieldNameUTF8ByteCount,
            kind: "\(kind) name"
        )
        try walletWireRequireStrictMapOrder(nameBytes, after: &previous, kind: kind)
        guard let nameText = String(bytes: nameBytes, encoding: .utf8) else {
            throw WalletWireError.invalidUTF8(kind: "\(kind) name")
        }
        let value = try reader.readString(
            maximum: walletWireMaximumText(limits),
            kind: "\(kind) value"
        )
        do {
            result[try CertificateFieldName(nameText, limits: certificateLimits)] = value
        } catch {
            throw walletWireMapCertificateError(error)
        }
    }
    return result
}

func walletWireWriteKeyring(
    _ values: [CertificateFieldName: CertificateCiphertext],
    kind: String,
    to writer: inout WalletWireWriter,
    certificateLimits: CertificateLimits,
    limits: WalletWireLimits
) throws {
    guard values.count <= certificateLimits.maximumFieldCount,
          values.count <= limits.abiLimits.maximumCollectionCount else {
        throw WalletWireError.countLimitExceeded(
            kind: kind,
            actual: UInt64(values.count),
            maximum: min(
                certificateLimits.maximumFieldCount,
                limits.abiLimits.maximumCollectionCount
            )
        )
    }
    let names = walletWireSortedCertificateNames(values)
    writer.writeCompactSize(UInt64(names.count))
    for name in names {
        guard let value = values[name] else {
            throw WalletWireError.nonRoundTrippableValue(kind: kind)
        }
        guard name.utf8Bytes.count <= certificateLimits.maximumFieldNameUTF8ByteCount else {
            throw WalletWireError.byteLimitExceeded(
                kind: "\(kind) name",
                actual: name.utf8Bytes.count,
                maximum: certificateLimits.maximumFieldNameUTF8ByteCount
            )
        }
        guard value.bytes.count <= certificateLimits.maximumKeyringCiphertextByteCount else {
            throw WalletWireError.byteLimitExceeded(
                kind: "\(kind) value",
                actual: value.bytes.count,
                maximum: certificateLimits.maximumKeyringCiphertextByteCount
            )
        }
        try writer.writeString(name.value)
        try writer.writeVarBytes(value.bytes)
    }
}

func walletWireReadKeyring(
    from reader: inout WalletWireReader,
    kind: String,
    certificateLimits: CertificateLimits,
    limits: WalletWireLimits
) throws -> [CertificateFieldName: CertificateCiphertext] {
    let maximum = min(
        certificateLimits.maximumFieldCount,
        limits.abiLimits.maximumCollectionCount
    )
    let count = try reader.readCount(maximum: maximum, kind: kind)
    var result: [CertificateFieldName: CertificateCiphertext] = [:]
    result.reserveCapacity(min(count, reader.remainingCount / 2))
    var previous = Set<[UInt8]>()
    for _ in 0..<count {
        let nameBytes = try reader.readVarBytes(
            maximum: certificateLimits.maximumFieldNameUTF8ByteCount,
            kind: "\(kind) name"
        )
        try walletWireRequireStrictMapOrder(nameBytes, after: &previous, kind: kind)
        guard let nameText = String(bytes: nameBytes, encoding: .utf8) else {
            throw WalletWireError.invalidUTF8(kind: "\(kind) name")
        }
        let value = try reader.readVarBytes(
            maximum: certificateLimits.maximumKeyringCiphertextByteCount,
            kind: "\(kind) value"
        )
        do {
            let name = try CertificateFieldName(nameText, limits: certificateLimits)
            result[name] = try CertificateCiphertext(
                value,
                maximumByteCount: certificateLimits.maximumKeyringCiphertextByteCount
            )
        } catch {
            throw walletWireMapCertificateError(error)
        }
    }
    return result
}

/// Map entries may arrive in any order (@bsv/sdk writes insertion order), but a
/// name may appear only once.
private func walletWireRequireStrictMapOrder(
    _ current: [UInt8],
    after previous: inout Set<[UInt8]>,
    kind: String
) throws {
    guard previous.insert(current).inserted else {
        throw WalletWireError.nonRoundTrippableValue(kind: "duplicate \(kind)")
    }
}

/// Maps certificate size and encoding failures to wire errors and keeps every other
/// error as it is, so the error frame and the log both say what was wrong.
func walletWireMapCertificateError(_ error: Error) -> any Error {
    guard let certificate = error as? CertificateError else { return error }
    switch certificate {
    case .tooManyFields(let actual, let maximum):
        return WalletWireError.countLimitExceeded(
            kind: "certificate fields",
            actual: UInt64(max(0, actual)),
            maximum: maximum
        )
    case .fieldNameTooLong(let actual, let maximum),
         .fieldValueTooLarge(let actual, let maximum),
         .keyringValueTooLarge(let actual, let maximum),
         .certificateTooLarge(let actual, let maximum):
        return WalletWireError.byteLimitExceeded(
            kind: "certificate value",
            actual: actual,
            maximum: maximum
        )
    case .nonCanonicalCompactSize:
        return WalletWireError.noncanonicalCompactSize
    case .truncatedCertificate:
        return WalletWireError.truncated
    case .invalidPublicKey:
        return WalletWireError.invalidPublicKey
    case .invalidSignature:
        return WalletWireError.invalidSignature
    default:
        return certificate
    }
}
