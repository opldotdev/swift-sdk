import BSVKeys

extension WalletWireCodec {
    public static func encodeCertificateRequest(
        _ request: WalletWireCertificateRequest,
        originator: String,
        certificateLimits: CertificateLimits = .standard,
        limits: WalletWireLimits = .standard
    ) throws -> [UInt8] {
        let parameters = try encodeCertificateParameters(
            request,
            certificateLimits: certificateLimits,
            limits: limits
        )
        return try encodeRequestFrame(
            WalletWireRequestFrame(
                call: request.call,
                originator: originator,
                parameters: parameters
            ),
            limits: limits
        )
    }

    public static func decodeCertificateRequest(
        _ bytes: [UInt8],
        certificateLimits: CertificateLimits = .standard,
        limits: WalletWireLimits = .standard
    ) throws -> WalletWireDecodedCertificateRequest {
        let frame = try decodeRequestFrame(bytes, limits: limits)
        do {
            return WalletWireDecodedCertificateRequest(
                originator: frame.originator,
                request: try decodeCertificateParameters(
                    frame.parameters,
                    call: frame.call,
                    certificateLimits: certificateLimits,
                    limits: limits
                )
            )
        } catch let error as WalletWireError {
            throw error
        } catch let error as WalletABIError {
            throw walletWireMapABIError(error)
        } catch {
            throw walletWireMapCertificateError(error)
        }
    }

    private static func encodeCertificateParameters(
        _ request: WalletWireCertificateRequest,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        var writer = WalletWireWriter(maximumByteCount: limits.maximumPayloadByteCount)
        switch request {
        case .revealCounterpartyKeyLinkage(let value):
            try walletWireEncodePrivilege(value.privilege, to: &writer, limits: limits)
            writer.writeCertificatePublicKey(value.counterparty)
            writer.writeCertificatePublicKey(value.verifier)
        case .revealSpecificKeyLinkage(let value):
            try walletWireEncodeProtocol(value.protocolID, to: &writer, limits: limits)
            try walletWireWriteText(
                value.keyID.value,
                kind: "key ID",
                to: &writer,
                limits: limits
            )
            walletWireEncodeCounterparty(value.counterparty, to: &writer)
            try walletWireEncodePrivilege(value.privilege, to: &writer, limits: limits)
            writer.writeCertificatePublicKey(value.verifier)
        case .acquireCertificate(let value):
            writer.writeBytes(value.type.bytes)
            writer.writeCertificatePublicKey(value.certifier)
            try walletWireWriteTextMap(
                value.fields,
                kind: "certificate fields",
                to: &writer,
                certificateLimits: certificateLimits,
                limits: limits
            )
            try walletWireEncodePrivilege(value.privilege, to: &writer, limits: limits)
            switch value.acquisition {
            case .direct(let direct):
                writer.writeByte(1)
                writer.writeBytes(direct.serialNumber.bytes)
                writer.writeActionOutpoint(direct.revocationOutpoint)
                try walletWireRequireLowSSignature(direct.signature)
                try writer.writeVarBytes(direct.signature.derBytes)
                switch direct.keyringRevealer {
                case .certifier:
                    writer.writeByte(11)
                case .publicKey(let key):
                    writer.writeCertificatePublicKey(key)
                }
                try walletWireWriteKeyring(
                    direct.keyringForSubject,
                    kind: "subject keyring",
                    to: &writer,
                    certificateLimits: certificateLimits,
                    limits: limits
                )
            case .issuance(let issuance):
                writer.writeByte(2)
                try walletWireWriteText(
                    issuance.certifierURL,
                    kind: "certifier URL",
                    to: &writer,
                    limits: limits
                )
            }
        case .listCertificates(let value):
            guard value.certifiers.count <= limits.abiLimits.maximumCollectionCount else {
                throw WalletWireError.countLimitExceeded(
                    kind: "certifiers",
                    actual: UInt64(value.certifiers.count),
                    maximum: limits.abiLimits.maximumCollectionCount
                )
            }
            writer.writeCompactSize(UInt64(value.certifiers.count))
            for certifier in value.certifiers {
                writer.writeCertificatePublicKey(certifier)
            }
            guard value.types.count <= limits.abiLimits.maximumCollectionCount else {
                throw WalletWireError.countLimitExceeded(
                    kind: "certificate types",
                    actual: UInt64(value.types.count),
                    maximum: limits.abiLimits.maximumCollectionCount
                )
            }
            writer.writeCompactSize(UInt64(value.types.count))
            for type in value.types { writer.writeBytes(type.bytes) }
            writer.writeOptionalUInt32(value.pagination.limit)
            writer.writeOptionalUInt32(value.pagination.offset)
            try walletWireEncodePrivilege(value.privilege, to: &writer, limits: limits)
        case .proveCertificate(let value):
            guard !value.certificate.type.bytes.allSatisfy({ $0 == 0 }) else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "zero prove-certificate type"
                )
            }
            try encodeProveCertificate(
                value,
                to: &writer,
                certificateLimits: certificateLimits,
                limits: limits
            )
        case .relinquishCertificate(let value):
            guard !value.type.bytes.allSatisfy({ $0 == 0 }) else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "zero relinquish-certificate type"
                )
            }
            guard !value.serialNumber.bytes.allSatisfy({ $0 == 0 }) else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "zero relinquish-certificate serial number"
                )
            }
            writer.writeBytes(value.type.bytes)
            writer.writeBytes(value.serialNumber.bytes)
            writer.writeCertificatePublicKey(value.certifier)
        case .discoverByIdentityKey(let value):
            writer.writeCertificatePublicKey(value.identityKey)
            writer.writeOptionalUInt32(value.pagination.limit)
            writer.writeOptionalUInt32(value.pagination.offset)
            writer.writeOptionalBoolean(value.seekPermission)
        case .discoverByAttributes(let value):
            try walletWireWriteTextMap(
                value.attributes,
                kind: "certificate attributes",
                to: &writer,
                certificateLimits: certificateLimits,
                limits: limits
            )
            writer.writeOptionalUInt32(value.pagination.limit)
            writer.writeOptionalUInt32(value.pagination.offset)
            writer.writeOptionalBoolean(value.seekPermission)
        }
        try writer.requireWithinLimit(kind: "request parameters")
        return writer.bytes
    }

    private static func decodeCertificateParameters(
        _ bytes: [UInt8],
        call: WalletCall,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> WalletWireCertificateRequest {
        var reader = WalletWireReader(bytes)
        let request: WalletWireCertificateRequest
        switch call {
        case .revealCounterpartyKeyLinkage:
            let privilege = try walletWireDecodePrivilege(from: &reader, limits: limits)
            request = .revealCounterpartyKeyLinkage(WalletRevealCounterpartyKeyLinkageRequest(
                counterparty: try reader.readCertificatePublicKey(kind: "counterparty"),
                verifier: try reader.readCertificatePublicKey(kind: "verifier"),
                privilege: privilege
            ))
        case .revealSpecificKeyLinkage:
            let protocolID = try walletWireDecodeProtocol(from: &reader, limits: limits)
            let keyText = try reader.readString(
                maximum: WalletKeyID.maximumUTF8ByteCount,
                kind: "key ID"
            )
            let counterparty = try walletWireDecodeCounterparty(from: &reader)
            let privilege = try walletWireDecodePrivilege(from: &reader, limits: limits)
            let verifier = try reader.readCertificatePublicKey(kind: "verifier")
            request = .revealSpecificKeyLinkage(try WalletRevealSpecificKeyLinkageRequest(
                counterparty: counterparty,
                verifier: verifier,
                protocolID: protocolID,
                keyID: try WalletKeyID(keyText),
                privilege: privilege
            ))
        case .acquireCertificate:
            request = .acquireCertificate(try decodeAcquireCertificate(
                from: &reader,
                certificateLimits: certificateLimits,
                limits: limits
            ))
        case .listCertificates:
            let certifierCount = try reader.readCount(
                maximum: limits.abiLimits.maximumCollectionCount,
                kind: "certifiers"
            )
            guard certifierCount <= reader.remainingCount / 33 else {
                throw WalletWireError.truncated
            }
            var certifiers: [PublicKey] = []
            certifiers.reserveCapacity(certifierCount)
            for _ in 0..<certifierCount {
                certifiers.append(try reader.readCertificatePublicKey(kind: "certifier"))
            }
            let typeCount = try reader.readCount(
                maximum: limits.abiLimits.maximumCollectionCount,
                kind: "certificate types"
            )
            guard typeCount <= reader.remainingCount / 32 else {
                throw WalletWireError.truncated
            }
            var types: [CertificateTypeID] = []
            types.reserveCapacity(typeCount)
            for _ in 0..<typeCount {
                types.append(try CertificateTypeID(reader.readBytes(count: 32)))
            }
            let pagination = try WalletPagination(
                limit: reader.readOptionalUInt32(kind: "limit"),
                offset: reader.readOptionalUInt32(kind: "offset")
            )
            let privilege = try walletWireDecodePrivilege(from: &reader, limits: limits)
            request = .listCertificates(try WalletListCertificatesRequest(
                certifiers: certifiers,
                types: types,
                pagination: pagination,
                privilege: privilege,
                limits: limits.abiLimits
            ))
        case .proveCertificate:
            request = .proveCertificate(try decodeProveCertificate(
                from: &reader,
                certificateLimits: certificateLimits,
                limits: limits
            ))
        case .relinquishCertificate:
            let type = try CertificateTypeID(reader.readBytes(count: 32))
            guard !type.bytes.allSatisfy({ $0 == 0 }) else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "zero relinquish-certificate type"
                )
            }
            let serialNumber = try CertificateSerialNumber(reader.readBytes(count: 32))
            guard !serialNumber.bytes.allSatisfy({ $0 == 0 }) else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "zero relinquish-certificate serial number"
                )
            }
            request = .relinquishCertificate(WalletRelinquishCertificateRequest(
                type: type,
                serialNumber: serialNumber,
                certifier: try reader.readCertificatePublicKey(kind: "certifier")
            ))
        case .discoverByIdentityKey:
            let identity = try reader.readCertificatePublicKey(kind: "identity key")
            let pagination = try WalletPagination(
                limit: reader.readOptionalUInt32(kind: "limit"),
                offset: reader.readOptionalUInt32(kind: "offset")
            )
            request = .discoverByIdentityKey(WalletDiscoverByIdentityKeyRequest(
                identityKey: identity,
                pagination: pagination,
                seekPermission: try reader.readOptionalBoolean(kind: "seek permission")
            ))
        case .discoverByAttributes:
            let attributes = try walletWireReadTextMap(
                from: &reader,
                kind: "certificate attributes",
                certificateLimits: certificateLimits,
                limits: limits
            )
            let pagination = try WalletPagination(
                limit: reader.readOptionalUInt32(kind: "limit"),
                offset: reader.readOptionalUInt32(kind: "offset")
            )
            request = .discoverByAttributes(try WalletDiscoverByAttributesRequest(
                attributes: attributes,
                pagination: pagination,
                seekPermission: try reader.readOptionalBoolean(kind: "seek permission"),
                limits: limits.abiLimits
            ))
        default:
            throw WalletWireError.invalidCall(call.rawValue)
        }
        try reader.requireEnd()
        return request
    }
}

private extension WalletWireCodec {
    static func decodeAcquireCertificate(
        from reader: inout WalletWireReader,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> WalletAcquireCertificateRequest {
        let type = try CertificateTypeID(reader.readBytes(count: 32))
        let certifier = try reader.readCertificatePublicKey(kind: "certifier")
        let fields = try walletWireReadTextMap(
            from: &reader,
            kind: "certificate fields",
            certificateLimits: certificateLimits,
            limits: limits
        )
        let privilege = try walletWireDecodePrivilege(from: &reader, limits: limits)
        let acquisition: WalletCertificateAcquisition
        switch try reader.readByte() {
        case 1:
            let serial = try CertificateSerialNumber(reader.readBytes(count: 32))
            let outpoint = try reader.readActionOutpoint()
            guard let signature = try reader.readCertificateSignature(
                optional: false,
                kind: "certificate signature"
            ) else { throw WalletWireError.invalidSignature }
            let revealer: WalletKeyringRevealer
            let marker = try reader.readByte()
            if marker == 11 {
                revealer = .certifier
            } else {
                guard marker == 2 || marker == 3 else {
                    throw WalletWireError.invalidDiscriminator(
                        kind: "keyring revealer",
                        value: marker
                    )
                }
                let rest = try reader.readBytes(count: 32)
                do { revealer = .publicKey(try PublicKey([marker] + rest)) }
                catch { throw WalletWireError.invalidPublicKey }
            }
            let keyring = try walletWireReadKeyring(
                from: &reader,
                kind: "subject keyring",
                certificateLimits: certificateLimits,
                limits: limits
            )
            acquisition = .direct(try WalletDirectCertificateAcquisition(
                serialNumber: serial,
                revocationOutpoint: outpoint,
                signature: signature,
                keyringRevealer: revealer,
                keyringForSubject: keyring,
                limits: limits.abiLimits
            ))
        case 2:
            let url = try reader.readString(
                maximum: walletWireMaximumText(limits),
                kind: "certifier URL"
            )
            acquisition = .issuance(try WalletIssuanceCertificateAcquisition(
                certifierURL: url,
                limits: limits.abiLimits
            ))
        case let flag:
            throw WalletWireError.invalidDiscriminator(
                kind: "certificate acquisition protocol",
                value: flag
            )
        }
        return try WalletAcquireCertificateRequest(
            type: type,
            certifier: certifier,
            fields: fields,
            acquisition: acquisition,
            privilege: privilege,
            limits: limits.abiLimits
        )
    }

    static func encodeProveCertificate(
        _ value: WalletProveCertificateRequest,
        to writer: inout WalletWireWriter,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws {
        let certificate = value.certificate
        writer.writeBytes(certificate.type.bytes)
        writer.writeCertificatePublicKey(certificate.subject)
        writer.writeBytes(certificate.serialNumber.bytes)
        writer.writeCertificatePublicKey(certificate.certifier)
        writer.writeActionOutpoint(certificate.revocationOutpoint)
        if let signature = certificate.signature {
            try walletWireRequireLowSSignature(signature)
            try writer.writeVarBytes(signature.derBytes)
        } else {
            writer.writeCompactSize(0)
        }
        try walletWireWriteCertificateFields(
            certificate.fields,
            to: &writer,
            certificateLimits: certificateLimits,
            limits: limits
        )
        guard value.fieldsToReveal.count <= limits.abiLimits.maximumCollectionCount else {
            throw WalletWireError.countLimitExceeded(
                kind: "fields to reveal",
                actual: UInt64(value.fieldsToReveal.count),
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        writer.writeCompactSize(UInt64(value.fieldsToReveal.count))
        for field in value.fieldsToReveal {
            guard field.utf8Bytes.count <= certificateLimits.maximumFieldNameUTF8ByteCount else {
                throw WalletWireError.byteLimitExceeded(
                    kind: "field to reveal",
                    actual: field.utf8Bytes.count,
                    maximum: certificateLimits.maximumFieldNameUTF8ByteCount
                )
            }
            try writer.writeString(field.value)
        }
        writer.writeCertificatePublicKey(value.verifier)
        try walletWireEncodePrivilege(value.privilege, to: &writer, limits: limits)
    }

    static func decodeProveCertificate(
        from reader: inout WalletWireReader,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> WalletProveCertificateRequest {
        let type = try CertificateTypeID(reader.readBytes(count: 32))
        guard !type.bytes.allSatisfy({ $0 == 0 }) else {
            throw WalletWireError.nonRoundTrippableValue(
                kind: "zero prove-certificate type"
            )
        }
        let subject = try reader.readCertificatePublicKey(kind: "subject")
        let serial = try CertificateSerialNumber(reader.readBytes(count: 32))
        let certifier = try reader.readCertificatePublicKey(kind: "certifier")
        let outpoint = try reader.readActionOutpoint()
        let signature = try reader.readCertificateSignature(
            optional: true,
            kind: "certificate signature"
        )
        let fields = try walletWireReadCertificateFields(
            from: &reader,
            certificateLimits: certificateLimits,
            limits: limits
        )
        let certificate = try Certificate(
            type: type,
            serialNumber: serial,
            subject: subject,
            certifier: certifier,
            revocationOutpoint: outpoint,
            fields: fields,
            signature: signature,
            limits: certificateLimits
        )
        let revealCount = try reader.readCount(
            maximum: limits.abiLimits.maximumCollectionCount,
            kind: "fields to reveal"
        )
        var fieldsToReveal: [CertificateFieldName] = []
        fieldsToReveal.reserveCapacity(min(revealCount, reader.remainingCount))
        var seen = Set<CertificateFieldName>()
        for _ in 0..<revealCount {
            let text = try reader.readString(
                maximum: certificateLimits.maximumFieldNameUTF8ByteCount,
                kind: "field to reveal"
            )
            let name = try CertificateFieldName(text, limits: certificateLimits)
            guard seen.insert(name).inserted else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "duplicate field to reveal"
                )
            }
            fieldsToReveal.append(name)
        }
        let verifier = try reader.readCertificatePublicKey(kind: "verifier")
        let privilege = try walletWireDecodePrivilege(from: &reader, limits: limits)
        return try WalletProveCertificateRequest(
            certificate: certificate,
            fieldsToReveal: fieldsToReveal,
            verifier: verifier,
            privilege: privilege,
            limits: limits.abiLimits
        )
    }
}

private func walletWireWriteCertificateFields(
    _ values: [CertificateFieldName: CertificateCiphertext],
    to writer: inout WalletWireWriter,
    certificateLimits: CertificateLimits,
    limits: WalletWireLimits
) throws {
    guard values.count <= certificateLimits.maximumFieldCount,
          values.count <= limits.abiLimits.maximumCollectionCount else {
        throw WalletWireError.countLimitExceeded(
            kind: "certificate fields",
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
            throw WalletWireError.nonRoundTrippableValue(kind: "certificate fields")
        }
        guard name.utf8Bytes.count <= certificateLimits.maximumFieldNameUTF8ByteCount else {
            throw WalletWireError.byteLimitExceeded(
                kind: "certificate field name",
                actual: name.utf8Bytes.count,
                maximum: certificateLimits.maximumFieldNameUTF8ByteCount
            )
        }
        guard value.bytes.count <= certificateLimits.maximumFieldCiphertextByteCount else {
            throw WalletWireError.byteLimitExceeded(
                kind: "certificate field value",
                actual: value.bytes.count,
                maximum: certificateLimits.maximumFieldCiphertextByteCount
            )
        }
        try writer.writeString(name.value)
        try writer.writeString(value.base64)
    }
}

private func walletWireReadCertificateFields(
    from reader: inout WalletWireReader,
    certificateLimits: CertificateLimits,
    limits: WalletWireLimits
) throws -> [CertificateFieldName: CertificateCiphertext] {
    let count = try reader.readCount(
        maximum: min(
            certificateLimits.maximumFieldCount,
            limits.abiLimits.maximumCollectionCount
        ),
        kind: "certificate fields"
    )
    var result: [CertificateFieldName: CertificateCiphertext] = [:]
    result.reserveCapacity(min(count, reader.remainingCount / 2))
    var prior: CertificateFieldName?
    for _ in 0..<count {
        let nameText = try reader.readString(
            maximum: certificateLimits.maximumFieldNameUTF8ByteCount,
            kind: "certificate field name"
        )
        let name = try CertificateFieldName(nameText, limits: certificateLimits)
        if let prior, !(prior < name) {
            throw WalletWireError.nonRoundTrippableValue(
                kind: "unsorted or duplicate certificate fields"
            )
        }
        prior = name
        let base64 = try reader.readString(
            maximum: certificateLimits.maximumFieldCiphertextBase64UTF8ByteCount,
            kind: "certificate field value"
        )
        result[name] = try CertificateCiphertext(
            base64: base64,
            maximumByteCount: certificateLimits.maximumFieldCiphertextByteCount
        )
    }
    return result
}
