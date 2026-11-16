import BSVCore
import BSVKeys

extension WalletWireCodec {
    /// Encodes a certificate result. Given the `request` it answers, a list or discovery
    /// result may hold no more records than the request's limit, as `@bsv/sdk` 4.1.1 checks.
    public static func encodeCertificateResult(
        _ result: WalletWireCertificateResult,
        request: WalletWireCertificateRequest? = nil,
        certificateLimits: CertificateLimits = .standard,
        limits: WalletWireLimits = .standard
    ) throws -> [UInt8] {
        do {
            let payload = try encodeCertificateResultPayload(
                result,
                requestedLimit: walletWireRequestedPageLimit(request),
                certificateLimits: certificateLimits,
                limits: limits
            )
            return try encodeResultFrame(.success(payload), limits: limits)
        } catch let error as WalletWireError {
            throw error
        } catch let error as WalletWireResultRejection {
            throw error
        } catch let error as WalletABIError {
            throw walletWireMapABIError(error)
        } catch {
            throw walletWireMapCertificateError(error)
        }
    }

    /// Decodes a certificate result. Given the `request` it answers, a list or discovery
    /// page is read up to the request's limit (10 when it gives none), as `@bsv/sdk` 4.1.1 does.
    public static func decodeCertificateResult(
        _ bytes: [UInt8],
        expectedCall: WalletCall,
        request: WalletWireCertificateRequest? = nil,
        certificateLimits: CertificateLimits = .standard,
        limits: WalletWireLimits = .standard
    ) throws -> WalletWireCertificateResult {
        switch try decodeResultFrame(bytes, limits: limits) {
        case .failure(let remote):
            throw remote
        case .success(let payload):
            do {
                return try decodeCertificateResultPayload(
                    payload,
                    call: expectedCall,
                    requestedLimit: walletWireRequestedPageLimit(request),
                    certificateLimits: certificateLimits,
                    limits: limits
                )
            } catch let error as WalletWireError {
                throw error
            } catch let error as WalletWireResultRejection {
                throw error
            } catch let error as WalletABIError {
                throw walletWireMapABIError(error)
            } catch {
                throw walletWireMapCertificateError(error)
            }
        }
    }

    private static func encodeCertificateResultPayload(
        _ result: WalletWireCertificateResult,
        requestedLimit: Int?,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        var writer = WalletWireWriter(maximumByteCount: limits.maximumPayloadByteCount)
        switch result {
        case .revealCounterpartyKeyLinkage(let value):
            writer.writeCertificatePublicKey(value.prover)
            writer.writeCertificatePublicKey(value.verifier)
            writer.writeCertificatePublicKey(value.counterparty)
            try walletWireWriteText(
                value.revelationTime,
                kind: "revelation time",
                to: &writer,
                limits: limits
            )
            try walletWireWriteLinkageBytes(
                value.encryptedLinkage.bytes,
                kind: "encrypted linkage",
                to: &writer,
                limits: limits
            )
            try walletWireWriteLinkageBytes(
                value.encryptedLinkageProof.bytes,
                kind: "encrypted linkage proof",
                to: &writer,
                limits: limits
            )
        case .revealSpecificKeyLinkage(let value):
            writer.writeCertificatePublicKey(value.prover)
            writer.writeCertificatePublicKey(value.verifier)
            writer.writeCertificatePublicKey(value.counterparty)
            try walletWireEncodeProtocol(value.protocolID, to: &writer, limits: limits)
            try walletWireWriteText(
                value.keyID.value,
                kind: "key ID",
                to: &writer,
                limits: limits
            )
            try walletWireWriteLinkageBytes(
                value.encryptedLinkage.bytes,
                kind: "encrypted linkage",
                to: &writer,
                limits: limits
            )
            try walletWireWriteLinkageBytes(
                value.encryptedLinkageProof.bytes,
                kind: "encrypted linkage proof",
                to: &writer,
                limits: limits
            )
            writer.writeByte(value.proofType)
        case .acquireCertificate(let certificate):
            try walletWireRequireSignedCertificate(certificate)
            let nestedLimits = try walletWireNestedCertificateLimits(
                certificateLimits,
                maximumBinaryByteCount: walletWireRemainingCapacity(
                    in: writer,
                    maximum: limits.maximumPayloadByteCount
                )
            )
            writer.writeBytes(try certificate.binary(
                includingSignature: true,
                limits: nestedLimits
            ))
        case .listCertificates(let value):
            try walletWireRequireResultPage(
                records: value.certificates.count,
                total: UInt64(value.totalCertificates),
                limit: requestedLimit,
                call: "listCertificates",
                totalField: "totalCertificates",
                entriesField: "certificates",
                resultName: "listCertificates result"
            )
            guard value.certificates.count <= limits.abiLimits.maximumCollectionCount else {
                throw WalletWireError.countLimitExceeded(
                    kind: "certificates",
                    actual: UInt64(value.certificates.count),
                    maximum: limits.abiLimits.maximumCollectionCount
                )
            }
            writer.writeCompactSize(UInt64(value.totalCertificates))
            for item in value.certificates {
                try walletWireRequireSignedCertificate(item.certificate)
                let nestedLimits = try walletWireNestedCertificateLimits(
                    certificateLimits,
                    maximumBinaryByteCount: walletWireMaximumVarBytesPayload(
                        in: walletWireRemainingCapacity(
                            in: writer,
                            maximum: limits.maximumPayloadByteCount
                        )
                    )
                )
                try writer.writeVarBytes(item.certificate.binary(
                    includingSignature: true,
                    limits: nestedLimits
                ))
                // TS writes flag 0 for an absent or empty keyring
                // (wallet/substrates/WalletWireProcessor.ts:2118).
                if let keyring = item.keyring, !keyring.isEmpty {
                    writer.writeByte(1)
                    try walletWireWriteKeyring(
                        keyring,
                        kind: "certificate keyring",
                        to: &writer,
                        certificateLimits: certificateLimits,
                        limits: limits
                    )
                } else {
                    writer.writeByte(0)
                }
                try walletWireWriteCertificateVerifier(item.verifier, to: &writer)
            }
        case .proveCertificate(let value):
            try walletWireWriteKeyring(
                value.keyringForVerifier,
                kind: "verifier keyring",
                to: &writer,
                certificateLimits: certificateLimits,
                limits: limits
            )
        case .relinquishCertificate(let value):
            guard value.relinquished else {
                // wallet/substrates/WalletWireProcessor.ts:2293
                throw WalletWireResultRejection(message: WalletWireFailureText.notRelinquishedCertificate)
            }
        case .discoverByIdentityKey(let value), .discoverByAttributes(let value):
            try encodeDiscoveryResult(
                value,
                call: result.call,
                requestedLimit: requestedLimit,
                to: &writer,
                certificateLimits: certificateLimits,
                limits: limits
            )
        }
        try writer.requireWithinLimit(kind: "result payload")
        return writer.bytes
    }

    private static func decodeCertificateResultPayload(
        _ bytes: [UInt8],
        call: WalletCall,
        requestedLimit: Int?,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> WalletWireCertificateResult {
        var reader = WalletWireReader(bytes)
        let result: WalletWireCertificateResult
        switch call {
        case .revealCounterpartyKeyLinkage:
            let prover = try reader.readCertificatePublicKey(kind: "prover")
            let verifier = try reader.readCertificatePublicKey(kind: "verifier")
            let counterparty = try reader.readCertificatePublicKey(kind: "counterparty")
            let time = try reader.readString(
                maximum: walletWireMaximumText(limits),
                kind: "revelation time"
            )
            let linkage = try reader.readVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount,
                kind: "encrypted linkage"
            )
            let proof = try reader.readVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount,
                kind: "encrypted linkage proof"
            )
            result = .revealCounterpartyKeyLinkage(
                try WalletRevealCounterpartyKeyLinkageResult(
                    prover: prover,
                    counterparty: counterparty,
                    verifier: verifier,
                    revelationTime: time,
                    encryptedLinkage: WalletLinkageCiphertext(
                        linkage,
                        limits: limits.abiLimits
                    ),
                    encryptedLinkageProof: WalletLinkageCiphertext(
                        proof,
                        limits: limits.abiLimits
                    ),
                    limits: limits.abiLimits
                )
            )
        case .revealSpecificKeyLinkage:
            let prover = try reader.readCertificatePublicKey(kind: "prover")
            let verifier = try reader.readCertificatePublicKey(kind: "verifier")
            let counterparty = try reader.readCertificatePublicKey(kind: "counterparty")
            let protocolID = try walletWireDecodeProtocol(from: &reader, limits: limits)
            let keyID = try WalletKeyID(reader.readString(
                maximum: WalletKeyID.maximumUTF8ByteCount,
                kind: "key ID"
            ))
            let linkage = try reader.readVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount,
                kind: "encrypted linkage"
            )
            let proof = try reader.readVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount,
                kind: "encrypted linkage proof"
            )
            result = .revealSpecificKeyLinkage(try WalletRevealSpecificKeyLinkageResult(
                encryptedLinkage: WalletLinkageCiphertext(
                    linkage,
                    limits: limits.abiLimits
                ),
                encryptedLinkageProof: WalletLinkageCiphertext(
                    proof,
                    limits: limits.abiLimits
                ),
                prover: prover,
                verifier: verifier,
                counterparty: counterparty,
                protocolID: protocolID,
                keyID: keyID,
                proofType: reader.readByte(),
                limits: limits.abiLimits
            ))
        case .acquireCertificate:
            let certificate = try Certificate(binary: bytes, limits: certificateLimits)
            try walletWireRequireSignedCertificate(certificate)
            reader = WalletWireReader([])
            result = .acquireCertificate(certificate)
        case .listCertificates:
            result = .listCertificates(try decodeListCertificatesResult(
                from: &reader,
                requestedLimit: requestedLimit,
                certificateLimits: certificateLimits,
                limits: limits
            ))
        case .proveCertificate:
            result = .proveCertificate(try WalletProveCertificateResult(
                keyringForVerifier: walletWireReadKeyring(
                    from: &reader,
                    kind: "verifier keyring",
                    certificateLimits: certificateLimits,
                    limits: limits
                ),
                limits: limits.abiLimits
            ))
        case .relinquishCertificate:
            try reader.requireEnd()
            result = .relinquishCertificate(
                WalletRelinquishCertificateResult(relinquished: true)
            )
        case .discoverByIdentityKey:
            result = .discoverByIdentityKey(try decodeDiscoveryResult(
                from: &reader,
                requestedLimit: requestedLimit,
                certificateLimits: certificateLimits,
                limits: limits
            ))
        case .discoverByAttributes:
            result = .discoverByAttributes(try decodeDiscoveryResult(
                from: &reader,
                requestedLimit: requestedLimit,
                certificateLimits: certificateLimits,
                limits: limits
            ))
        default:
            throw WalletWireError.invalidCall(call.rawValue)
        }
        try reader.requireEnd()
        return result
    }
}

private extension WalletWireCodec {
    static func decodeListCertificatesResult(
        from reader: inout WalletWireReader,
        requestedLimit: Int?,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> WalletListCertificatesResult {
        // @bsv/sdk writes the total, then records until the end of the frame.
        let totalRaw = try reader.readCompactSize()
        guard let total = UInt32(exactly: totalRaw) else { throw WalletWireError.uint32Overflow }
        var certificates: [WalletCertificateResult] = []
        while !reader.isAtEnd {
            try walletWireRequirePageCapacity(
                certificates.count,
                limit: requestedLimit ?? limits.abiLimits.maximumCollectionCount,
                call: "listCertificates"
            )
            let certificateBytes = try reader.readVarBytes(
                maximum: certificateLimits.maximumBinaryByteCount,
                kind: "certificate"
            )
            let certificate = try Certificate(binary: certificateBytes, limits: certificateLimits)
            try walletWireRequireSignedCertificate(certificate)
            let keyring: [CertificateFieldName: CertificateCiphertext]?
            switch try reader.readByte() {
            case 0:
                keyring = nil
            case 1:
                // TS reads flag 1 with no entries as an empty keyring; it is stored as nil.
                keyring = try walletWireReadKeyring(
                    from: &reader,
                    kind: "certificate keyring",
                    certificateLimits: certificateLimits,
                    limits: limits
                )
            case let flag:
                throw WalletWireError.invalidDiscriminator(
                    kind: "certificate keyring presence",
                    value: flag
                )
            }
            let verifier = try walletWireReadCertificateVerifier(from: &reader)
            certificates.append(try WalletCertificateResult(
                certificate: certificate,
                keyring: keyring,
                verifier: verifier,
                limits: limits.abiLimits
            ))
        }
        try walletWireRequireResponsePage(
            records: certificates.count, total: totalRaw, call: "listCertificates"
        )
        return try WalletListCertificatesResult(
            totalCertificates: total,
            certificates: certificates,
            limits: limits.abiLimits
        )
    }

    static func encodeDiscoveryResult(
        _ value: WalletDiscoverCertificatesResult,
        call: WalletCall,
        requestedLimit: Int?,
        to writer: inout WalletWireWriter,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws {
        try walletWireRequireResultPage(
            records: value.certificates.count,
            total: UInt64(value.totalCertificates),
            limit: requestedLimit,
            call: call.wireMethodName,
            totalField: "totalCertificates",
            entriesField: "certificates",
            resultName: "discovery result"
        )
        guard value.certificates.count <= limits.abiLimits.maximumCollectionCount else {
            throw WalletWireError.countLimitExceeded(
                kind: "discovered certificates",
                actual: UInt64(value.certificates.count),
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        writer.writeCompactSize(UInt64(value.totalCertificates))
        for certificate in value.certificates {
            try encodeIdentityCertificate(
                certificate,
                to: &writer,
                certificateLimits: certificateLimits,
                limits: limits
            )
        }
    }

    static func decodeDiscoveryResult(
        from reader: inout WalletWireReader,
        requestedLimit: Int?,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> WalletDiscoverCertificatesResult {
        let totalRaw = try reader.readCompactSize()
        guard let total = UInt32(exactly: totalRaw) else { throw WalletWireError.uint32Overflow }
        var certificates: [WalletIdentityCertificate] = []
        while !reader.isAtEnd {
            try walletWireRequirePageCapacity(
                certificates.count,
                limit: requestedLimit ?? limits.abiLimits.maximumCollectionCount,
                call: "discover"
            )
            certificates.append(try decodeIdentityCertificate(
                from: &reader,
                certificateLimits: certificateLimits,
                limits: limits
            ))
        }
        try walletWireRequireResponsePage(
            records: certificates.count, total: totalRaw, call: "discover"
        )
        return try WalletDiscoverCertificatesResult(
            totalCertificates: total,
            certificates: certificates,
            limits: limits.abiLimits
        )
    }

    static func encodeIdentityCertificate(
        _ value: WalletIdentityCertificate,
        to writer: inout WalletWireWriter,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws {
        try walletWireRequireSignedCertificate(value.certificate)
        let nestedLimits = try walletWireNestedCertificateLimits(
            certificateLimits,
            maximumBinaryByteCount: walletWireMaximumVarBytesPayload(
                in: walletWireRemainingCapacity(
                    in: writer,
                    maximum: limits.maximumPayloadByteCount
                )
            )
        )
        try writer.writeVarBytes(value.certificate.binary(
            includingSignature: true,
            limits: nestedLimits
        ))
        try walletWireWriteText(
            value.certifierInfo.name,
            kind: "certifier name",
            to: &writer,
            limits: limits
        )
        try walletWireWriteText(
            value.certifierInfo.iconURL,
            kind: "certifier icon URL",
            to: &writer,
            limits: limits
        )
        try walletWireWriteText(
            value.certifierInfo.description,
            kind: "certifier description",
            to: &writer,
            limits: limits
        )
        writer.writeByte(value.certifierInfo.trust)
        try walletWireWriteKeyring(
            value.publiclyRevealedKeyring,
            kind: "public keyring",
            to: &writer,
            certificateLimits: certificateLimits,
            limits: limits
        )
        try walletWireWriteTextMap(
            value.decryptedFields,
            kind: "decrypted fields",
            to: &writer,
            certificateLimits: certificateLimits,
            limits: limits
        )
    }

    static func decodeIdentityCertificate(
        from reader: inout WalletWireReader,
        certificateLimits: CertificateLimits,
        limits: WalletWireLimits
    ) throws -> WalletIdentityCertificate {
        let certificateBytes = try reader.readVarBytes(
            maximum: certificateLimits.maximumBinaryByteCount,
            kind: "identity certificate"
        )
        let certificate = try Certificate(binary: certificateBytes, limits: certificateLimits)
        try walletWireRequireSignedCertificate(certificate)
        let info = try WalletIdentityCertifier(
            name: reader.readString(
                maximum: walletWireMaximumText(limits),
                kind: "certifier name"
            ),
            iconURL: reader.readString(
                maximum: walletWireMaximumText(limits),
                kind: "certifier icon URL"
            ),
            description: reader.readString(
                maximum: walletWireMaximumText(limits),
                kind: "certifier description"
            ),
            trust: reader.readByte(),
            limits: limits.abiLimits
        )
        let keyring = try walletWireReadKeyring(
            from: &reader,
            kind: "public keyring",
            certificateLimits: certificateLimits,
            limits: limits
        )
        let fields = try walletWireReadTextMap(
            from: &reader,
            kind: "decrypted fields",
            certificateLimits: certificateLimits,
            limits: limits
        )
        return try WalletIdentityCertificate(
            certificate: certificate,
            certifierInfo: info,
            publiclyRevealedKeyring: keyring,
            decryptedFields: fields,
            limits: limits.abiLimits
        )
    }
}

private func walletWireWriteLinkageBytes(
    _ value: [UInt8],
    kind: String,
    to writer: inout WalletWireWriter,
    limits: WalletWireLimits
) throws {
    guard value.count <= limits.abiLimits.maximumBytePayloadCount else {
        throw WalletWireError.byteLimitExceeded(
            kind: kind,
            actual: value.count,
            maximum: limits.abiLimits.maximumBytePayloadCount
        )
    }
    try writer.writeVarBytes(value)
}

private func walletWireRequireSignedCertificate(_ certificate: Certificate) throws {
    guard !certificate.type.bytes.allSatisfy({ $0 == 0 }) else {
        throw WalletWireError.nonRoundTrippableValue(kind: "zero certificate type")
    }
    guard let signature = certificate.signature else {
        throw WalletWireError.nonRoundTrippableValue(kind: "unsigned certificate")
    }
    try walletWireRequireLowSSignature(signature)
}

private func walletWireRemainingCapacity(
    in writer: WalletWireWriter,
    maximum: Int
) -> Int {
    max(0, maximum - writer.bytes.count)
}

private func walletWireMaximumVarBytesPayload(in capacity: Int) -> Int {
    guard capacity > 0 else { return 0 }
    var maximum = min(252, capacity - 1)
    if capacity >= 256 {
        maximum = max(maximum, min(65_535, capacity - 3))
    }
    if capacity >= 65_541 {
        maximum = max(maximum, min(Int(UInt32.max), capacity - 5))
    }
    if capacity >= 9 {
        maximum = max(maximum, capacity - 9)
    }
    return maximum
}

private func walletWireNestedCertificateLimits(
    _ source: CertificateLimits,
    maximumBinaryByteCount: Int
) throws -> CertificateLimits {
    try CertificateLimits(
        maximumFieldCount: source.maximumFieldCount,
        maximumFieldNameUTF8ByteCount: source.maximumFieldNameUTF8ByteCount,
        maximumFieldPlaintextByteCount: source.maximumFieldPlaintextByteCount,
        maximumFieldCiphertextByteCount: source.maximumFieldCiphertextByteCount,
        maximumKeyringCiphertextByteCount: source.maximumKeyringCiphertextByteCount,
        maximumBinaryByteCount: min(
            source.maximumBinaryByteCount,
            maximumBinaryByteCount
        ),
        maximumJSONByteCount: source.maximumJSONByteCount
    )
}

/// The list-result verifier is a public key hex string in the ABI (as in JSON).
/// On the wire @bsv/sdk writes its 33 decoded bytes, or length 0 when absent.
func walletWireWriteCertificateVerifier(
    _ verifier: [UInt8],
    to writer: inout WalletWireWriter
) throws {
    guard !verifier.isEmpty else {
        writer.writeCompactSize(0)
        return
    }
    guard let text = String(bytes: verifier, encoding: .utf8),
          let key = try? decodeWalletJSONPublicKey(text) else {
        throw WalletWireResultRejection(
            message: "Invalid listCertificates verifier: expected a compressed public key in hex"
        )
    }
    try writer.writeVarBytes(key.compressedBytes)
}

func walletWireReadCertificateVerifier(from reader: inout WalletWireReader) throws -> [UInt8] {
    let length = try reader.readCompactSize()
    if length == 0 { return [] }
    guard length == 33 else {
        throw WalletWireResultRejection(
            message: "Invalid listCertificates verifier length: expected 33 bytes, received \(length)"
        )
    }
    let bytes = try reader.readBytes(count: 33)
    do {
        let key = try PublicKey(bytes)
        guard key.compressedBytes == bytes else { throw WalletWireError.invalidPublicKey }
    } catch {
        throw WalletWireError.invalidPublicKey
    }
    return Array(Hex.encode(bytes).utf8)
}

/// The page size a certificate list or discovery request asks for (10 when it gives none).
func walletWireRequestedPageLimit(_ request: WalletWireCertificateRequest?) -> Int? {
    switch request {
    case .listCertificates(let value)?: Int(value.pagination.effectiveLimit)
    case .discoverByIdentityKey(let value)?: Int(value.pagination.effectiveLimit)
    case .discoverByAttributes(let value)?: Int(value.pagination.effectiveLimit)
    default: nil
    }
}
