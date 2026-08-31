import BSVCore
import BSVKeys
import BSVTransaction

extension WalletBRC100JSONCodec {
    func decodeCertificateRequest(call: WalletCall, bytes: [UInt8]) throws -> WalletWireCertificateRequest {
        switch call {
        case .revealCounterpartyKeyLinkage:
            .revealCounterpartyKeyLinkage(try decode(RevealCounterpartyRequestDTO.self, bytes).model(self))
        case .revealSpecificKeyLinkage:
            .revealSpecificKeyLinkage(try decode(RevealSpecificRequestDTO.self, bytes).model(self))
        case .acquireCertificate:
            .acquireCertificate(try decode(AcquireCertificateDTO.self, bytes).model(self))
        case .listCertificates:
            .listCertificates(try decode(ListCertificatesDTO.self, bytes).model(self))
        case .proveCertificate:
            .proveCertificate(try decode(ProveCertificateDTO.self, bytes).model(self))
        case .relinquishCertificate:
            .relinquishCertificate(try decode(RelinquishCertificateDTO.self, bytes).model(self))
        case .discoverByIdentityKey:
            .discoverByIdentityKey(try decode(DiscoverIdentityDTO.self, bytes).model(self))
        case .discoverByAttributes:
            .discoverByAttributes(try decode(DiscoverAttributesDTO.self, bytes).model(self))
        default: throw WalletJSONCodecError.requestCallMismatch(expected: .acquireCertificate, actual: call)
        }
    }

    func encodeCertificateRequest(_ request: WalletWireCertificateRequest) throws -> [UInt8] {
        switch request {
        case .revealCounterpartyKeyLinkage(let value): try encode(RevealCounterpartyRequestDTO(value))
        case .revealSpecificKeyLinkage(let value): try encode(RevealSpecificRequestDTO(value))
        case .acquireCertificate(let value): try encode(AcquireCertificateDTO(value))
        case .listCertificates(let value): try encode(ListCertificatesDTO(value))
        case .proveCertificate(let value): try encode(try ProveCertificateDTO(value))
        case .relinquishCertificate(let value): try encode(RelinquishCertificateDTO(value))
        case .discoverByIdentityKey(let value): try encode(DiscoverIdentityDTO(value))
        case .discoverByAttributes(let value): try encode(DiscoverAttributesDTO(value))
        }
    }

    func decodeCertificateResult(call: WalletCall, bytes: [UInt8]) throws -> WalletWireCertificateResult {
        switch call {
        case .revealCounterpartyKeyLinkage:
            .revealCounterpartyKeyLinkage(try decode(RevealCounterpartyResultDTO.self, bytes).model(self))
        case .revealSpecificKeyLinkage:
            .revealSpecificKeyLinkage(try decode(RevealSpecificResultDTO.self, bytes).model(self))
        case .acquireCertificate:
            .acquireCertificate(try decode(CertificateDTO.self, bytes).model(self))
        case .listCertificates:
            .listCertificates(try decode(ListCertificatesResultDTO.self, bytes).model(self))
        case .proveCertificate:
            .proveCertificate(try decode(ProveCertificateResultDTO.self, bytes).model(self))
        case .relinquishCertificate:
            .relinquishCertificate(.init(relinquished: try decode(CertificateRelinquishedDTO.self, bytes).relinquished))
        case .discoverByIdentityKey:
            .discoverByIdentityKey(try decode(DiscoveryResultDTO.self, bytes).model(self))
        case .discoverByAttributes:
            .discoverByAttributes(try decode(DiscoveryResultDTO.self, bytes).model(self))
        default: throw WalletJSONCodecError.resultCallMismatch(expected: .acquireCertificate, actual: call)
        }
    }

    func encodeCertificateResult(_ result: WalletWireCertificateResult) throws -> [UInt8] {
        switch result {
        case .revealCounterpartyKeyLinkage(let value): try encode(RevealCounterpartyResultDTO(value))
        case .revealSpecificKeyLinkage(let value): try encode(RevealSpecificResultDTO(value))
        case .acquireCertificate(let value): try encode(try CertificateDTO(value))
        case .listCertificates(let value): try encode(try ListCertificatesResultDTO(value))
        case .proveCertificate(let value): try encode(ProveCertificateResultDTO(value))
        case .relinquishCertificate(let value): try encode(CertificateRelinquishedDTO(relinquished: value.relinquished))
        case .discoverByIdentityKey(let value), .discoverByAttributes(let value): try encode(try DiscoveryResultDTO(value))
        }
    }
}

private struct PrivilegeDTO: Codable {
    let privileged: Bool?
    let privilegedReason: String?
    init(_ value: WalletPrivilege) { privileged = value.privileged; privilegedReason = value.privilegedReason }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletPrivilege { try .init(privileged: privileged, privilegedReason: privilegedReason, limits: codec.abiLimits) }
}

private struct RevealCounterpartyRequestDTO: Codable {
    let counterparty: String; let verifier: String; let privileged: Bool?; let privilegedReason: String?
    init(_ value: WalletRevealCounterpartyKeyLinkageRequest) { counterparty = Hex.encode(value.counterparty.compressedBytes); verifier = Hex.encode(value.verifier.compressedBytes); privileged = value.privilege.privileged; privilegedReason = value.privilege.privilegedReason }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletRevealCounterpartyKeyLinkageRequest { .init(counterparty: try decodeWalletJSONPublicKey(counterparty), verifier: try decodeWalletJSONPublicKey(verifier), privilege: try .init(privileged: privileged, privilegedReason: privilegedReason, limits: codec.abiLimits)) }
}
private struct RevealSpecificRequestDTO: Codable {
    let counterparty: WalletCounterparty; let verifier: String; let protocolID: WalletProtocolID; let keyID: WalletKeyID
    let privileged: Bool?; let privilegedReason: String?
    init(_ value: WalletRevealSpecificKeyLinkageRequest) { counterparty = value.counterparty; verifier = Hex.encode(value.verifier.compressedBytes); protocolID = value.protocolID; keyID = value.keyID; privileged = value.privilege.privileged; privilegedReason = value.privilege.privilegedReason }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletRevealSpecificKeyLinkageRequest { try .init(counterparty: counterparty, verifier: decodeWalletJSONPublicKey(verifier), protocolID: protocolID, keyID: keyID, privilege: .init(privileged: privileged, privilegedReason: privilegedReason, limits: codec.abiLimits)) }
}
private struct RevealCounterpartyResultDTO: Codable {
    let prover: String; let verifier: String; let counterparty: String; let revelationTime: String
    let encryptedLinkage: [UInt8]; let encryptedLinkageProof: [UInt8]
    init(_ value: WalletRevealCounterpartyKeyLinkageResult) { prover = Hex.encode(value.prover.compressedBytes); verifier = Hex.encode(value.verifier.compressedBytes); counterparty = Hex.encode(value.counterparty.compressedBytes); revelationTime = value.revelationTime; encryptedLinkage = value.encryptedLinkage.bytes; encryptedLinkageProof = value.encryptedLinkageProof.bytes }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletRevealCounterpartyKeyLinkageResult { try .init(prover: decodeWalletJSONPublicKey(prover), counterparty: decodeWalletJSONPublicKey(counterparty), verifier: decodeWalletJSONPublicKey(verifier), revelationTime: revelationTime, encryptedLinkage: .init(encryptedLinkage, limits: codec.abiLimits), encryptedLinkageProof: .init(encryptedLinkageProof, limits: codec.abiLimits), limits: codec.abiLimits) }
}
private struct RevealSpecificResultDTO: Codable {
    let prover: String; let verifier: String; let counterparty: String; let protocolID: WalletProtocolID; let keyID: WalletKeyID
    let encryptedLinkage: [UInt8]; let encryptedLinkageProof: [UInt8]; let proofType: UInt8
    init(_ value: WalletRevealSpecificKeyLinkageResult) { prover = Hex.encode(value.prover.compressedBytes); verifier = Hex.encode(value.verifier.compressedBytes); counterparty = Hex.encode(value.counterparty.compressedBytes); protocolID = value.protocolID; keyID = value.keyID; encryptedLinkage = value.encryptedLinkage.bytes; encryptedLinkageProof = value.encryptedLinkageProof.bytes; proofType = value.proofType }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletRevealSpecificKeyLinkageResult { try .init(encryptedLinkage: .init(encryptedLinkage, limits: codec.abiLimits), encryptedLinkageProof: .init(encryptedLinkageProof, limits: codec.abiLimits), prover: decodeWalletJSONPublicKey(prover), verifier: decodeWalletJSONPublicKey(verifier), counterparty: decodeWalletJSONPublicKey(counterparty), protocolID: protocolID, keyID: keyID, proofType: proofType, limits: codec.abiLimits) }
}

private struct AcquireCertificateDTO: Codable {
    let type: CertificateTypeID; let certifier: String; let acquisitionProtocol: WalletCertificateAcquisitionProtocol
    let fields: [String: String]; let serialNumber: CertificateSerialNumber?; let revocationOutpoint: String?
    let signature: String?; let certifierUrl: String?; let keyringRevealer: String?
    let keyringForSubject: [String: CertificateCiphertext]?; let privileged: Bool?; let privilegedReason: String?
    init(_ value: WalletAcquireCertificateRequest) {
        type = value.type; certifier = Hex.encode(value.certifier.compressedBytes)
        acquisitionProtocol = value.acquisition.protocol
        fields = Dictionary(uniqueKeysWithValues: value.fields.map { ($0.key.value, $0.value) })
        switch value.acquisition {
        case .direct(let direct):
            serialNumber = direct.serialNumber; revocationOutpoint = direct.revocationOutpoint.description
            signature = Hex.encode(direct.signature.derBytes); certifierUrl = nil
            switch direct.keyringRevealer { case .certifier: keyringRevealer = nil; case .publicKey(let key): keyringRevealer = Hex.encode(key.compressedBytes) }
            keyringForSubject = Dictionary(uniqueKeysWithValues: direct.keyringForSubject.map { ($0.key.value, $0.value) })
        case .issuance(let issuance):
            serialNumber = nil; revocationOutpoint = nil; signature = nil; certifierUrl = issuance.certifierURL
            keyringRevealer = nil; keyringForSubject = nil
        }
        privileged = value.privilege.privileged; privilegedReason = value.privilege.privilegedReason
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletAcquireCertificateRequest {
        let namedFields = try dictionaryFieldNames(fields, limits: codec.certificateLimits)
        let acquisition: WalletCertificateAcquisition
        switch acquisitionProtocol {
        case .direct:
            guard let serialNumber, let revocationOutpoint, let signature, let keyringForSubject else { throw WalletJSONCodecError.invalidJSON }
            let signatureBytes = try decodeCanonicalHex(signature, maximum: 72)
            let parsedSignature = try ECDSASignature(derBytes: signatureBytes)
            guard parsedSignature.derBytes == signatureBytes else { throw WalletJSONCodecError.invalidJSON }
            let revealer: WalletKeyringRevealer = try keyringRevealer.map { .publicKey(try decodeWalletJSONPublicKey($0)) } ?? .certifier
            let keyring = try dictionaryCiphertexts(keyringForSubject, limits: codec.certificateLimits)
            acquisition = .direct(try .init(serialNumber: serialNumber, revocationOutpoint: .init(revocationOutpoint), signature: parsedSignature, keyringRevealer: revealer, keyringForSubject: keyring, limits: codec.abiLimits))
        case .issuance:
            guard let certifierUrl else { throw WalletJSONCodecError.invalidJSON }
            acquisition = .issuance(try .init(certifierURL: certifierUrl, limits: codec.abiLimits))
        }
        return try .init(type: type, certifier: decodeWalletJSONPublicKey(certifier), fields: namedFields, acquisition: acquisition, privilege: .init(privileged: privileged, privilegedReason: privilegedReason, limits: codec.abiLimits), limits: codec.abiLimits)
    }
}

private struct CertificateDTO: Codable {
    let type: CertificateTypeID; let subject: String; let serialNumber: CertificateSerialNumber; let certifier: String
    let revocationOutpoint: String; let signature: String?; let fields: [String: String]
    init(_ value: Certificate) throws {
        type = value.type; subject = Hex.encode(value.subject.compressedBytes); serialNumber = value.serialNumber
        certifier = Hex.encode(value.certifier.compressedBytes); revocationOutpoint = value.revocationOutpoint.description
        signature = value.signature.map { Hex.encode($0.derBytes) }
        fields = Dictionary(uniqueKeysWithValues: value.fields.map { ($0.key.value, $0.value.base64) })
    }
    init(type: CertificateTypeID, subject: String, serialNumber: CertificateSerialNumber, certifier: String, revocationOutpoint: String, signature: String?, fields: [String: String]) {
        self.type = type; self.subject = subject; self.serialNumber = serialNumber
        self.certifier = certifier; self.revocationOutpoint = revocationOutpoint
        self.signature = signature; self.fields = fields
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> Certificate {
        let signatureValue: ECDSASignature?
        if let signature { let bytes = try decodeCanonicalHex(signature, maximum: 72); let parsed = try ECDSASignature(derBytes: bytes); guard parsed.derBytes == bytes else { throw WalletJSONCodecError.invalidJSON }; signatureValue = parsed } else { signatureValue = nil }
        let fieldValues = try dictionaryBase64Ciphertexts(fields, limits: codec.certificateLimits)
        return try .init(type: type, serialNumber: serialNumber, subject: decodeWalletJSONPublicKey(subject), certifier: decodeWalletJSONPublicKey(certifier), revocationOutpoint: .init(revocationOutpoint), fields: fieldValues, signature: signatureValue, limits: codec.certificateLimits)
    }
}

private struct ListCertificatesDTO: Codable {
    let certifiers: [String]; let types: [CertificateTypeID]; let limit: UInt32?; let offset: UInt32?
    let privileged: Bool?; let privilegedReason: String?
    init(_ value: WalletListCertificatesRequest) { certifiers = value.certifiers.map { Hex.encode($0.compressedBytes) }; types = value.types; limit = value.pagination.limit; offset = value.pagination.offset; privileged = value.privilege.privileged; privilegedReason = value.privilege.privilegedReason }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletListCertificatesRequest { try .init(certifiers: certifiers.map(decodeWalletJSONPublicKey), types: types, pagination: .init(limit: limit, offset: offset), privilege: .init(privileged: privileged, privilegedReason: privilegedReason, limits: codec.abiLimits), limits: codec.abiLimits) }
}
private struct CertificateResultDTO: Codable {
    let type: CertificateTypeID; let subject: String; let serialNumber: CertificateSerialNumber; let certifier: String
    let revocationOutpoint: String; let signature: String?; let fields: [String: String]
    let keyring: [String: CertificateCiphertext]?; let verifier: String?
    init(_ value: WalletCertificateResult) throws { let certificate = try CertificateDTO(value.certificate); type = certificate.type; subject = certificate.subject; serialNumber = certificate.serialNumber; certifier = certificate.certifier; revocationOutpoint = certificate.revocationOutpoint; signature = certificate.signature; fields = certificate.fields; keyring = value.keyring.map { Dictionary(uniqueKeysWithValues: $0.map { ($0.key.value, $0.value) }) }; if value.verifier.isEmpty { verifier = nil } else { guard let text = String(bytes: value.verifier, encoding: .utf8) else { throw WalletJSONCodecError.invalidJSON }; verifier = text } }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletCertificateResult { try .init(certificate: CertificateDTO(type: type, subject: subject, serialNumber: serialNumber, certifier: certifier, revocationOutpoint: revocationOutpoint, signature: signature, fields: fields).model(codec), keyring: try keyring.map { try dictionaryCiphertexts($0, limits: codec.certificateLimits) }, verifier: verifier.map { Array($0.utf8) } ?? [], limits: codec.abiLimits) }
}
private struct ListCertificatesResultDTO: Codable {
    let totalCertificates: UInt32; let certificates: [CertificateResultDTO]
    init(_ value: WalletListCertificatesResult) throws { totalCertificates = value.totalCertificates; certificates = try value.certificates.map(CertificateResultDTO.init) }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletListCertificatesResult { try .init(totalCertificates: totalCertificates, certificates: try certificates.map { try $0.model(codec) }, limits: codec.abiLimits) }
}

private struct ProveCertificateDTO: Codable {
    let certificate: CertificateDTO; let fieldsToReveal: [CertificateFieldName]; let verifier: String
    let privileged: Bool?; let privilegedReason: String?
    init(_ value: WalletProveCertificateRequest) throws { certificate = try CertificateDTO(value.certificate); fieldsToReveal = value.fieldsToReveal; verifier = Hex.encode(value.verifier.compressedBytes); privileged = value.privilege.privileged; privilegedReason = value.privilege.privilegedReason }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletProveCertificateRequest { try .init(certificate: certificate.model(codec), fieldsToReveal: fieldsToReveal, verifier: decodeWalletJSONPublicKey(verifier), privilege: .init(privileged: privileged, privilegedReason: privilegedReason, limits: codec.abiLimits), limits: codec.abiLimits) }
}
private struct ProveCertificateResultDTO: Codable {
    let keyringForVerifier: [String: CertificateCiphertext]
    init(_ value: WalletProveCertificateResult) { keyringForVerifier = Dictionary(uniqueKeysWithValues: value.keyringForVerifier.map { ($0.key.value, $0.value) }) }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletProveCertificateResult { try .init(keyringForVerifier: dictionaryCiphertexts(keyringForVerifier, limits: codec.certificateLimits), limits: codec.abiLimits) }
}
private struct RelinquishCertificateDTO: Codable {
    let type: CertificateTypeID; let serialNumber: CertificateSerialNumber; let certifier: String
    init(_ value: WalletRelinquishCertificateRequest) { type = value.type; serialNumber = value.serialNumber; certifier = Hex.encode(value.certifier.compressedBytes) }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletRelinquishCertificateRequest { .init(type: type, serialNumber: serialNumber, certifier: try decodeWalletJSONPublicKey(certifier)) }
}
private struct CertificateRelinquishedDTO: Codable { let relinquished: Bool }

private struct IdentityCertifierDTO: Codable {
    let name: String; let iconUrl: String; let description: String; let trust: UInt8
    init(_ value: WalletIdentityCertifier) { name = value.name; iconUrl = value.iconURL; description = value.description; trust = value.trust }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletIdentityCertifier { try .init(name: name, iconURL: iconUrl, description: description, trust: trust, limits: codec.abiLimits) }
}
private struct IdentityCertificateDTO: Codable {
    let type: CertificateTypeID; let subject: String; let serialNumber: CertificateSerialNumber; let certifier: String
    let revocationOutpoint: String; let signature: String?; let fields: [String: String]
    let certifierInfo: IdentityCertifierDTO; let publiclyRevealedKeyring: [String: CertificateCiphertext]
    let decryptedFields: [String: String]
    init(_ value: WalletIdentityCertificate) throws { let certificate = try CertificateDTO(value.certificate); type = certificate.type; subject = certificate.subject; serialNumber = certificate.serialNumber; certifier = certificate.certifier; revocationOutpoint = certificate.revocationOutpoint; signature = certificate.signature; fields = certificate.fields; certifierInfo = .init(value.certifierInfo); publiclyRevealedKeyring = Dictionary(uniqueKeysWithValues: value.publiclyRevealedKeyring.map { ($0.key.value, $0.value) }); decryptedFields = Dictionary(uniqueKeysWithValues: value.decryptedFields.map { ($0.key.value, $0.value) }) }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletIdentityCertificate { try .init(certificate: CertificateDTO(type: type, subject: subject, serialNumber: serialNumber, certifier: certifier, revocationOutpoint: revocationOutpoint, signature: signature, fields: fields).model(codec), certifierInfo: certifierInfo.model(codec), publiclyRevealedKeyring: dictionaryCiphertexts(publiclyRevealedKeyring, limits: codec.certificateLimits), decryptedFields: dictionaryFieldNames(decryptedFields, limits: codec.certificateLimits), limits: codec.abiLimits) }
}
private struct DiscoverIdentityDTO: Codable {
    let identityKey: String; let limit: UInt32?; let offset: UInt32?; let seekPermission: Bool?
    init(_ value: WalletDiscoverByIdentityKeyRequest) { identityKey = Hex.encode(value.identityKey.compressedBytes); limit = value.pagination.limit; offset = value.pagination.offset; seekPermission = value.seekPermission }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletDiscoverByIdentityKeyRequest { .init(identityKey: try decodeWalletJSONPublicKey(identityKey), pagination: try .init(limit: limit, offset: offset), seekPermission: seekPermission) }
}
private struct DiscoverAttributesDTO: Codable {
    let attributes: [String: String]; let limit: UInt32?; let offset: UInt32?; let seekPermission: Bool?
    init(_ value: WalletDiscoverByAttributesRequest) { attributes = Dictionary(uniqueKeysWithValues: value.attributes.map { ($0.key.value, $0.value) }); limit = value.pagination.limit; offset = value.pagination.offset; seekPermission = value.seekPermission }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletDiscoverByAttributesRequest { try .init(attributes: dictionaryFieldNames(attributes, limits: codec.certificateLimits), pagination: .init(limit: limit, offset: offset), seekPermission: seekPermission, limits: codec.abiLimits) }
}
private struct DiscoveryResultDTO: Codable {
    let totalCertificates: UInt32; let certificates: [IdentityCertificateDTO]
    init(_ value: WalletDiscoverCertificatesResult) throws { totalCertificates = value.totalCertificates; certificates = try value.certificates.map(IdentityCertificateDTO.init) }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletDiscoverCertificatesResult { try .init(totalCertificates: totalCertificates, certificates: try certificates.map { try $0.model(codec) }, limits: codec.abiLimits) }
}

private func dictionaryFieldNames<T>(_ values: [String: T], limits: CertificateLimits) throws -> [CertificateFieldName: T] {
    var result: [CertificateFieldName: T] = [:]
    for (key, value) in values { result[try CertificateFieldName(key, limits: limits)] = value }
    return result
}
private func dictionaryCiphertexts(_ values: [String: CertificateCiphertext], limits: CertificateLimits) throws -> [CertificateFieldName: CertificateCiphertext] { try dictionaryFieldNames(values, limits: limits) }
private func dictionaryBase64Ciphertexts(_ values: [String: String], limits: CertificateLimits) throws -> [CertificateFieldName: CertificateCiphertext] {
    var result: [CertificateFieldName: CertificateCiphertext] = [:]
    for (key, value) in values {
        result[try CertificateFieldName(key, limits: limits)] = try CertificateCiphertext(
            base64: value,
            maximumByteCount: limits.maximumFieldCiphertextByteCount
        )
    }
    return result
}
