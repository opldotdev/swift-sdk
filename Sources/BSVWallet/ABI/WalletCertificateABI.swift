import BSVKeys
import BSVTransaction

public struct WalletRevealCounterpartyKeyLinkageRequest: Equatable, Sendable {
    public let counterparty: PublicKey
    public let verifier: PublicKey
    public let privilege: WalletPrivilege
    public init(
        counterparty: PublicKey,
        verifier: PublicKey,
        privilege: WalletPrivilege = .standard
    ) {
        self.counterparty = counterparty
        self.verifier = verifier
        self.privilege = privilege
    }
}

public struct WalletLinkageCiphertext:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let bytes: [UInt8]
    public init(_ bytes: [UInt8], limits: WalletABILimits = .standard) throws {
        try walletABIRequireBytes(bytes.count, kind: "linkage ciphertext", limits: limits)
        self.bytes = bytes
    }
    public var description: String { "<redacted linkage ciphertext>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletRevealCounterpartyKeyLinkageResult:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let prover: PublicKey
    public let counterparty: PublicKey
    public let verifier: PublicKey
    public let revelationTime: String
    public let encryptedLinkage: WalletLinkageCiphertext
    public let encryptedLinkageProof: WalletLinkageCiphertext
    public init(
        prover: PublicKey,
        counterparty: PublicKey,
        verifier: PublicKey,
        revelationTime: String,
        encryptedLinkage: WalletLinkageCiphertext,
        encryptedLinkageProof: WalletLinkageCiphertext,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireText(revelationTime, kind: "revelation time", limits: limits)
        try walletABIRequireAggregate(
            [encryptedLinkage.bytes.count, encryptedLinkageProof.bytes.count], limits: limits
        )
        self.prover = prover
        self.counterparty = counterparty
        self.verifier = verifier
        self.revelationTime = revelationTime
        self.encryptedLinkage = encryptedLinkage
        self.encryptedLinkageProof = encryptedLinkageProof
    }
    public var description: String { "<redacted counterparty key-linkage result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletRevealSpecificKeyLinkageRequest: Equatable, Sendable {
    public let counterparty: WalletCounterparty
    public let verifier: PublicKey
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let privilege: WalletPrivilege
    public init(
        counterparty: WalletCounterparty,
        verifier: PublicKey,
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        privilege: WalletPrivilege = .standard
    ) throws {
        guard case .publicKey = counterparty else {
            throw WalletABIError.invalidFieldRelation(
                "specific key linkage requires a concrete counterparty public key"
            )
        }
        self.counterparty = counterparty
        self.verifier = verifier
        self.protocolID = protocolID
        self.keyID = keyID
        self.privilege = privilege
    }
}

public struct WalletRevealSpecificKeyLinkageResult:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let encryptedLinkage: WalletLinkageCiphertext
    public let encryptedLinkageProof: WalletLinkageCiphertext
    public let prover: PublicKey
    public let verifier: PublicKey
    public let counterparty: PublicKey
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let proofType: UInt8
    public init(
        encryptedLinkage: WalletLinkageCiphertext,
        encryptedLinkageProof: WalletLinkageCiphertext,
        prover: PublicKey,
        verifier: PublicKey,
        counterparty: PublicKey,
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        proofType: UInt8,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireAggregate(
            [encryptedLinkage.bytes.count, encryptedLinkageProof.bytes.count], limits: limits
        )
        self.encryptedLinkage = encryptedLinkage
        self.encryptedLinkageProof = encryptedLinkageProof
        self.prover = prover
        self.verifier = verifier
        self.counterparty = counterparty
        self.protocolID = protocolID
        self.keyID = keyID
        self.proofType = proofType
    }
    public var description: String { "<redacted specific key-linkage result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public enum WalletCertificateAcquisitionProtocol: String, CaseIterable, Codable, Sendable {
    case direct, issuance
    public init(_ text: String) throws {
        guard let value = Self(rawValue: text) else {
            throw WalletABIError.invalidEnumText(
                type: "WalletCertificateAcquisitionProtocol", value: text
            )
        }
        self = value
    }
}

public enum WalletKeyringRevealer: Equatable, Sendable {
    case certifier
    case publicKey(PublicKey)

    public init(certifier: Bool, publicKey: PublicKey?) throws {
        switch (certifier, publicKey) {
        case (true, nil): self = .certifier
        case (false, .some(let key)): self = .publicKey(key)
        default:
            throw WalletABIError.conflictingUnionMembers(
                "keyring revealer must be certifier or one public key"
            )
        }
    }
}

public struct WalletDirectCertificateAcquisition:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let serialNumber: CertificateSerialNumber
    public let revocationOutpoint: Outpoint
    public let signature: ECDSASignature
    public let keyringRevealer: WalletKeyringRevealer
    public let keyringForSubject: [CertificateFieldName: CertificateCiphertext]
    public init(
        serialNumber: CertificateSerialNumber,
        revocationOutpoint: Outpoint,
        signature: ECDSASignature,
        keyringRevealer: WalletKeyringRevealer,
        keyringForSubject: [CertificateFieldName: CertificateCiphertext],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(
            keyringForSubject.count,
            kind: "subject keyring",
            maximum: limits.maximumCollectionCount
        )
        try walletABIRequireAggregate(
            keyringForSubject.map { $0.key.value.utf8.count + $0.value.bytes.count },
            limits: limits
        )
        self.serialNumber = serialNumber
        self.revocationOutpoint = revocationOutpoint
        self.signature = signature
        self.keyringRevealer = keyringRevealer
        self.keyringForSubject = keyringForSubject
    }
    public var description: String { "<redacted direct certificate acquisition>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletIssuanceCertificateAcquisition: Equatable, Sendable {
    public let certifierURL: String
    public init(certifierURL: String, limits: WalletABILimits = .standard) throws {
        try walletABIRequireText(certifierURL, kind: "certifier URL", limits: limits)
        guard !certifierURL.isEmpty else {
            throw WalletABIError.invalidFieldRelation("issuance requires a certifier URL")
        }
        self.certifierURL = certifierURL
    }
}

public enum WalletCertificateAcquisition: Equatable, Sendable {
    case direct(WalletDirectCertificateAcquisition)
    case issuance(WalletIssuanceCertificateAcquisition)
    public var `protocol`: WalletCertificateAcquisitionProtocol {
        switch self {
        case .direct: .direct
        case .issuance: .issuance
        }
    }
}

public struct WalletAcquireCertificateRequest:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let type: CertificateTypeID
    public let certifier: PublicKey
    public let fields: [CertificateFieldName: String]
    public let acquisition: WalletCertificateAcquisition
    public let privilege: WalletPrivilege
    public init(
        type: CertificateTypeID,
        certifier: PublicKey,
        fields: [CertificateFieldName: String],
        acquisition: WalletCertificateAcquisition,
        privilege: WalletPrivilege = .standard,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIValidateTextMap(fields, kind: "certificate fields", limits: limits)
        self.type = type
        self.certifier = certifier
        self.fields = fields
        self.acquisition = acquisition
        self.privilege = privilege
    }
    public var description: String { "<redacted acquire-certificate request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletListCertificatesRequest: Equatable, Sendable {
    public let certifiers: [PublicKey]
    public let types: [CertificateTypeID]
    public let pagination: WalletPagination
    public let privilege: WalletPrivilege
    public init(
        certifiers: [PublicKey],
        types: [CertificateTypeID],
        pagination: WalletPagination = .standard,
        privilege: WalletPrivilege = .standard,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(certifiers.count, kind: "certifiers", maximum: limits.maximumCollectionCount)
        try walletABIRequireCount(types.count, kind: "certificate types", maximum: limits.maximumCollectionCount)
        self.certifiers = certifiers
        self.types = types
        self.pagination = pagination
        self.privilege = privilege
    }
}

public struct WalletCertificateResult:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let certificate: Certificate
    /// `nil` means that the wallet did not return a keyring. A present keyring
    /// must contain at least one entry because the pinned Go reader cannot
    /// preserve the distinction between an empty map and an absent map.
    public let keyring: [CertificateFieldName: CertificateCiphertext]?
    public let verifier: [UInt8]
    public init(
        certificate: Certificate,
        keyring: [CertificateFieldName: CertificateCiphertext]?,
        verifier: [UInt8],
        limits: WalletABILimits = .standard
    ) throws {
        if let keyring {
            guard !keyring.isEmpty else {
                throw WalletABIError.invalidFieldRelation(
                    "a present certificate keyring must not be empty"
                )
            }
            try walletABIRequireCount(
                keyring.count,
                kind: "certificate keyring",
                maximum: limits.maximumCollectionCount
            )
        }
        try walletABIRequireBytes(verifier.count, kind: "certificate verifier", limits: limits)
        try walletABIRequireAggregate(
            [verifier.count] + (keyring?.map {
                $0.key.value.utf8.count + $0.value.bytes.count
            } ?? []),
            limits: limits
        )
        self.certificate = certificate
        self.keyring = keyring
        self.verifier = verifier
    }
    public var description: String { "<redacted wallet certificate result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletListCertificatesResult:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let totalCertificates: UInt32
    public let certificates: [WalletCertificateResult]
    public init(
        totalCertificates: UInt32,
        certificates: [WalletCertificateResult],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(certificates.count, kind: "certificates", maximum: limits.maximumCollectionCount)
        self.totalCertificates = totalCertificates
        self.certificates = certificates
    }
    public var description: String { "<redacted wallet certificate list>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletProveCertificateRequest:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let certificate: Certificate
    public let fieldsToReveal: [CertificateFieldName]
    public let verifier: PublicKey
    public let privilege: WalletPrivilege
    public init(
        certificate: Certificate,
        fieldsToReveal: [CertificateFieldName],
        verifier: PublicKey,
        privilege: WalletPrivilege = .standard,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(
            fieldsToReveal.count, kind: "fields to reveal", maximum: limits.maximumCollectionCount
        )
        guard Set(fieldsToReveal).count == fieldsToReveal.count else {
            throw WalletABIError.invalidFieldRelation("fieldsToReveal contains duplicates")
        }
        guard fieldsToReveal.allSatisfy({ certificate.fields[$0] != nil }) else {
            throw WalletABIError.invalidFieldRelation("a requested field is absent from the certificate")
        }
        self.certificate = certificate
        self.fieldsToReveal = fieldsToReveal
        self.verifier = verifier
        self.privilege = privilege
    }
    public var description: String { "<redacted prove-certificate request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletProveCertificateResult:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let keyringForVerifier: [CertificateFieldName: CertificateCiphertext]
    public init(
        keyringForVerifier: [CertificateFieldName: CertificateCiphertext],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(
            keyringForVerifier.count,
            kind: "verifier keyring",
            maximum: limits.maximumCollectionCount
        )
        try walletABIRequireAggregate(
            keyringForVerifier.map { $0.key.value.utf8.count + $0.value.bytes.count }, limits: limits
        )
        self.keyringForVerifier = keyringForVerifier
    }
    public var description: String { "<redacted prove-certificate result>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletRelinquishCertificateRequest: Equatable, Sendable {
    public let type: CertificateTypeID
    public let serialNumber: CertificateSerialNumber
    public let certifier: PublicKey
    public init(type: CertificateTypeID, serialNumber: CertificateSerialNumber, certifier: PublicKey) {
        self.type = type
        self.serialNumber = serialNumber
        self.certifier = certifier
    }
}

public struct WalletRelinquishCertificateResult: Equatable, Sendable {
    public let relinquished: Bool
    public init(relinquished: Bool) { self.relinquished = relinquished }
}

public struct WalletIdentityCertifier: Equatable, Sendable {
    public let name: String
    public let iconURL: String
    public let description: String
    public let trust: UInt8
    public init(
        name: String,
        iconURL: String,
        description: String,
        trust: UInt8,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireText(name, kind: "certifier name", limits: limits)
        try walletABIRequireText(iconURL, kind: "certifier icon URL", limits: limits)
        try walletABIRequireText(description, kind: "certifier description", limits: limits)
        guard trust <= 10 else { throw WalletABIError.invalidFieldRelation("certifier trust exceeds 10") }
        self.name = name
        self.iconURL = iconURL
        self.description = description
        self.trust = trust
    }
}

public struct WalletIdentityCertificate:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let certificate: Certificate
    public let certifierInfo: WalletIdentityCertifier
    public let publiclyRevealedKeyring: [CertificateFieldName: CertificateCiphertext]
    public let decryptedFields: [CertificateFieldName: String]
    public init(
        certificate: Certificate,
        certifierInfo: WalletIdentityCertifier,
        publiclyRevealedKeyring: [CertificateFieldName: CertificateCiphertext],
        decryptedFields: [CertificateFieldName: String],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(
            publiclyRevealedKeyring.count,
            kind: "publicly revealed keyring",
            maximum: limits.maximumCollectionCount
        )
        try walletABIValidateTextMap(decryptedFields, kind: "decrypted fields", limits: limits)
        try walletABIRequireAggregate(
            publiclyRevealedKeyring.map { $0.key.value.utf8.count + $0.value.bytes.count }
                + decryptedFields.map { $0.key.value.utf8.count + $0.value.utf8.count },
            limits: limits
        )
        self.certificate = certificate
        self.certifierInfo = certifierInfo
        self.publiclyRevealedKeyring = publiclyRevealedKeyring
        self.decryptedFields = decryptedFields
    }
    public var description: String { "<redacted identity certificate>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletDiscoverByIdentityKeyRequest: Equatable, Sendable {
    public let identityKey: PublicKey
    public let pagination: WalletPagination
    public let seekPermission: Bool?
    public init(
        identityKey: PublicKey,
        pagination: WalletPagination = .standard,
        seekPermission: Bool? = nil
    ) {
        self.identityKey = identityKey
        self.pagination = pagination
        self.seekPermission = seekPermission
    }
}

public struct WalletDiscoverByAttributesRequest:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let attributes: [CertificateFieldName: String]
    public let pagination: WalletPagination
    public let seekPermission: Bool?
    public init(
        attributes: [CertificateFieldName: String],
        pagination: WalletPagination = .standard,
        seekPermission: Bool? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIValidateTextMap(attributes, kind: "attributes", limits: limits)
        self.attributes = attributes
        self.pagination = pagination
        self.seekPermission = seekPermission
    }
    public var description: String { "<redacted certificate attributes>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletDiscoverCertificatesResult:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let totalCertificates: UInt32
    public let certificates: [WalletIdentityCertificate]
    public init(
        totalCertificates: UInt32,
        certificates: [WalletIdentityCertificate],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(certificates.count, kind: "certificates", maximum: limits.maximumCollectionCount)
        self.totalCertificates = totalCertificates
        self.certificates = certificates
    }
    public var description: String { "<redacted discovered certificates>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

private func walletABIValidateTextMap(
    _ values: [CertificateFieldName: String],
    kind: String,
    limits: WalletABILimits
) throws {
    try walletABIRequireCount(values.count, kind: kind, maximum: limits.maximumCollectionCount)
    var counts: [Int] = []
    counts.reserveCapacity(values.count)
    for (name, value) in values {
        try walletABIRequireText(value, kind: kind, limits: limits)
        let (count, overflow) = name.value.utf8.count.addingReportingOverflow(value.utf8.count)
        guard !overflow else { throw WalletABIError.sizeOverflow }
        counts.append(count)
    }
    try walletABIRequireAggregate(counts, limits: limits)
}
