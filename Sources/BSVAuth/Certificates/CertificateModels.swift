import BSVKeys
import BSVTransaction
import BSVWallet

/// A signed core certificate plus the complete subject/certifier master keyring.
public struct MasterCertificate:
    Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let certificate: Certificate
    public let masterKeyring: CertificateKeyring

    public init(
        certificate: Certificate,
        masterKeyring: CertificateKeyring
    ) throws {
        guard certificate.signature != nil else { throw CertificateError.missingSignature }
        guard Set(certificate.fields.keys) == Set(masterKeyring.entries.keys) else {
            throw CertificateError.keyringMismatch
        }
        self.certificate = certificate
        self.masterKeyring = masterKeyring
    }

    public var description: String { "<redacted master certificate>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    public func binary(limits: CertificateLimits = .standard) throws -> [UInt8] {
        try CertificateWithKeyringBinary(
            certificate: certificate,
            keyring: masterKeyring
        ).binary(limits: limits)
    }

    public init(binary: [UInt8], limits: CertificateLimits = .standard) throws {
        let envelope = try CertificateWithKeyringBinary(binary: binary, limits: limits)
        try self.init(certificate: envelope.certificate, masterKeyring: envelope.keyring)
    }
}

/// A signed core certificate with only verifier-authorized revelation keys.
public struct VerifiableCertificate:
    Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let certificate: Certificate
    public let keyring: CertificateKeyring

    public init(certificate: Certificate, keyring: CertificateKeyring) throws {
        guard certificate.signature != nil else { throw CertificateError.missingSignature }
        guard Set(keyring.entries.keys).isSubset(of: Set(certificate.fields.keys)) else {
            throw CertificateError.keyringMismatch
        }
        self.certificate = certificate
        self.keyring = keyring
    }

    public var description: String { "<redacted verifiable certificate>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    public func binary(limits: CertificateLimits = .standard) throws -> [UInt8] {
        try CertificateWithKeyringBinary(
            certificate: certificate,
            keyring: keyring
        ).binary(limits: limits)
    }

    public init(binary: [UInt8], limits: CertificateLimits = .standard) throws {
        let envelope = try CertificateWithKeyringBinary(binary: binary, limits: limits)
        try self.init(certificate: envelope.certificate, keyring: envelope.keyring)
    }
}

/// Expectations checked before an acquired certificate is accepted.
public struct CertificateAcquisitionRequirements: Equatable, Sendable {
    public let type: CertificateTypeID?
    public let serialNumber: CertificateSerialNumber?
    public let certifier: PublicKey?
    public let revocationOutpoint: Outpoint?

    public init(
        type: CertificateTypeID? = nil,
        serialNumber: CertificateSerialNumber? = nil,
        certifier: PublicKey? = nil,
        revocationOutpoint: Outpoint? = nil
    ) {
        self.type = type
        self.serialNumber = serialNumber
        self.certifier = certifier
        self.revocationOutpoint = revocationOutpoint
    }
}

/// A fully authenticated acquisition result. No partial plaintext is returned.
public struct AcquiredCertificate:
    Equatable, Sendable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let masterCertificate: MasterCertificate
    public let plaintextFields: [CertificateFieldName: String]

    public var description: String { "<redacted acquired certificate>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}
