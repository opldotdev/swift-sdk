import BSVCore
import BSVCrypto
import BSVKeys
import BSVTransaction
import BSVWallet

/// Offline, bounded BRC-52 issuance, acquisition, and selective disclosure.
public enum CertificateEngine {
    /// Issues and signs a certificate directly for a subject.
    ///
    /// `.self` creates a self-signed certificate. `.anyone` is intentionally
    /// rejected rather than silently being treated as self, a stricter Swift
    /// deviation from the pinned Go helper's ambiguous fallback.
    public static func issue(
        type: CertificateTypeID,
        serialNumber suppliedSerialNumber: CertificateSerialNumber? = nil,
        subject: WalletCounterparty,
        plaintextFields: [CertificateFieldName: String],
        revocationOutpoint: Outpoint = disabledRevocationOutpoint,
        using certifierWallet: any CertificateWallet,
        limits: CertificateLimits = .standard,
        randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) async throws -> MasterCertificate {
        try validateFieldSet(plaintextFields, limits: limits)
        let serialNumber: CertificateSerialNumber
        if let suppliedSerialNumber {
            serialNumber = suppliedSerialNumber
        } else {
            serialNumber = try CertificateSerialNumber(draw32(using: randomSource))
        }

        let certifier = try await certifierWallet.getPublicKey(.init(selection: .identity)).publicKey
        let subjectKey: PublicKey
        switch subject {
        case .self:
            subjectKey = certifier
        case .publicKey(let key):
            subjectKey = key
        case .anyone:
            throw CertificateError.walletIdentityMismatch
        }

        let encrypted = try await encryptFields(
            plaintextFields,
            wrappingFor: subject,
            using: certifierWallet,
            limits: limits,
            randomSource: randomSource
        )
        let unsigned = try Certificate(
            type: type,
            serialNumber: serialNumber,
            subject: subjectKey,
            certifier: certifier,
            revocationOutpoint: revocationOutpoint,
            fields: encrypted.fields,
            limits: limits
        )
        let signed = try await unsigned.signed(using: certifierWallet, limits: limits)
        return try MasterCertificate(certificate: signed, masterKeyring: encrypted.keyring)
    }

    /// Acquires a direct certificate only after identity, expectations,
    /// signature, every master-key entry, and every encrypted field authenticate.
    public static func acquire(
        _ masterCertificate: MasterCertificate,
        requirements: CertificateAcquisitionRequirements = .init(),
        using subjectWallet: any CertificateWallet,
        limits: CertificateLimits = .standard
    ) async throws -> AcquiredCertificate {
        let certificate = masterCertificate.certificate
        if let type = requirements.type, type != certificate.type { throw CertificateError.requirementMismatch }
        if let serial = requirements.serialNumber, serial != certificate.serialNumber { throw CertificateError.requirementMismatch }
        if let certifier = requirements.certifier, certifier != certificate.certifier { throw CertificateError.requirementMismatch }
        if let outpoint = requirements.revocationOutpoint, outpoint != certificate.revocationOutpoint { throw CertificateError.requirementMismatch }
        try validateKeyringBounds(masterCertificate.masterKeyring, limits: limits)
        guard try await certificate.verifySignature(limits: limits) else {
            throw CertificateError.signatureMismatch
        }
        let identity = try await subjectWallet.getPublicKey(.init(selection: .identity)).publicKey
        guard certificate.subject == identity else { throw CertificateError.walletIdentityMismatch }
        let counterparty: WalletCounterparty = certificate.subject == certificate.certifier
            ? .self
            : .publicKey(certificate.certifier)
        let plaintext = try await decryptAll(
            certificate: certificate,
            keyring: masterCertificate.masterKeyring,
            keyID: { try CertificateProtocols.masterFieldKeyID($0) },
            counterparty: counterparty,
            using: subjectWallet,
            limits: limits,
            requireCompleteKeyring: true
        )
        return AcquiredCertificate(masterCertificate: masterCertificate, plaintextFields: plaintext)
    }

    /// Projects only requested, authenticated field keys to one verifier.
    public static func project(
        _ masterCertificate: MasterCertificate,
        fields requestedFields: [CertificateFieldName],
        to verifier: PublicKey,
        using subjectWallet: any CertificateWallet,
        limits: CertificateLimits = .standard
    ) async throws -> VerifiableCertificate {
        let certificate = masterCertificate.certificate
        guard requestedFields.count <= limits.maximumFieldCount else {
            throw CertificateError.tooManyFields(
                actual: requestedFields.count,
                maximum: limits.maximumFieldCount
            )
        }
        guard Set(requestedFields).count == requestedFields.count else {
            throw CertificateError.duplicateFieldName
        }
        for field in requestedFields where certificate.fields[field] == nil {
            throw CertificateError.fieldNotFound
        }
        try validateKeyringBounds(masterCertificate.masterKeyring, limits: limits)
        guard try await certificate.verifySignature(limits: limits) else {
            throw CertificateError.signatureMismatch
        }
        let identity = try await subjectWallet.getPublicKey(.init(selection: .identity)).publicKey
        guard identity == certificate.subject else { throw CertificateError.walletIdentityMismatch }

        let masterCounterparty: WalletCounterparty = certificate.subject == certificate.certifier
            ? .self
            : .publicKey(certificate.certifier)
        var revelationKeys: [CertificateFieldName: [UInt8]] = [:]
        for field in requestedFields.sorted() {
            revelationKeys[field] = try await decryptFieldKeyAndAuthenticateValue(
                certificate: certificate,
                keyring: masterCertificate.masterKeyring,
                field: field,
                keyID: try CertificateProtocols.masterFieldKeyID(field),
                counterparty: masterCounterparty,
                using: subjectWallet,
                limits: limits
            ).key
        }

        var projected: [CertificateFieldName: CertificateCiphertext] = [:]
        for field in requestedFields.sorted() {
            guard let key = revelationKeys[field] else { throw CertificateError.fieldNotFound }
            let encrypted: [UInt8]
            do {
                encrypted = try await subjectWallet.encrypt(.init(
                    protocolID: try CertificateProtocols.fieldEncryption,
                    keyID: try CertificateProtocols.verifierFieldKeyID(
                        serialNumber: certificate.serialNumber,
                        field: field
                    ),
                    counterparty: .publicKey(verifier),
                    plaintext: key
                )).ciphertext
            } catch WalletCryptoError.randomGenerationFailed {
                throw CertificateError.randomGenerationFailed
            } catch {
                throw CertificateError.encryptionFailed
            }
            projected[field] = try CertificateCiphertext(
                encrypted,
                maximumByteCount: limits.maximumKeyringCiphertextByteCount
            )
        }
        return try VerifiableCertificate(
            certificate: certificate,
            keyring: CertificateKeyring(projected, limits: limits)
        )
    }

    /// Verifies a core signature, decrypts exactly the projected fields, and
    /// returns no partial result if any key or field authentication fails.
    public static func verify(
        _ verifiableCertificate: VerifiableCertificate,
        using verifierWallet: any CertificateWallet,
        limits: CertificateLimits = .standard
    ) async throws -> [CertificateFieldName: String] {
        let certificate = verifiableCertificate.certificate
        try validateKeyringBounds(verifiableCertificate.keyring, limits: limits)
        guard try await certificate.verifySignature(limits: limits) else {
            throw CertificateError.signatureMismatch
        }
        return try await decryptAll(
            certificate: certificate,
            keyring: verifiableCertificate.keyring,
            keyID: {
                try CertificateProtocols.verifierFieldKeyID(
                    serialNumber: certificate.serialNumber,
                    field: $0
                )
            },
            counterparty: .publicKey(certificate.subject),
            using: verifierWallet,
            limits: limits,
            requireCompleteKeyring: false
        )
    }

    public static let disabledRevocationOutpoint = Outpoint(
        transactionID: TransactionID(
            exactDigestBytesGuaranteed: [UInt8](repeating: 0, count: 32)
        ),
        outputIndex: 0
    )

    private struct EncryptedFields {
        let fields: [CertificateFieldName: CertificateCiphertext]
        let keyring: CertificateKeyring
    }

    private static func encryptFields(
        _ plaintextFields: [CertificateFieldName: String],
        wrappingFor counterparty: WalletCounterparty,
        using wallet: any CertificateWallet,
        limits: CertificateLimits,
        randomSource: any SecureRandomSource
    ) async throws -> EncryptedFields {
        var fields: [CertificateFieldName: CertificateCiphertext] = [:]
        var keyring: [CertificateFieldName: CertificateCiphertext] = [:]
        for name in plaintextFields.keys.sorted() {
            guard let plaintext = plaintextFields[name] else { throw CertificateError.fieldNotFound }
            let plaintextBytes = Array(plaintext.utf8)
            guard plaintextBytes.count <= limits.maximumFieldPlaintextByteCount else {
                throw CertificateError.fieldValueTooLarge(actual: plaintextBytes.count, maximum: limits.maximumFieldPlaintextByteCount)
            }
            let key: SymmetricKey
            do { key = try SymmetricKey.random(using: randomSource) }
            catch { throw CertificateError.randomGenerationFailed }
            let encryptedField: [UInt8]
            do { encryptedField = try key.seal(plaintextBytes, using: randomSource) }
            catch SymmetricKeyError.randomGenerationFailed { throw CertificateError.randomGenerationFailed }
            catch { throw CertificateError.encryptionFailed }
            fields[name] = try CertificateCiphertext(
                encryptedField,
                maximumByteCount: limits.maximumFieldCiphertextByteCount
            )
            let wrapped: [UInt8]
            do {
                wrapped = try await wallet.encrypt(.init(
                    protocolID: try CertificateProtocols.fieldEncryption,
                    keyID: try CertificateProtocols.masterFieldKeyID(name),
                    counterparty: counterparty,
                    plaintext: key.bytes
                )).ciphertext
            } catch WalletCryptoError.randomGenerationFailed {
                throw CertificateError.randomGenerationFailed
            } catch {
                throw CertificateError.encryptionFailed
            }
            keyring[name] = try CertificateCiphertext(
                wrapped,
                maximumByteCount: limits.maximumKeyringCiphertextByteCount
            )
        }
        return EncryptedFields(fields: fields, keyring: try CertificateKeyring(keyring, limits: limits))
    }

    private static func decryptAll(
        certificate: Certificate,
        keyring: CertificateKeyring,
        keyID: (CertificateFieldName) throws -> WalletKeyID,
        counterparty: WalletCounterparty,
        using wallet: any CertificateWallet,
        limits: CertificateLimits,
        requireCompleteKeyring: Bool
    ) async throws -> [CertificateFieldName: String] {
        guard keyring.entries.count <= limits.maximumFieldCount else {
            throw CertificateError.tooManyFields(
                actual: keyring.entries.count,
                maximum: limits.maximumFieldCount
            )
        }
        if requireCompleteKeyring,
           Set(keyring.entries.keys) != Set(certificate.fields.keys) {
            throw CertificateError.keyringMismatch
        }
        guard Set(keyring.entries.keys).isSubset(of: Set(certificate.fields.keys)) else {
            throw CertificateError.keyringMismatch
        }
        var staged: [CertificateFieldName: String] = [:]
        for field in keyring.entries.keys.sorted() {
            let result = try await decryptFieldKeyAndAuthenticateValue(
                certificate: certificate,
                keyring: keyring,
                field: field,
                keyID: try keyID(field),
                counterparty: counterparty,
                using: wallet,
                limits: limits
            )
            staged[field] = result.plaintext
        }
        return staged
    }

    private static func decryptFieldKeyAndAuthenticateValue(
        certificate: Certificate,
        keyring: CertificateKeyring,
        field: CertificateFieldName,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty,
        using wallet: any CertificateWallet,
        limits: CertificateLimits
    ) async throws -> (key: [UInt8], plaintext: String) {
        guard let wrappedKey = keyring.entries[field],
              let encryptedField = certificate.fields[field] else {
            throw CertificateError.fieldNotFound
        }
        guard wrappedKey.bytes.count <= limits.maximumKeyringCiphertextByteCount,
              encryptedField.bytes.count <= limits.maximumFieldCiphertextByteCount else {
            throw CertificateError.decryptionFailed
        }
        let key: [UInt8]
        do {
            key = try await wallet.decrypt(.init(
                protocolID: try CertificateProtocols.fieldEncryption,
                keyID: keyID,
                counterparty: counterparty,
                ciphertext: wrappedKey.bytes
            )).plaintext
        } catch {
            throw CertificateError.decryptionFailed
        }
        guard key.count == SymmetricKey.keyByteCount else { throw CertificateError.decryptionFailed }
        let plaintextBytes: [UInt8]
        do { plaintextBytes = try SymmetricKey(key).open(encryptedField.bytes) }
        catch { throw CertificateError.decryptionFailed }
        guard plaintextBytes.count <= limits.maximumFieldPlaintextByteCount,
              let plaintext = String(bytes: plaintextBytes, encoding: .utf8),
              Array(plaintext.utf8) == plaintextBytes else {
            throw CertificateError.decryptionFailed
        }
        return (key, plaintext)
    }

    private static func validateFieldSet(
        _ fields: [CertificateFieldName: String],
        limits: CertificateLimits
    ) throws {
        guard fields.count <= limits.maximumFieldCount else {
            throw CertificateError.tooManyFields(actual: fields.count, maximum: limits.maximumFieldCount)
        }
        for (name, value) in fields {
            _ = try CertificateFieldName(name.value, limits: limits)
            let count = value.utf8.count
            guard count <= limits.maximumFieldPlaintextByteCount else {
                throw CertificateError.fieldValueTooLarge(actual: count, maximum: limits.maximumFieldPlaintextByteCount)
            }
        }
    }

    private static func validateKeyringBounds(
        _ keyring: CertificateKeyring,
        limits: CertificateLimits
    ) throws {
        guard keyring.entries.count <= limits.maximumFieldCount else {
            throw CertificateError.tooManyFields(
                actual: keyring.entries.count,
                maximum: limits.maximumFieldCount
            )
        }
        for (name, value) in keyring.entries {
            guard name.utf8Bytes.count <= limits.maximumFieldNameUTF8ByteCount else {
                throw CertificateError.fieldNameTooLong(
                    actual: name.utf8Bytes.count,
                    maximum: limits.maximumFieldNameUTF8ByteCount
                )
            }
            guard value.bytes.count <= limits.maximumKeyringCiphertextByteCount else {
                throw CertificateError.keyringValueTooLarge(
                    actual: value.bytes.count,
                    maximum: limits.maximumKeyringCiphertextByteCount
                )
            }
        }
    }

    private static func draw32(using randomSource: any SecureRandomSource) throws -> [UInt8] {
        let bytes: [UInt8]
        do { bytes = try randomSource.randomBytes(count: 32) }
        catch { throw CertificateError.randomGenerationFailed }
        guard bytes.count == 32 else { throw CertificateError.randomGenerationFailed }
        return bytes
    }
}
