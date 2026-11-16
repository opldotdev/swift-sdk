import BSVKeys
import BSVWallet

/// Bounded wallet helpers for BRC-103 certificate exchange.
///
/// These helpers do not select a transport, certifier trust policy, or
/// revocation policy. The caller supplies the wallet and must check revocation
/// before it treats a validated certificate as current.
public enum AuthCertificateExchange {
    /// Selects wallet certificates and projects exactly the requested fields
    /// for one verifier.
    public static func prepare(
        _ request: AuthRequestedCertificateSet,
        for verifier: PublicKey,
        using wallet: any WalletCertificateOperations,
        privilege: WalletPrivilege = .standard,
        limits: AuthLimits = .standard,
        walletLimits: WalletABILimits = .standard
    ) async throws -> [VerifiableCertificate] {
        try Task.checkCancellation()
        let listed = try await wallet.listCertificates(
            try WalletListCertificatesRequest(
                certifiers: request.certifiers,
                types: sortedTypes(request.certificateTypes),
                privilege: privilege,
                limits: walletLimits
            )
        )
        try Task.checkCancellation()
        guard listed.certificates.count <= limits.maximumCertificateCount else {
            throw AuthError.resourceLimit
        }

        var result: [VerifiableCertificate] = []
        result.reserveCapacity(listed.certificates.count)
        var foundTypes = Set<CertificateTypeID>()
        var aggregate = 0

        for item in listed.certificates {
            try Task.checkCancellation()
            let certificate = item.certificate
            guard request.certifiers.contains(certificate.certifier),
                let fields = request.certificateTypes[certificate.type]
            else { continue }

            do {
                guard try await certificate.verifySignatureInEitherFieldOrder(limits: limits.certificateLimits) else {
                    throw AuthError.certificateValidationFailed
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                AuthLog.reported(
                    "AuthCertificateExchange.prepare signature", error,
                    as: AuthError.certificateValidationFailed)
                throw AuthError.certificateValidationFailed
            }
            try Task.checkCancellation()

            let proof = try await wallet.proveCertificate(
                try WalletProveCertificateRequest(
                    certificate: certificate,
                    fieldsToReveal: fields,
                    verifier: verifier,
                    privilege: privilege,
                    limits: walletLimits
                )
            )
            try Task.checkCancellation()
            guard Set(proof.keyringForVerifier.keys) == Set(fields) else {
                AuthLog.rejected(
                    "AuthCertificateExchange.prepare",
                    "the wallet proof does not reveal exactly the requested fields",
                    as: AuthError.certificateValidationFailed)
                throw AuthError.certificateValidationFailed
            }
            let verifiable = try VerifiableCertificate(
                certificate: certificate,
                keyring: CertificateKeyring(
                    proof.keyringForVerifier,
                    limits: limits.certificateLimits
                )
            )
            try addEnvelopeSize(
                verifiable,
                aggregate: &aggregate,
                limits: limits
            )
            result.append(verifiable)
            foundTypes.insert(certificate.type)
        }

        guard foundTypes == Set(request.certificateTypes.keys), !result.isEmpty else {
            AuthLog.rejected(
                "AuthCertificateExchange.prepare",
                "the wallet holds \(foundTypes.count) of \(request.certificateTypes.count) requested types",
                as: AuthError.certificateValidationFailed)
            throw AuthError.certificateValidationFailed
        }
        return result
    }

    /// Verifies certificate signatures, request matching, subject binding, and
    /// every disclosed field. The result is all-or-nothing.
    ///
    /// Every requested type must be present and every certificate must
    /// reveal every requested field of its type. Use `validateSubset` to
    /// accept any allowed subset, as `@bsv/sdk` does.
    public static func validate(
        _ certificates: [VerifiableCertificate],
        from peer: PublicKey,
        requested request: AuthRequestedCertificateSet,
        using wallet: any CertificateWallet,
        limits: AuthLimits = .standard
    ) async throws -> [AuthValidatedCertificate] {
        guard !certificates.isEmpty else {
            AuthLog.rejected(
                "AuthCertificateExchange.validate", "no certificates",
                as: AuthError.certificateValidationFailed)
            throw AuthError.certificateValidationFailed
        }
        return try await validate(
            certificates, from: peer, requested: request, using: wallet, limits: limits,
            complete: true)
    }

    /// Verifies certificates that answer a request as an allowlist, as
    /// `validateCertificates` in `@bsv/sdk` does (`validateCertificates.ts:23-29`).
    ///
    /// Each certificate must be signed by a requested certifier, be of a
    /// requested type, name `peer` as subject, and reveal a nonempty subset of
    /// that type's requested fields, all of which must decrypt. Types and
    /// fields that were requested but not supplied are allowed: the result
    /// holds exactly what was disclosed, and the caller decides whether that
    /// is enough. No certificates gives an empty result. Any certificate that
    /// fails makes the whole call fail.
    public static func validateSubset(
        _ certificates: [VerifiableCertificate],
        from peer: PublicKey,
        requested request: AuthRequestedCertificateSet,
        using wallet: any CertificateWallet,
        limits: AuthLimits = .standard
    ) async throws -> [AuthValidatedCertificate] {
        try await validate(
            certificates, from: peer, requested: request, using: wallet, limits: limits,
            complete: false)
    }

    private static func validate(
        _ certificates: [VerifiableCertificate],
        from peer: PublicKey,
        requested request: AuthRequestedCertificateSet,
        using wallet: any CertificateWallet,
        limits: AuthLimits,
        complete: Bool
    ) async throws -> [AuthValidatedCertificate] {
        let operation = complete ? "AuthCertificateExchange.validate" : "AuthCertificateExchange.validateSubset"
        func reject(_ reason: String) -> AuthError {
            AuthLog.rejected(operation, reason, as: AuthError.certificateValidationFailed)
            return AuthError.certificateValidationFailed
        }
        guard certificates.count <= limits.maximumCertificateCount else {
            throw reject("\(certificates.count) certificates exceed the limit")
        }

        var aggregate = 0
        var foundTypes = Set<CertificateTypeID>()
        var result: [AuthValidatedCertificate] = []
        result.reserveCapacity(certificates.count)

        for (position, verifiable) in certificates.enumerated() {
            try Task.checkCancellation()
            let certificate = verifiable.certificate
            guard certificate.subject == peer else {
                throw reject("certificate \(position) names another subject")
            }
            guard request.certifiers.contains(certificate.certifier) else {
                throw reject("certificate \(position) has a certifier that was not requested")
            }
            guard let fields = request.certificateTypes[certificate.type] else {
                throw reject("certificate \(position) has a type that was not requested")
            }
            let revealed = Set(verifiable.keyring.entries.keys)
            if complete {
                guard revealed == Set(fields) else {
                    throw reject("certificate \(position) does not reveal exactly the requested fields")
                }
            } else {
                guard !revealed.isEmpty, revealed.isSubset(of: Set(fields)) else {
                    throw reject(
                        "certificate \(position) reveals no field or a field that was not requested")
                }
            }

            try addEnvelopeSize(
                verifiable,
                aggregate: &aggregate,
                limits: limits
            )
            let plaintext: [CertificateFieldName: String]
            do {
                plaintext = try await CertificateEngine.verify(
                    verifiable,
                    using: wallet,
                    limits: limits.certificateLimits
                )
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                AuthLog.reported(
                    "\(operation) certificate \(position)", error,
                    as: AuthError.certificateValidationFailed)
                throw AuthError.certificateValidationFailed
            }
            try Task.checkCancellation()
            guard Set(plaintext.keys) == revealed else {
                throw reject("certificate \(position) decrypted to other fields than it reveals")
            }
            result.append(
                AuthValidatedCertificate(
                    certificate: certificate,
                    disclosedFields: plaintext
                )
            )
            foundTypes.insert(certificate.type)
        }

        guard !complete || foundTypes == Set(request.certificateTypes.keys) else {
            throw reject("\(request.certificateTypes.count - foundTypes.count) requested types are missing")
        }
        return result
    }

    private static func sortedTypes(
        _ values: [CertificateTypeID: [CertificateFieldName]]
    ) -> [CertificateTypeID] {
        values.keys.sorted { $0.bytes.lexicographicallyPrecedes($1.bytes) }
    }

    private static func addEnvelopeSize(
        _ certificate: VerifiableCertificate,
        aggregate: inout Int,
        limits: AuthLimits
    ) throws {
        let bytes = try certificate.binary(limits: limits.certificateLimits)
        let (next, overflow) = aggregate.addingReportingOverflow(bytes.count)
        guard !overflow, next <= limits.maximumCertificateAggregateBytes else {
            throw AuthError.resourceLimit
        }
        aggregate = next
    }
}
