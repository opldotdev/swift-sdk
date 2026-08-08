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
                guard try await certificate.verifySignature(limits: limits.certificateLimits) else {
                    throw AuthError.certificateValidationFailed
                }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
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
            throw AuthError.certificateValidationFailed
        }
        return result
    }

    /// Verifies certificate signatures, request matching, subject binding, and
    /// every disclosed field. The result is all-or-nothing.
    public static func validate(
        _ certificates: [VerifiableCertificate],
        from peer: PublicKey,
        requested request: AuthRequestedCertificateSet,
        using wallet: any CertificateWallet,
        limits: AuthLimits = .standard
    ) async throws -> [AuthValidatedCertificate] {
        guard !certificates.isEmpty,
            certificates.count <= limits.maximumCertificateCount
        else { throw AuthError.certificateValidationFailed }

        var aggregate = 0
        var foundTypes = Set<CertificateTypeID>()
        var result: [AuthValidatedCertificate] = []
        result.reserveCapacity(certificates.count)

        for verifiable in certificates {
            try Task.checkCancellation()
            let certificate = verifiable.certificate
            guard certificate.subject == peer,
                request.certifiers.contains(certificate.certifier),
                let fields = request.certificateTypes[certificate.type],
                Set(verifiable.keyring.entries.keys) == Set(fields)
            else { throw AuthError.certificateValidationFailed }

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
                throw AuthError.certificateValidationFailed
            }
            try Task.checkCancellation()
            guard Set(plaintext.keys) == Set(fields) else {
                throw AuthError.certificateValidationFailed
            }
            result.append(
                AuthValidatedCertificate(
                    certificate: certificate,
                    disclosedFields: plaintext
                )
            )
            foundTypes.insert(certificate.type)
        }

        guard foundTypes == Set(request.certificateTypes.keys) else {
            throw AuthError.certificateValidationFailed
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
