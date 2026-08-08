import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet

/// A bounded transport-neutral identity resolver and disclosure client.
public struct IdentityClient<Wallet: WalletInterface>:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let wallet: Wallet
    public let options: IdentityClientOptions
    public let limits: IdentityLimits

    public init(
        wallet: Wallet,
        options: IdentityClientOptions? = nil,
        limits: IdentityLimits
    ) throws {
        self.wallet = wallet
        self.options = try options ?? IdentityClientOptions()
        self.limits = limits
    }

    public func resolveByIdentityKey(
        _ request: WalletDiscoverByIdentityKeyRequest
    ) async throws -> [DisplayableIdentity] {
        try Task.checkCancellation()
        let result: WalletDiscoverCertificatesResult
        do {
            result = try await wallet.discoverByIdentityKey(request)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw IdentityError.walletOperationFailed(.discoverByIdentityKey)
        }
        try Task.checkCancellation()
        return try parse(result)
    }

    public func resolveByAttributes(
        _ request: WalletDiscoverByAttributesRequest
    ) async throws -> [DisplayableIdentity] {
        try Task.checkCancellation()
        let result: WalletDiscoverCertificatesResult
        do {
            result = try await wallet.discoverByAttributes(request)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw IdentityError.walletOperationFailed(.discoverByAttributes)
        }
        try Task.checkCancellation()
        return try parse(result)
    }

    public static func parseIdentity(
        _ identity: WalletIdentityCertificate,
        limits: IdentityLimits
    ) throws -> DisplayableIdentity {
        try IdentityParser.parse(identity, limits: limits)
    }

    public func publiclyRevealAttributes<BroadcasterType: Broadcaster>(
        certificate: Certificate,
        fieldsToReveal: [CertificateFieldName],
        verifier: PublicKey,
        using broadcaster: BroadcasterType
    ) async throws -> BroadcastResult {
        try validateDisclosure(certificate: certificate, fieldsToReveal: fieldsToReveal)
        try Task.checkCancellation()
        do {
            guard try await certificate.verifySignature(limits: limits.certificateLimits) else {
                throw IdentityError.certificateVerificationFailed
            }
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as IdentityError {
            throw error
        } catch {
            throw IdentityError.certificateVerificationFailed
        }
        try Task.checkCancellation()

        let proveRequest = try WalletProveCertificateRequest(
            certificate: certificate,
            fieldsToReveal: fieldsToReveal,
            verifier: verifier,
            limits: limits.walletLimits
        )
        let proof: WalletProveCertificateResult
        do {
            proof = try await wallet.proveCertificate(proveRequest)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw IdentityError.walletOperationFailed(.proveCertificate)
        }
        try Task.checkCancellation()
        guard Set(proof.keyringForVerifier.keys) == Set(fieldsToReveal) else {
            throw IdentityError.inconsistentProvedKeyring
        }
        _ = try CertificateKeyring(
            proof.keyringForVerifier,
            limits: limits.certificateLimits
        )

        let disclosure = try IdentityDisclosureJSON.encode(
            certificate: certificate,
            keyring: proof.keyringForVerifier,
            limits: limits
        )
        let lockingScript: Script
        do {
            lockingScript = try await PushDrop.lockingScript(
                fields: [disclosure],
                using: wallet,
                protocolID: options.protocolID,
                keyID: options.keyID,
                counterparty: .anyone,
                forSelf: true,
                includeSignature: true,
                lockPosition: .beforeCompatibility,
                limits: limits.pushDropLimits
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as PushDropError {
            throw error
        } catch {
            throw IdentityError.walletOperationFailed(.createDisclosureScript)
        }
        try Task.checkCancellation()

        let output = try WalletCreateActionOutput(
            lockingScript: lockingScript.bytes,
            satoshis: options.tokenAmount,
            outputDescription: "Identity Token",
            limits: limits.walletLimits
        )
        let actionOptions = try WalletCreateActionOptions(
            randomizeOutputs: false,
            limits: limits.walletLimits
        )
        let actionRequest = try WalletCreateActionRequest(
            description: "Create a new Identity Token",
            outputs: [output],
            options: actionOptions,
            limits: limits.walletLimits
        )
        let action: WalletCreateActionResult
        do {
            action = try await wallet.createAction(actionRequest)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw IdentityError.walletOperationFailed(.createAction)
        }
        try Task.checkCancellation()

        guard let atomic = action.transaction else {
            throw IdentityError.missingCompletedTransaction
        }
        guard let transaction = try atomic.beef.transaction(
            for: atomic.subjectTransactionID,
            limits: limits.beefLimits.transactionLimits
        ) else {
            throw IdentityError.missingSubjectTransaction
        }
        let broadcastResult: BroadcastResult
        do {
            broadcastResult = try await broadcaster.broadcast(
                transaction,
                limits: limits.beefLimits.transactionLimits
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw IdentityError.broadcastFailed
        }
        try Task.checkCancellation()
        guard broadcastResult.transactionID == atomic.subjectTransactionID else {
            throw IdentityError.broadcastTransactionIDMismatch
        }
        return broadcastResult
    }

    public func publiclyRevealAttributesSimple<BroadcasterType: Broadcaster>(
        certificate: Certificate,
        fieldsToReveal: [CertificateFieldName],
        verifier: PublicKey,
        using broadcaster: BroadcasterType
    ) async throws -> TransactionID {
        let result = try await publiclyRevealAttributes(
            certificate: certificate,
            fieldsToReveal: fieldsToReveal,
            verifier: verifier,
            using: broadcaster
        )
        return result.transactionID
    }

    public var description: String { "<redacted identity client>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    private func parse(
        _ result: WalletDiscoverCertificatesResult
    ) throws -> [DisplayableIdentity] {
        let count = result.certificates.count
        guard UInt64(count) <= UInt64(result.totalCertificates) else {
            throw IdentityError.inconsistentDiscoveryTotal
        }
        guard count <= limits.maximumIdentityCount else {
            throw IdentityError.tooManyIdentities(
                actual: count,
                maximum: limits.maximumIdentityCount
            )
        }
        var identities: [DisplayableIdentity] = []
        identities.reserveCapacity(count)
        var aggregate = 0
        for certificate in result.certificates {
            let identity = try IdentityParser.parse(certificate, limits: limits)
            let values = [
                identity.name, identity.avatarURL, identity.abbreviatedKey,
                identity.identityKey, identity.badgeIconURL,
                identity.badgeLabel, identity.badgeClickURL,
            ]
            for value in values {
                let (next, overflow) = aggregate.addingReportingOverflow(value.utf8.count)
                guard !overflow else { throw IdentityError.sizeOverflow }
                aggregate = next
                guard aggregate <= limits.maximumAggregateDisplayUTF8ByteCount else {
                    throw IdentityError.aggregateDisplayTextTooLarge(
                        actual: aggregate,
                        maximum: limits.maximumAggregateDisplayUTF8ByteCount
                    )
                }
            }
            identities.append(identity)
        }
        return identities
    }

    private func validateDisclosure(
        certificate: Certificate,
        fieldsToReveal: [CertificateFieldName]
    ) throws {
        guard !certificate.fields.isEmpty else { throw IdentityError.certificateHasNoFields }
        guard !fieldsToReveal.isEmpty else { throw IdentityError.noFieldsToReveal }
        let fieldMaximum = min(
            limits.maximumFieldsToReveal,
            limits.certificateLimits.maximumFieldCount
        )
        guard fieldsToReveal.count <= fieldMaximum else {
            throw IdentityError.tooManyFieldsToReveal(
                actual: fieldsToReveal.count,
                maximum: fieldMaximum
            )
        }
        guard Set(fieldsToReveal).count == fieldsToReveal.count else {
            throw IdentityError.duplicateFieldToReveal
        }
        guard fieldsToReveal.allSatisfy({ certificate.fields[$0] != nil }) else {
            throw IdentityError.requestedFieldIsAbsent
        }
        guard certificate.signature != nil else {
            throw IdentityError.certificateVerificationFailed
        }
    }
}
