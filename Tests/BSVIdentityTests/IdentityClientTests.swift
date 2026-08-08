@testable import BSVIdentity
import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import Testing

@Suite("Transport-neutral identity client")
struct IdentityClientTests {
    @Test("known identities use canonical compressed-key hex")
    func parsesKnownIdentity() async throws {
        let fixture = try await identityFixture()
        let identityCertificate = try WalletIdentityCertificate(
            certificate: fixture.certificate,
            certifierInfo: try WalletIdentityCertifier(
                name: "Certifier", iconURL: "icon", description: "description", trust: 7
            ),
            publiclyRevealedKeyring: [:],
            decryptedFields: [
                try CertificateFieldName("userName"): "Alice",
                try CertificateFieldName("profilePhoto"): "photo",
            ]
        )

        let parsed = try IdentityClient<IdentityTestWallet>.parseIdentity(
            identityCertificate,
            limits: fixture.limits
        )
        #expect(parsed.name == "Alice")
        #expect(parsed.avatarURL == "photo")
        #expect(parsed.identityKey == Hex.encode(fixture.root.publicKey.compressedBytes))
        #expect(parsed.abbreviatedKey == String(parsed.identityKey.prefix(10)) + "...")
        #expect(parsed.badgeLabel == "X account certified by Certifier")
        #expect(!String(reflecting: parsed).contains("Alice"))
        #expect(Array(Mirror(reflecting: parsed).children).isEmpty)
    }

    @Test("every unrecognized type uses the complete unknown fallback")
    func parsesUnknownIdentity() async throws {
        let fixture = try await identityFixture(type: try CertificateTypeID([UInt8](repeating: 9, count: 32)))
        let identityCertificate = try WalletIdentityCertificate(
            certificate: fixture.certificate,
            certifierInfo: try WalletIdentityCertifier(
                name: "hostile", iconURL: "hostile", description: "hostile", trust: 0
            ),
            publiclyRevealedKeyring: [:],
            decryptedFields: [try CertificateFieldName("profilePhoto"): "fallback-photo"]
        )

        let parsed = try IdentityParser.parse(identityCertificate, limits: fixture.limits)
        #expect(parsed.name == "Unknown Identity")
        #expect(parsed.avatarURL == "fallback-photo")
        #expect(parsed.identityKey.isEmpty)
        #expect(parsed.abbreviatedKey.isEmpty)
    }

    @Test("all nine pinned identity types keep their display mapping")
    func parsesAllKnownTypes() async throws {
        let fixture = try await identityFixture()
        let fields: [CertificateFieldName: String] = [
            try CertificateFieldName("userName"): "handle",
            try CertificateFieldName("profilePhoto"): "photo",
            try CertificateFieldName("email"): "a@example.com",
            try CertificateFieldName("phoneNumber"): "+1",
            try CertificateFieldName("firstName"): "Ada",
            try CertificateFieldName("lastName"): "Lovelace",
            try CertificateFieldName("name"): "Entity",
            try CertificateFieldName("icon"): "entity-icon",
            try CertificateFieldName("cool"): "true",
        ]
        let expectedNames: [KnownIdentityType: String] = [
            .identiCert: "Ada Lovelace",
            .discord: "handle",
            .phone: "+1",
            .x: "handle",
            .registrant: "Entity",
            .email: "a@example.com",
            .anyone: "Anyone",
            .self: "You",
            .cool: "Cool Person!",
        ]

        for kind in KnownIdentityType.allCases {
            let certificate = try Certificate(
                type: try kind.certificateType,
                serialNumber: fixture.certificate.serialNumber,
                subject: fixture.root.publicKey,
                certifier: fixture.root.publicKey,
                revocationOutpoint: fixture.certificate.revocationOutpoint,
                fields: fixture.certificate.fields
            )
            let value = try WalletIdentityCertificate(
                certificate: certificate,
                certifierInfo: try WalletIdentityCertifier(
                    name: "Certifier", iconURL: "icon", description: "description", trust: 1
                ),
                publiclyRevealedKeyring: [:],
                decryptedFields: fields
            )
            let parsed = try IdentityParser.parse(value, limits: fixture.limits)
            #expect(parsed.name == expectedNames[kind])
        }
        #expect(KnownIdentityType.allCases.count == 9)
    }

    @Test("result count and display bytes are bounded before output growth")
    func resolutionBounds() async throws {
        let fixture = try await identityFixture()
        let certificate = try WalletIdentityCertificate(
            certificate: fixture.certificate,
            certifierInfo: try WalletIdentityCertifier(
                name: "Certifier", iconURL: "icon", description: "description", trust: 1
            ),
            publiclyRevealedKeyring: [:],
            decryptedFields: [try CertificateFieldName("userName"): "Alice"]
        )
        let state = IdentityWalletState(discovered: [certificate, certificate])
        let wallet = IdentityTestWallet(root: fixture.root, state: state)
        let oneIdentity = try identityLimits(maximumIdentityCount: 1)
        let client = try IdentityClient(wallet: wallet, limits: oneIdentity)

        await #expect(throws: IdentityError.tooManyIdentities(actual: 2, maximum: 1)) {
            try await client.resolveByIdentityKey(
                WalletDiscoverByIdentityKeyRequest(identityKey: fixture.root.publicKey)
            )
        }

        let smallText = try identityLimits(maximumDisplayText: 4)
        #expect(throws: IdentityError.displayTextTooLarge(actual: 5, maximum: 4)) {
            try DisplayableIdentity(
                name: "Alice",
                avatarURL: "",
                abbreviatedKey: "",
                identityKey: "",
                badgeIconURL: "",
                badgeLabel: "",
                badgeClickURL: "",
                limits: smallText
            )
        }
    }

    @Test("public disclosure uses the explicit verifier and canonical bounded JSON")
    func revealsAttributes() async throws {
        let fixture = try await identityFixture()
        let state = IdentityWalletState(
            proofKeyring: [fixture.field: try CertificateCiphertext([7, 8, 9])],
            completedTransaction: fixture.atomic
        )
        let wallet = IdentityTestWallet(root: fixture.root, state: state)
        let client = try IdentityClient(wallet: wallet, limits: fixture.limits)
        let verifier = try PrivateKey(Array(repeating: 2, count: 31) + [3]).publicKey
        let broadcaster = RecordingBroadcaster(expected: fixture.transactionID)

        let result = try await client.publiclyRevealAttributes(
            certificate: fixture.certificate,
            fieldsToReveal: [fixture.field],
            verifier: verifier,
            using: broadcaster
        )
        #expect(result.transactionID == fixture.transactionID)
        let snapshot = await state.snapshot()
        #expect(snapshot.proveVerifier == verifier)
        let request = try #require(snapshot.action)
        let output = try #require(request.outputs?.first)
        let script = try Script(
            bytes: output.lockingScript,
            maximumByteCount: fixture.limits.pushDropLimits.maximumScriptByteCount
        )
        let decoded = try PushDrop.decode(
            script,
            lockPosition: .beforeCompatibility,
            limits: fixture.limits.pushDropLimits
        )
        let disclosure = try #require(decoded.fields.first)
        let expected = try IdentityDisclosureJSON.encode(
            certificate: fixture.certificate,
            keyring: [fixture.field: try CertificateCiphertext([7, 8, 9])],
            limits: fixture.limits
        )
        #expect(disclosure == expected)
        let signature = try #require(fixture.certificate.signature)
        let expectedText = "{\"certifier\":\""
            + Hex.encode(fixture.certificate.certifier.compressedBytes)
            + "\",\"fields\":{\"userName\":\"AQID\"},\"keyring\":{\"userName\":\"BwgJ\"}"
            + ",\"revocationOutpoint\":\"" + fixture.certificate.revocationOutpoint.description
            + "\",\"serialNumber\":\"" + fixture.certificate.serialNumber.base64
            + "\",\"signature\":\"" + Hex.encode(signature.derBytes)
            + "\",\"subject\":\"" + Hex.encode(fixture.certificate.subject.compressedBytes)
            + "\",\"type\":\"" + fixture.certificate.type.base64 + "\"}"
        #expect(disclosure == Array(expectedText.utf8))
        let text = try #require(String(bytes: disclosure, encoding: .utf8))
        #expect(text.hasPrefix("{\"certifier\":"))
        #expect(text.range(of: "\"fields\":")!.lowerBound < text.range(of: "\"keyring\":")!.lowerBound)
        #expect(await broadcaster.callCount() == 1)
        #expect(!String(reflecting: client).contains("IdentityTestWallet"))
    }

    @Test("disclosure JSON enforces exact and max plus one limits during append")
    func disclosureJSONBounds() async throws {
        let fixture = try await identityFixture()
        let keyring = [fixture.field: try CertificateCiphertext([7, 8, 9])]
        let baseline = try IdentityDisclosureJSON.encode(
            certificate: fixture.certificate,
            keyring: keyring,
            limits: fixture.limits
        )
        let exact = try identityLimits(maximumJSON: baseline.count)
        #expect(try IdentityDisclosureJSON.encode(
            certificate: fixture.certificate,
            keyring: keyring,
            limits: exact
        ) == baseline)
        let short = try identityLimits(maximumJSON: baseline.count - 1)
        #expect(throws: IdentityError.disclosureJSONTooLarge(
            actual: baseline.count,
            maximum: baseline.count - 1
        )) {
            try IdentityDisclosureJSON.encode(
                certificate: fixture.certificate,
                keyring: keyring,
                limits: short
            )
        }
    }

    @Test("validation precedes wallet calls and duplicate fields are rejected")
    func validatesBeforeWallet() async throws {
        let fixture = try await identityFixture()
        let state = IdentityWalletState()
        let client = try IdentityClient(
            wallet: IdentityTestWallet(root: fixture.root, state: state),
            limits: fixture.limits
        )
        let broadcaster = RecordingBroadcaster(expected: fixture.transactionID)

        await #expect(throws: IdentityError.duplicateFieldToReveal) {
            try await client.publiclyRevealAttributes(
                certificate: fixture.certificate,
                fieldsToReveal: [fixture.field, fixture.field],
                verifier: fixture.root.publicKey,
                using: broadcaster
            )
        }
        #expect(await state.snapshot().callCount == 0)
        #expect(await broadcaster.callCount() == 0)
        #expect(throws: IdentityError.unsupportedOutputIndex(1)) {
            try IdentityClientOptions(outputIndex: 1)
        }
        #expect(throws: IdentityError.invalidTokenAmount) {
            try IdentityClientOptions(tokenAmount: 0)
        }
    }

    @Test("wallet proof keyrings must match the requested fields exactly")
    func rejectsInconsistentProofKeyring() async throws {
        let fixture = try await identityFixture()
        let client = try IdentityClient(
            wallet: IdentityTestWallet(
                root: fixture.root,
                state: IdentityWalletState(proofKeyring: [:])
            ),
            limits: fixture.limits
        )
        await #expect(throws: IdentityError.inconsistentProvedKeyring) {
            try await client.publiclyRevealAttributes(
                certificate: fixture.certificate,
                fieldsToReveal: [fixture.field],
                verifier: fixture.root.publicKey,
                using: RecordingBroadcaster(expected: fixture.transactionID)
            )
        }
    }

    @Test("wallet failures are redacted and cancellation remains cancellation")
    func redactionAndCancellation() async throws {
        let fixture = try await identityFixture()
        let failed = IdentityTestWallet(
            root: fixture.root,
            state: IdentityWalletState(discoveryFailure: true)
        )
        let failedClient = try IdentityClient(wallet: failed, limits: fixture.limits)
        await #expect(throws: IdentityError.walletOperationFailed(.discoverByAttributes)) {
            try await failedClient.resolveByAttributes(try WalletDiscoverByAttributesRequest(
                attributes: [try CertificateFieldName("email"): "secret@example.com"]
            ))
        }

        let blocking = IdentityTestWallet(
            root: fixture.root,
            state: IdentityWalletState(blockDiscovery: true)
        )
        let blockingClient = try IdentityClient(wallet: blocking, limits: fixture.limits)
        let task = Task {
            try await blockingClient.resolveByIdentityKey(
                WalletDiscoverByIdentityKeyRequest(identityKey: fixture.root.publicKey)
            )
        }
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
    }
}

private struct IdentityFixture {
    let root: PrivateKey
    let field: CertificateFieldName
    let certificate: Certificate
    let limits: IdentityLimits
    let atomic: AtomicBEEF
    let transactionID: TransactionID
}

private func identityFixture(
    type: CertificateTypeID? = nil
) async throws -> IdentityFixture {
    let root = try PrivateKey(Array(repeating: 0, count: 31) + [1])
    let field = try CertificateFieldName("userName")
    let unsigned = try Certificate(
        type: try type ?? KnownIdentityType.x.certificateType,
        serialNumber: try CertificateSerialNumber([UInt8](repeating: 4, count: 32)),
        subject: root.publicKey,
        certifier: root.publicKey,
        revocationOutpoint: Outpoint(
            transactionID: TransactionID(exactDigestBytesGuaranteed: [UInt8](repeating: 0, count: 32)),
            outputIndex: 0
        ),
        fields: [field: try CertificateCiphertext([1, 2, 3])]
    )
    let certificate = try await unsigned.signed(using: ProtoWallet(rootKey: root))
    let limits = try identityLimits()
    let transaction = Transaction(
        outputs: [TransactionOutput(
            satoshis: 1,
            lockingScript: try Script(bytes: [0x51], maximumByteCount: 10_000)
        )]
    )
    let transactionID = try transaction.transactionID(limits: limits.beefLimits.transactionLimits)
    let beef = try BEEF(
        merklePaths: [],
        transactions: [.raw(transaction)],
        limits: limits.beefLimits
    )
    let atomic = try AtomicBEEF(
        subjectTransactionID: transactionID,
        beef: beef,
        limits: limits.beefLimits
    )
    return IdentityFixture(
        root: root,
        field: field,
        certificate: certificate,
        limits: limits,
        atomic: atomic,
        transactionID: transactionID
    )
}

private func identityLimits(
    maximumIdentityCount: Int = 100,
    maximumDisplayText: Int = 2_000,
    maximumJSON: Int = 1_000_000
) throws -> IdentityLimits {
    let transactionLimits = try TransactionLimits(
        maximumTransactionByteCount: 1_000_000,
        maximumInputCount: 10_000,
        maximumOutputCount: 10_000,
        maximumScriptByteCount: 1_000_000
    )
    return try IdentityLimits(
        maximumIdentityCount: maximumIdentityCount,
        maximumFieldsToReveal: 256,
        maximumDisplayTextUTF8ByteCount: maximumDisplayText,
        maximumAggregateDisplayUTF8ByteCount: 2_000_000,
        maximumDisclosureJSONByteCount: maximumJSON,
        certificateLimits: .standard,
        walletLimits: try WalletABILimits(
            maximumTextUTF8ByteCount: 2_000,
            maximumCollectionCount: 10_000,
            maximumTagCount: 1_000,
            maximumLabelCount: 1_000,
            maximumBytePayloadCount: 1_000_000,
            maximumAggregatePayloadByteCount: 2_000_000
        ),
        pushDropLimits: try PushDropLimits(
            maximumFieldCount: 16,
            maximumFieldByteCount: 1_000_000,
            maximumScriptByteCount: 1_000_000
        ),
        beefLimits: try BEEFLimits(
            maximumByteCount: 1_000_000,
            maximumMerklePathCount: 100,
            maximumTransactionCount: 1_000,
            transactionLimits: transactionLimits,
            merklePathLimits: try MerklePathLimits(
                maximumByteCount: 100_000,
                maximumLeavesPerLevel: 100,
                maximumTotalLeaves: 1_000
            )
        )
    )
}

private enum IdentityTestFailure: Error {
    case unexpectedCall
    case secret(String)
}

private struct IdentityWalletSnapshot: Sendable {
    let callCount: Int
    let proveVerifier: PublicKey?
    let action: WalletCreateActionRequest?
}

private actor IdentityWalletState {
    let discovered: [WalletIdentityCertificate]
    let proofKeyring: [CertificateFieldName: CertificateCiphertext]
    let completedTransaction: AtomicBEEF?
    let discoveryFailure: Bool
    let blockDiscovery: Bool
    private var callCount = 0
    private var proveVerifier: PublicKey?
    private var action: WalletCreateActionRequest?

    init(
        discovered: [WalletIdentityCertificate] = [],
        proofKeyring: [CertificateFieldName: CertificateCiphertext] = [:],
        completedTransaction: AtomicBEEF? = nil,
        discoveryFailure: Bool = false,
        blockDiscovery: Bool = false
    ) {
        self.discovered = discovered
        self.proofKeyring = proofKeyring
        self.completedTransaction = completedTransaction
        self.discoveryFailure = discoveryFailure
        self.blockDiscovery = blockDiscovery
    }

    func recordProof(_ verifier: PublicKey) {
        callCount += 1
        proveVerifier = verifier
    }

    func recordAction(_ request: WalletCreateActionRequest) {
        callCount += 1
        action = request
    }

    func recordDiscovery() { callCount += 1 }

    func snapshot() -> IdentityWalletSnapshot {
        IdentityWalletSnapshot(
            callCount: callCount,
            proveVerifier: proveVerifier,
            action: action
        )
    }
}

private struct IdentityTestWallet: WalletInterface {
    let crypto: ProtoWallet
    let state: IdentityWalletState

    init(root: PrivateKey, state: IdentityWalletState) {
        crypto = ProtoWallet(rootKey: root)
        self.state = state
    }

    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult {
        try await crypto.getPublicKey(request)
    }

    func createSignature(_ request: WalletCreateSignatureRequest) async throws -> WalletCreateSignatureResult {
        try await crypto.createSignature(request)
    }

    func proveCertificate(
        _ request: WalletProveCertificateRequest
    ) async throws -> WalletProveCertificateResult {
        await state.recordProof(request.verifier)
        return try WalletProveCertificateResult(keyringForVerifier: state.proofKeyring)
    }

    func createAction(_ request: WalletCreateActionRequest) async throws -> WalletCreateActionResult {
        await state.recordAction(request)
        guard let transaction = state.completedTransaction else {
            throw IdentityTestFailure.secret("secret-action-detail")
        }
        return try WalletCreateActionResult(transaction: transaction)
    }

    func discoverByIdentityKey(
        _ request: WalletDiscoverByIdentityKeyRequest
    ) async throws -> WalletDiscoverCertificatesResult {
        try await discover()
    }

    func discoverByAttributes(
        _ request: WalletDiscoverByAttributesRequest
    ) async throws -> WalletDiscoverCertificatesResult {
        try await discover()
    }

    private func discover() async throws -> WalletDiscoverCertificatesResult {
        await state.recordDiscovery()
        if state.blockDiscovery {
            try await Task.sleep(for: .seconds(60))
        }
        if state.discoveryFailure {
            throw IdentityTestFailure.secret("secret@example.com")
        }
        let certificates = state.discovered
        return try WalletDiscoverCertificatesResult(
            totalCertificates: UInt32(certificates.count),
            certificates: certificates
        )
    }
}

private actor RecordingBroadcaster: Broadcaster {
    let expected: TransactionID
    private var calls = 0

    init(expected: TransactionID) { self.expected = expected }

    func broadcast(_ transaction: Transaction, limits: TransactionLimits) async throws -> BroadcastResult {
        calls += 1
        #expect(try transaction.transactionID(limits: limits) == expected)
        return BroadcastResult(transactionID: expected)
    }

    func callCount() -> Int { calls }
}

private extension WalletActionOperations {
    func createAction(_ request: WalletCreateActionRequest) async throws -> WalletCreateActionResult { throw IdentityTestFailure.unexpectedCall }
    func signAction(_ request: WalletSignActionRequest) async throws -> WalletSignActionResult { throw IdentityTestFailure.unexpectedCall }
    func abortAction(_ request: WalletAbortActionRequest) async throws -> WalletAbortActionResult { throw IdentityTestFailure.unexpectedCall }
    func listActions(_ request: WalletListActionsRequest) async throws -> WalletListActionsResult { throw IdentityTestFailure.unexpectedCall }
    func internalizeAction(_ request: WalletInternalizeActionRequest) async throws -> WalletInternalizeActionResult { throw IdentityTestFailure.unexpectedCall }
}

private extension WalletOutputOperations {
    func listOutputs(_ request: WalletListOutputsRequest) async throws -> WalletListOutputsResult { throw IdentityTestFailure.unexpectedCall }
    func relinquishOutput(_ request: WalletRelinquishOutputRequest) async throws -> WalletRelinquishOutputResult { throw IdentityTestFailure.unexpectedCall }
}

private extension WalletCertificateOperations {
    func acquireCertificate(_ request: WalletAcquireCertificateRequest) async throws -> Certificate { throw IdentityTestFailure.unexpectedCall }
    func listCertificates(_ request: WalletListCertificatesRequest) async throws -> WalletListCertificatesResult { throw IdentityTestFailure.unexpectedCall }
    func proveCertificate(_ request: WalletProveCertificateRequest) async throws -> WalletProveCertificateResult { throw IdentityTestFailure.unexpectedCall }
    func relinquishCertificate(_ request: WalletRelinquishCertificateRequest) async throws -> WalletRelinquishCertificateResult { throw IdentityTestFailure.unexpectedCall }
}

private extension WalletLinkageOperations {
    func revealCounterpartyKeyLinkage(_ request: WalletRevealCounterpartyKeyLinkageRequest) async throws -> WalletRevealCounterpartyKeyLinkageResult { throw IdentityTestFailure.unexpectedCall }
    func revealSpecificKeyLinkage(_ request: WalletRevealSpecificKeyLinkageRequest) async throws -> WalletRevealSpecificKeyLinkageResult { throw IdentityTestFailure.unexpectedCall }
}

private extension WalletDiscoveryOperations {
    func discoverByIdentityKey(_ request: WalletDiscoverByIdentityKeyRequest) async throws -> WalletDiscoverCertificatesResult { throw IdentityTestFailure.unexpectedCall }
    func discoverByAttributes(_ request: WalletDiscoverByAttributesRequest) async throws -> WalletDiscoverCertificatesResult { throw IdentityTestFailure.unexpectedCall }
}

private extension WalletAuthenticationOperations {
    func isAuthenticated(_ request: WalletIsAuthenticatedRequest) async throws -> WalletAuthenticatedResult { throw IdentityTestFailure.unexpectedCall }
    func waitForAuthentication(_ request: WalletWaitForAuthenticationRequest) async throws -> WalletAuthenticatedResult { throw IdentityTestFailure.unexpectedCall }
}

private extension WalletChainInformation {
    func getHeight(_ request: WalletGetHeightRequest) async throws -> WalletGetHeightResult { throw IdentityTestFailure.unexpectedCall }
    func getHeaderForHeight(_ request: WalletGetHeaderRequest) async throws -> WalletGetHeaderResult { throw IdentityTestFailure.unexpectedCall }
    func getNetwork(_ request: WalletGetNetworkRequest) async throws -> WalletGetNetworkResult { throw IdentityTestFailure.unexpectedCall }
    func getVersion(_ request: WalletGetVersionRequest) async throws -> WalletGetVersionResult { throw IdentityTestFailure.unexpectedCall }
}

private extension WalletKeyOperations {
    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult { throw IdentityTestFailure.unexpectedCall }
    func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult { throw IdentityTestFailure.unexpectedCall }
    func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult { throw IdentityTestFailure.unexpectedCall }
    func createHMAC(_ request: WalletCreateHMACRequest) async throws -> WalletCreateHMACResult { throw IdentityTestFailure.unexpectedCall }
    func verifyHMAC(_ request: WalletVerifyHMACRequest) async throws -> WalletVerifyHMACResult { throw IdentityTestFailure.unexpectedCall }
    func createSignature(_ request: WalletCreateSignatureRequest) async throws -> WalletCreateSignatureResult { throw IdentityTestFailure.unexpectedCall }
    func verifySignature(_ request: WalletVerifySignatureRequest) async throws -> WalletVerifySignatureResult { throw IdentityTestFailure.unexpectedCall }
}
