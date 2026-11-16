@testable import BSVIdentity
import BSVCore
import BSVCrypto
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

    @Test("public disclosure proves to the anyone verifier and writes canonical bounded JSON")
    func revealsAttributes() async throws {
        let fixture = try await identityFixture()
        let state = IdentityWalletState(
            proofKeyring: [fixture.field: try CertificateCiphertext([7, 8, 9])],
            completedTransaction: fixture.atomic
        )
        let wallet = IdentityTestWallet(root: fixture.root, state: state)
        let client = try IdentityClient(wallet: wallet, limits: fixture.limits)
        let broadcaster = RecordingBroadcaster(expected: fixture.transactionID)

        let result = try await client.publiclyRevealAttributes(
            certificate: fixture.certificate,
            fieldsToReveal: [fixture.field],
            using: broadcaster
        )
        #expect(result.transactionID == fixture.transactionID)
        let snapshot = await state.snapshot()
        // TypeScript identity/IdentityClient.ts:471-477 fixes the verifier.
        #expect(
            snapshot.proveVerifier.map { Hex.encode($0.compressedBytes) }
                == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        #expect(
            try IdentityPublicReveal.verifierPublicKey().compressedBytes
                == Hex.decode(IdentityPublicReveal.verifierPublicKeyHex, maximumDecodedByteCount: 33))
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

    /// A certificate signed by `@bsv/sdk` 4.1.1 `Certificate.sign`, whose
    /// fields TypeScript orders with `localeCompare`
    /// (`auth/certificates/Certificate.ts:290`): names differ from byte order
    /// in case, accents, underscores and digits. TypeScript
    /// `IdentityClient.publiclyRevealAttributes` verifies it
    /// (`identity/IdentityClient.ts:461`); so must this client. From
    /// `certorder-vec.ts` (Documentation/Compatibility/TypeScriptAuthVectors.md).
    @Test("public disclosure accepts a certificate TypeScript signed in localeCompare order")
    func revealsTypeScriptCertificate() async throws {
        let fixture = try await identityFixture()
        let certificate = try Certificate(json: Array(Self.typeScriptCertificateJSON.utf8))
        let field = try CertificateFieldName("résumé")
        let subject = try PrivateKey(Array(repeating: 0, count: 31) + [7])
        #expect(certificate.subject == subject.publicKey)
        let state = IdentityWalletState(
            proofKeyring: [field: try CertificateCiphertext([7, 8, 9])],
            completedTransaction: fixture.atomic
        )
        let client = try IdentityClient(
            wallet: IdentityTestWallet(root: subject, state: state),
            limits: fixture.limits
        )
        let result = try await client.publiclyRevealAttributes(
            certificate: certificate,
            fieldsToReveal: [field],
            using: RecordingBroadcaster(expected: fixture.transactionID)
        )
        #expect(result.transactionID == fixture.transactionID)
        #expect(await state.snapshot().action != nil)
    }

    private static let typeScriptCertificateJSON =
        #"{"type":"MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=","serialNumber":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI=","subject":"025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc","certifier":"03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb","revocationOutpoint":"0000000000000000000000000000000000000000000000000000000000000000.0","fields":{"Zip":"AQ==","zip_code":"Ag==","zip-code":"Aw==","zip2":"BA==","zip10":"BQ==","Zeta":"Bg==","email":"Bw==","eMail":"CA==","Email":"CQ==","_id":"Cg==","id":"Cw==","ID":"DA==","a1":"DQ==","a_1":"Dg==","a-1":"Dw==","aB":"EA==","ab":"EQ==","cafe":"Eg==","café":"Ew==","Café":"FA==","cafés":"FQ==","émile":"Fg==","Émile":"Fw==","naïve":"GA==","nausea":"GQ==","résumé":"Gg==","resume":"Gw==","zoë":"HA==","Ångström":"HQ==","angle":"Hg=="},"signature":"30440220414ba43586646efbbb901e48680c419bb5de91ec1730ef99f7602bda95c1711b02204aa129d5d7bb3d1d2c5865243d48a9f84a34dbeab5b58f8ce06c6d9d0e607969"}"#

    /// The token must pass the TypeScript tm_identity topic manager
    /// (packages/overlays/topics/src/identity/identityTokenValidation.ts):
    /// exactly two fields in a five-chunk script, locked to the anyone key's
    /// view of the subject under [1, "identity"], key ID "1", and signed by
    /// the same key over the certificate JSON.
    @Test("disclosure token matches the TypeScript tm_identity rules")
    func disclosureTokenMatchesTopicManager() async throws {
        let subject = try PrivateKey(Array(repeating: 0, count: 31) + [0x5c])
        let fixture = try await identityFixture(root: subject)
        let state = IdentityWalletState(
            proofKeyring: [fixture.field: try CertificateCiphertext([7, 8, 9])],
            completedTransaction: fixture.atomic
        )
        let client = try IdentityClient(
            wallet: IdentityTestWallet(root: subject, state: state),
            limits: fixture.limits
        )
        #expect(
            client.options.protocolID
                == (try WalletProtocolID(securityLevel: .everyApp, name: "identity")))
        _ = try await client.publiclyRevealAttributes(
            certificate: fixture.certificate,
            fieldsToReveal: [fixture.field],
            using: RecordingBroadcaster(expected: fixture.transactionID)
        )
        let output = try #require(await state.snapshot().action?.outputs?.first)
        let decoded = try PushDrop.decode(
            try Script(bytes: output.lockingScript, maximumByteCount: 1_000_000),
            lockPosition: .beforeCompatibility,
            limits: fixture.limits.pushDropLimits
        )
        #expect(decoded.fields.count == 2)
        // <33 key> OP_CHECKSIG <json> <signature> OP_2DROP: five chunks.
        #expect(output.lockingScript.first == 0x21)
        #expect(output.lockingScript[34] == 0xac)
        #expect(output.lockingScript.last == 0x6d)

        let anyone = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        let expectedKey = try subject.publicKey.derivedChild(
            with: anyone,
            invoiceNumber: "1-identity-1"
        )
        #expect(decoded.publicKey == expectedKey)
        let signature = try ECDSASignature(derBytes: decoded.fields[1])
        #expect(expectedKey.verify(signature, digest: BSVHashing.sha256(decoded.fields[0])))

        // The previous Swift default, [2, "identity"], locks to another key.
        let levelTwoKey = try subject.publicKey.derivedChild(
            with: anyone,
            invoiceNumber: "2-identity-1"
        )
        #expect(decoded.publicKey != levelTwoKey)
    }

    /// The locking key `@bsv/sdk` 4.1.1 itself (ts-stack `3b1abc569`, run
    /// under bun) gives a public reveal by the identity of `PrivateKey(42)`:
    ///
    /// ```ts
    /// const { PrivateKey, ProtoWallet } = await import(`${process.env.TS_SDK}/mod.ts`)
    /// const wallet = new ProtoWallet(new PrivateKey(42))
    /// const { publicKey } = await wallet.getPublicKey({
    ///   protocolID: [1, 'identity'], keyID: '1', counterparty: 'anyone', forSelf: true
    /// }) // IdentityClient: pushdrop.lock(fields, [1, 'identity'], '1', 'anyone', true)
    /// ```
    @Test("disclosure locking key matches the key TypeScript generates")
    func disclosureLockingKeyMatchesTypeScriptVector() async throws {
        let typeScriptKey = "034009190eadccbea812a05e818ecf8a77e29b9d886008f8a428c247fccec9a2d8"
        let subject = try PrivateKey(Array(repeating: 0, count: 31) + [42])
        let options = try IdentityClientOptions()

        // Swift's wallet path with the default options.
        let walletKey = try await ProtoWallet(rootKey: subject).getPublicKey(.init(
            selection: .derived(
                protocolID: options.protocolID,
                keyID: options.keyID,
                counterparty: .anyone,
                forSelf: true
            )
        )).publicKey
        #expect(Hex.encode(walletKey.compressedBytes) == typeScriptKey)

        // The token IdentityClient writes is locked to that key.
        let fixture = try await identityFixture(root: subject)
        let state = IdentityWalletState(
            proofKeyring: [fixture.field: try CertificateCiphertext([7, 8, 9])],
            completedTransaction: fixture.atomic
        )
        let client = try IdentityClient(
            wallet: IdentityTestWallet(root: subject, state: state),
            limits: fixture.limits
        )
        _ = try await client.publiclyRevealAttributes(
            certificate: fixture.certificate,
            fieldsToReveal: [fixture.field],
            using: RecordingBroadcaster(expected: fixture.transactionID)
        )
        let output = try #require(await state.snapshot().action?.outputs?.first)
        let decoded = try PushDrop.decode(
            try Script(bytes: output.lockingScript, maximumByteCount: 1_000_000),
            lockPosition: .beforeCompatibility,
            limits: fixture.limits.pushDropLimits
        )
        #expect(Hex.encode(decoded.publicKey.compressedBytes) == typeScriptKey)
    }

    @Test("badge links match the TypeScript identity client")
    func badgeLinksMatchTypeScript() async throws {
        let fixture = try await identityFixture()
        let link = "https://bsv-blockchain.github.io/ts-sdk/reference/identity/"
        for kind in [KnownIdentityType.registrant, .anyone, .self] {
            let certificate = try Certificate(
                type: try kind.certificateType,
                serialNumber: fixture.certificate.serialNumber,
                subject: fixture.root.publicKey,
                certifier: fixture.root.publicKey,
                revocationOutpoint: fixture.certificate.revocationOutpoint,
                fields: fixture.certificate.fields
            )
            let parsed = try IdentityParser.parse(
                try WalletIdentityCertificate(
                    certificate: certificate,
                    certifierInfo: try WalletIdentityCertifier(
                        name: "Certifier", iconURL: "icon", description: "description", trust: 1
                    ),
                    publiclyRevealedKeyring: [:],
                    decryptedFields: [try CertificateFieldName("name"): "Entity"]
                ),
                limits: fixture.limits
            )
            #expect(parsed.badgeClickURL == link)
        }
        #expect(try DisplayableIdentity.unknown(limits: fixture.limits).badgeClickURL == link)
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
    type: CertificateTypeID? = nil,
    root: PrivateKey? = nil
) async throws -> IdentityFixture {
    let root = try root ?? PrivateKey(Array(repeating: 0, count: 31) + [1])
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
