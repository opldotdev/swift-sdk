import BSVCrypto
import BSVKeys
import BSVOverlay
import BSVScript
import BSVTransaction
import Testing

@Suite("Deterministic overlay resolver and broadcaster policy")
struct OverlayPolicyTests {
    @Test("resolver selects and merges explicit hosts in deterministic order")
    func deterministicFreeformResolution() async throws {
        let service = try OverlayService(rawValue: "ls_records")
        let a = try OverlayHost(rawValue: "https://a.example")
        let b = try OverlayHost(rawValue: "https://b.example")
        let z = try OverlayHost(rawValue: "https://z.example")
        let facilitator = OverlayLookupMock(responses: [
            a: .freeform(Array("a".utf8)),
            b: .freeform(Array("b".utf8)),
            z: .freeform(Array("z".utf8)),
        ])
        let resolver = try LookupResolver(
            facilitator: facilitator,
            slapTrackers: [],
            hostOverrides: [service: [z, a]],
            additionalHosts: [service: [b]],
            beefLimits: try beefLimits()
        )

        let answer = try await resolver.resolve(
            LookupQuestion(service: service, query: Array("{}".utf8))
        )
        #expect(answer == .freeform(Array("a".utf8)))
        #expect(await facilitator.requestCount() == 3)
    }

    @Test("resolver discovers only verified SLAP advertisements")
    func verifiedSLAPDiscovery() async throws {
        let tracker = try OverlayHost(rawValue: "https://tracker.example")
        let advertised = try OverlayHost(rawValue: "https://service.example")
        let service = try OverlayService(rawValue: "ls_records")
        let item = try advertisementItem(
            protocolText: "SLAP",
            host: advertised.rawValue,
            subject: service.rawValue,
            keyByte: 3
        )
        let facilitator = OverlayLookupMock(responses: [
            tracker: try LookupAnswer(outputList: [item]),
            advertised: try LookupAnswer(freeform: Array("result".utf8)),
        ])
        let resolver = try LookupResolver(
            facilitator: facilitator,
            slapTrackers: [tracker],
            beefLimits: try beefLimits()
        )

        #expect(try await resolver.competentHosts(for: service) == [advertised])
        #expect(
            try await resolver.resolve(
                LookupQuestion(service: service, query: Array("{}".utf8))
            ) == .freeform(Array("result".utf8))
        )
    }

    @Test("resolver rejects mixed answer representations")
    func rejectsMixedAnswers() async throws {
        let service = try OverlayService(rawValue: "ls_records")
        let a = try OverlayHost(rawValue: "https://a.example")
        let b = try OverlayHost(rawValue: "https://b.example")
        let facilitator = OverlayLookupMock(responses: [
            a: try LookupAnswer(freeform: [1]),
            b: try LookupAnswer(outputList: []),
        ])
        let resolver = try LookupResolver(
            facilitator: facilitator,
            slapTrackers: [],
            hostOverrides: [service: [a, b]],
            beefLimits: try beefLimits()
        )
        await #expect(throws: OverlayPolicyError.inconsistentAnswerTypes) {
            _ = try await resolver.resolve(LookupQuestion(service: service, query: []))
        }
    }

    @Test("resolver deduplicates and sorts output-list answers")
    func deterministicOutputMerge() async throws {
        let service = try OverlayService(rawValue: "ls_records")
        let a = try OverlayHost(rawValue: "https://a.example")
        let b = try OverlayHost(rawValue: "https://b.example")
        let first = try advertisementItem(
            protocolText: "SLAP",
            host: "https://first.example",
            subject: service.rawValue,
            keyByte: 7
        )
        let second = try advertisementItem(
            protocolText: "SLAP",
            host: "https://second.example",
            subject: service.rawValue,
            keyByte: 8
        )
        let facilitator = OverlayLookupMock(responses: [
            a: try LookupAnswer(outputList: [second, first]),
            b: try LookupAnswer(outputList: [first]),
        ])
        let limits = try beefLimits()
        let resolver = try LookupResolver(
            facilitator: facilitator,
            slapTrackers: [],
            hostOverrides: [service: [b, a]],
            beefLimits: limits
        )

        let answer = try await resolver.resolve(LookupQuestion(service: service, query: []))
        guard case .outputList(let outputs) = answer else {
            Issue.record("Expected an output-list answer")
            return
        }
        #expect(outputs.count == 2)
        let transactionIDs = try outputs.map { output in
            let beef = try BEEF(bytes: output.beef, limits: limits)
            return try #require(beef.transactions.last?.transaction)
                .transactionID(limits: limits.transactionLimits)
                .displayHex
        }
        #expect(transactionIDs == transactionIDs.sorted())
    }

    @Test("topic broadcaster submits once per verified SHIP host")
    func verifiedSHIPBroadcast() async throws {
        let topic = try OverlayTopic(rawValue: "tm_records")
        let a = try OverlayHost(rawValue: "https://a.example")
        let z = try OverlayHost(rawValue: "https://z.example")
        let discovery = try LookupAnswer(outputList: [
            advertisementItem(
                protocolText: "SHIP",
                host: z.rawValue,
                subject: topic.rawValue,
                keyByte: 4
            ),
            advertisementItem(
                protocolText: "SHIP",
                host: a.rawValue,
                subject: topic.rawValue,
                keyByte: 5
            ),
        ])
        let resolver = OverlayResolverMock(answer: discovery)
        let instructions = try AdmittanceInstructions(outputsToAdmit: [0])
        let facilitator = OverlayTopicMock(
            steaks: [
                a: try Steak(instructions: [topic: instructions]),
                z: try Steak(instructions: [topic: instructions]),
            ]
        )
        let limits = try beefLimits()
        let atomic = try atomicBEEF(limits: limits)
        let broadcaster = try OverlayTopicBroadcaster(
            topics: [topic],
            facilitator: facilitator,
            resolver: resolver,
            beefLimits: limits
        )

        let result = try await broadcaster.broadcast(atomic)
        #expect(result.transactionID == atomic.subjectTransactionID)
        #expect(await facilitator.submittedHosts() == Set([a, z]))
        #expect(await facilitator.submissionCount() == 2)
    }

    @Test("acknowledgment failure and submission failure are distinct")
    func acknowledgmentAndUncertainty() async throws {
        let topic = try OverlayTopic(rawValue: "tm_records")
        let host = try OverlayHost(rawValue: "https://host.example")
        let discovery = try LookupAnswer(outputList: [
            advertisementItem(
                protocolText: "SHIP",
                host: host.rawValue,
                subject: topic.rawValue,
                keyByte: 6
            )
        ])
        let resolver = OverlayResolverMock(answer: discovery)
        let limits = try beefLimits()
        let atomic = try atomicBEEF(limits: limits)

        let noAck = OverlayTopicMock(steaks: [host: try Steak()])
        let noAckBroadcaster = try OverlayTopicBroadcaster(
            topics: [topic],
            facilitator: noAck,
            resolver: resolver,
            beefLimits: limits
        )
        await #expect(throws: OverlayPolicyError.acknowledgmentFailed) {
            _ = try await noAckBroadcaster.broadcast(atomic)
        }

        let failing = OverlayTopicMock(steaks: [:], failingHosts: [host])
        let uncertainBroadcaster = try OverlayTopicBroadcaster(
            topics: [topic],
            facilitator: failing,
            resolver: resolver,
            beefLimits: limits
        )
        await #expect(throws: OverlayPolicyError.uncertainDelivery) {
            _ = try await uncertainBroadcaster.broadcast(atomic)
        }
    }

    @Test("resolver host ceilings apply before facilitator calls")
    func hostLimit() async throws {
        let limits = try overlayLimits(maximumHosts: 1)
        let service = try OverlayService(rawValue: "ls_records", limits: limits)
        let first = try OverlayHost(rawValue: "https://a.example", limits: limits)
        let second = try OverlayHost(rawValue: "https://b.example", limits: limits)
        let facilitator = OverlayLookupMock(responses: [:])
        #expect(
            throws: OverlayError.limitExceeded(
                name: "resolvedHosts",
                actual: 2,
                maximum: 1
            )
        ) {
            _ = try LookupResolver(
                facilitator: facilitator,
                slapTrackers: [],
                hostOverrides: [service: [first, second]],
                beefLimits: try beefLimits(),
                limits: limits
            )
        }
        #expect(await facilitator.requestCount() == 0)
    }

    private func advertisementItem(
        protocolText: String,
        host: String,
        subject: String,
        keyByte: UInt8
    ) throws -> OutputListItem {
        let identityKey = try PrivateKey(Array(repeating: 0, count: 31) + [keyByte])
        let lockingKey = try PrivateKey(Array(repeating: 0, count: 31) + [keyByte + 20])
        let fields = [
            Array(protocolText.utf8),
            identityKey.publicKey.compressedBytes,
            Array(host.utf8),
            Array(subject.utf8),
        ]
        let signature = try lockingKey.sign(digest: BSVHashing.sha256(fields.flatMap { $0 }))
        let script = try PushDrop.lockingScript(
            fields: fields + [signature.derBytes],
            publicKey: lockingKey.publicKey,
            lockPosition: .beforeCompatibility
        )
        let transaction = Transaction(
            outputs: [TransactionOutput(satoshis: 1, lockingScript: script)]
        )
        let limits = try beefLimits()
        let beef = try BEEF(
            version: .v2,
            merklePaths: [],
            transactions: [.raw(transaction)],
            limits: limits
        )
        return try OutputListItem(
            beef: beef.serialized(limits: limits),
            outputIndex: 0
        )
    }

    private func atomicBEEF(limits: BEEFLimits) throws -> AtomicBEEF {
        let script = try Script(bytes: [0x51], maximumByteCount: 1)
        let transaction = Transaction(
            outputs: [TransactionOutput(satoshis: 1, lockingScript: script)]
        )
        let transactionID = try transaction.transactionID(limits: limits.transactionLimits)
        let beef = try BEEF(
            version: .v2,
            merklePaths: [],
            transactions: [.raw(transaction)],
            limits: limits
        )
        return try AtomicBEEF(
            subjectTransactionID: transactionID,
            beef: beef,
            limits: limits
        )
    }

    private func beefLimits() throws -> BEEFLimits {
        let transactionLimits = try TransactionLimits(
            maximumTransactionByteCount: 1_000_000,
            maximumInputCount: 1_000,
            maximumOutputCount: 1_000,
            maximumScriptByteCount: 100_000
        )
        return try BEEFLimits(
            maximumByteCount: 32 * 1_024 * 1_024,
            maximumMerklePathCount: 1_000,
            maximumTransactionCount: 1_000,
            transactionLimits: transactionLimits,
            merklePathLimits: try MerklePathLimits(
                maximumByteCount: 1_000_000,
                maximumLeavesPerLevel: 1_000,
                maximumTotalLeaves: 1_000
            )
        )
    }

    private func overlayLimits(maximumHosts: Int) throws -> OverlayLimits {
        try OverlayLimits(
            maximumTaggedBEEFByteCount: 32 * 1_024 * 1_024,
            maximumOffChainValueByteCount: 1_024,
            maximumTopicCount: 16,
            maximumTopicUTF8ByteCount: 256,
            maximumServiceUTF8ByteCount: 256,
            maximumHostUTF8ByteCount: 2_048,
            maximumMetadataUTF8ByteCount: 4_096,
            maximumLookupQueryByteCount: 1_024,
            maximumLookupOutputCount: 16,
            maximumLookupOutputBEEFByteCount: 32 * 1_024 * 1_024,
            maximumFreeformByteCount: 1_024,
            maximumResolutionHostCount: maximumHosts,
            maximumConcurrentRequestCount: 1
        )
    }
}

private actor OverlayLookupMock: LookupFacilitator {
    private let responses: [OverlayHost: LookupAnswer]
    private var count = 0

    init(responses: [OverlayHost: LookupAnswer]) {
        self.responses = responses
    }

    func lookup(question: LookupQuestion, at host: OverlayHost) async throws -> LookupAnswer {
        count += 1
        guard let answer = responses[host] else { throw OverlayPolicyMockError.failed }
        return answer
    }

    func requestCount() -> Int { count }
}

private struct OverlayResolverMock: OverlayLookupResolving {
    let answer: LookupAnswer

    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer { answer }
}

private actor OverlayTopicMock: TopicFacilitator {
    private let steaks: [OverlayHost: Steak]
    private let failingHosts: Set<OverlayHost>
    private var hosts: [OverlayHost] = []

    init(steaks: [OverlayHost: Steak], failingHosts: Set<OverlayHost> = []) {
        self.steaks = steaks
        self.failingHosts = failingHosts
    }

    func submit(_ taggedBEEF: TaggedBEEF, to host: OverlayHost) async throws -> Steak {
        hosts.append(host)
        if failingHosts.contains(host) { throw OverlayPolicyMockError.failed }
        guard let steak = steaks[host] else { throw OverlayPolicyMockError.failed }
        return steak
    }

    func submittedHosts() -> Set<OverlayHost> { Set(hosts) }
    func submissionCount() -> Int { hosts.count }
}

private enum OverlayPolicyMockError: Error {
    case failed
}
