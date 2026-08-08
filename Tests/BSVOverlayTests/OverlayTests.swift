import BSVCore
import BSVOverlay
import BSVTransaction
import Testing

@Suite("Transport-neutral overlay values")
struct OverlayTests {
    @Test("SHIP and SLAP protocol identifiers and network names are exact")
    func protocolValues() {
        #expect(OverlayProtocol.ship.identifier == .ship)
        #expect(OverlayProtocol.slap.identifier == .slap)
        #expect(OverlayProtocolIdentifier.ship.rawValue == "service host interconnect")
        #expect(OverlayProtocolIdentifier.slap.rawValue == "service lookup availability")
        #expect(OverlayNetwork.mainnet.rawValue == "mainnet")
        #expect(OverlayNetwork.testnet.rawValue == "testnet")
        #expect(OverlayNetwork.local.rawValue == "local")
    }

    @Test("topic and service identifiers fail closed")
    func identifierValidation() throws {
        #expect(try OverlayTopic(rawValue: "tm_payments").rawValue == "tm_payments")
        #expect(try OverlayService(rawValue: "ls_slap").rawValue == "ls_slap")
        #expect(throws: OverlayError.invalidTopic) {
            _ = try OverlayTopic(rawValue: "payments")
        }
        #expect(throws: OverlayError.invalidService) {
            _ = try OverlayService(rawValue: "LS_slap")
        }
    }

    @Test("tagged BEEF bounds all caller-owned collections and values")
    func taggedBEEFBounds() throws {
        let topic = try OverlayTopic(rawValue: "tm_test")
        let value = try TaggedBEEF(beef: [1], topics: [topic])
        #expect(value.topics == [topic])
        #expect(throws: OverlayError.emptyValue(name: "beef")) {
            _ = try TaggedBEEF(beef: [], topics: [topic])
        }
        #expect(throws: OverlayError.duplicateValue(name: "topics")) {
            _ = try TaggedBEEF(beef: [1], topics: [topic, topic])
        }
        let limits = try OverlayLimits(
            maximumTaggedBEEFByteCount: 1,
            maximumOffChainValueByteCount: 1,
            maximumTopicCount: 1,
            maximumTopicUTF8ByteCount: 32,
            maximumServiceUTF8ByteCount: 32,
            maximumHostUTF8ByteCount: 32,
            maximumMetadataUTF8ByteCount: 32,
            maximumLookupQueryByteCount: 1,
            maximumLookupOutputCount: 1,
            maximumLookupOutputBEEFByteCount: 1,
            maximumFreeformByteCount: 1
        )
        #expect(throws: OverlayError.limitExceeded(name: "beef", actual: 2, maximum: 1)) {
            _ = try TaggedBEEF(beef: [1, 2], topics: [topic], limits: limits)
        }
    }

    @Test("lookup values remain opaque and bounded without type erasure")
    func lookupValues() throws {
        let service = try OverlayService(rawValue: "ls_slap")
        let question = try LookupQuestion(service: service, query: [0x7b, 0x7d])
        #expect(question.query == [0x7b, 0x7d])
        let output = try OutputListItem(beef: [1], outputIndex: 2)
        let answer = try LookupAnswer(outputList: [output])
        #expect(answer == .outputList([output]))
        #expect(try LookupAnswer(freeform: [0]) == .freeform([0]))
    }

    @Test("topic acknowledgments are strongly typed")
    func acknowledgments() throws {
        let topic = try OverlayTopic(rawValue: "tm_test")
        let transactionID = try TransactionID(wireBytes: Array(repeating: 1, count: 32))
        let instructions = try AdmittanceInstructions(
            outputsToAdmit: [0],
            ancillaryTransactionIDs: [transactionID]
        )
        let steak = try Steak(instructions: [topic: instructions])
        #expect(steak.acknowledges(topic))
        #expect(try AckFrom(requirement: .some, topics: [topic]).topics == [topic])
        #expect(throws: OverlayError.emptyValue(name: "topics")) {
            _ = try AckFrom(requirement: .some)
        }
    }

    @Test("nested overlay collections enforce exact limits and reject duplicates")
    func nestedCollectionBounds() throws {
        let limits = try limitsWithSingleElementCollections()
        let transactionID = try TransactionID(wireBytes: Array(repeating: 1, count: 32))
        let secondTransactionID = try TransactionID(wireBytes: Array(repeating: 2, count: 32))
        let firstOutpoint = Outpoint(transactionID: transactionID, outputIndex: 0)
        let secondOutpoint = Outpoint(transactionID: transactionID, outputIndex: 1)

        #expect(
            try TopicData(payload: "value", dependencies: [firstOutpoint], limits: limits)
                .dependencies == [firstOutpoint]
        )
        #expect(throws: OverlayError.limitExceeded(name: "dependencies", actual: 2, maximum: 1)) {
            _ = try TopicData(
                payload: "value",
                dependencies: [firstOutpoint, secondOutpoint],
                limits: limits
            )
        }
        #expect(throws: OverlayError.duplicateValue(name: "dependencies")) {
            _ = try TopicData(
                payload: "value",
                dependencies: [firstOutpoint, firstOutpoint],
                limits: OverlayLimits.standard
            )
        }

        #expect(
            try AdmittanceInstructions(
                outputsToAdmit: [0],
                ancillaryTransactionIDs: [transactionID],
                limits: limits
            ).outputsToAdmit == [0]
        )
        #expect(throws: OverlayError.limitExceeded(name: "outputsToAdmit", actual: 2, maximum: 1)) {
            _ = try AdmittanceInstructions(outputsToAdmit: [0, 1], limits: limits)
        }
        #expect(
            throws: OverlayError.limitExceeded(
                name: "ancillaryTransactionIDs",
                actual: 2,
                maximum: 1
            )
        ) {
            _ = try AdmittanceInstructions(
                ancillaryTransactionIDs: [transactionID, secondTransactionID],
                limits: limits
            )
        }
    }

    @Test("lookup answers, steaks, and acknowledgments enforce aggregate limits")
    func aggregateBounds() throws {
        let limits = try limitsWithSingleElementCollections()
        let firstTopic = try OverlayTopic(rawValue: "tm_one")
        let secondTopic = try OverlayTopic(rawValue: "tm_two")
        let output = try OutputListItem(beef: [1], outputIndex: 0, limits: limits)

        #expect(try LookupAnswer(outputList: [output], limits: limits) == .outputList([output]))
        #expect(throws: OverlayError.limitExceeded(name: "lookupAnswer", actual: 2, maximum: 1)) {
            _ = try LookupAnswer(outputList: [output, output], limits: limits)
        }

        let instructions = try AdmittanceInstructions(outputsToAdmit: [0], limits: limits)
        #expect(
            try Steak(instructions: [firstTopic: instructions], limits: limits).acknowledges(
                firstTopic))
        #expect(throws: OverlayError.limitExceeded(name: "steakTopics", actual: 2, maximum: 1)) {
            _ = try Steak(
                instructions: [firstTopic: instructions, secondTopic: instructions],
                limits: limits
            )
        }
        #expect(throws: OverlayError.limitExceeded(name: "topics", actual: 2, maximum: 1)) {
            _ = try AckFrom(requirement: .all, topics: [firstTopic, secondTopic], limits: limits)
        }
        #expect(throws: OverlayError.duplicateValue(name: "topics")) {
            _ = try AckFrom(requirement: .all, topics: [firstTopic, firstTopic])
        }
    }

    @Test("identifier limits take precedence and errors do not retain rejected input")
    func identifierLimitPrecedenceAndPrivacy() throws {
        let limits = try limitsWithSingleElementCollections()
        let rejected = "not_a_topic"
        #expect(throws: OverlayError.limitExceeded(name: "topic", actual: 11, maximum: 8)) {
            _ = try OverlayTopic(rawValue: rejected, limits: limits)
        }
        let error = OverlayError.invalidTopic
        #expect(!String(reflecting: error).contains(rejected))
    }

    @Test("binary overlay values redact descriptions and reflection")
    func binaryValueRedaction() throws {
        let marker = 173
        let markerText = String(marker)
        let topic = try OverlayTopic(rawValue: "tm_test")
        let service = try OverlayService(rawValue: "ls_test")
        let values: [Any] = [
            try TaggedBEEF(beef: [UInt8(marker)], topics: [topic]),
            try LookupQuestion(service: service, query: [UInt8(marker)]),
            try OutputListItem(beef: [UInt8(marker)], outputIndex: 0),
            try LookupAnswer(freeform: [UInt8(marker)]),
            try TopicData(payload: [UInt8(marker)]),
        ]

        for value in values {
            #expect(!String(describing: value).contains(markerText))
            #expect(!String(reflecting: value).contains(markerText))
            var dumped = ""
            dump(value, to: &dumped)
            #expect(!dumped.contains(markerText))
        }
    }

    @Test("overlay public values are Sendable")
    func sendable() async throws {
        let topic = try OverlayTopic(rawValue: "tm_test")
        let service = try OverlayService(rawValue: "ls_slap")
        let host = try OverlayHost(rawValue: "overlay.example")
        acceptSendable(OverlayLimits.standard)
        acceptSendable(topic)
        acceptSendable(service)
        acceptSendable(host)
        acceptSendable(try LookupQuestion(service: service, query: []))
        acceptSendable(try TaggedBEEF(beef: [1], topics: [topic]))
    }

    private func acceptSendable<T: Sendable>(_ value: T) {}

    private func limitsWithSingleElementCollections() throws -> OverlayLimits {
        try OverlayLimits(
            maximumTaggedBEEFByteCount: 1,
            maximumOffChainValueByteCount: 1,
            maximumTopicCount: 1,
            maximumTopicUTF8ByteCount: 8,
            maximumServiceUTF8ByteCount: 8,
            maximumHostUTF8ByteCount: 32,
            maximumMetadataUTF8ByteCount: 32,
            maximumLookupQueryByteCount: 1,
            maximumLookupOutputCount: 2,
            maximumLookupOutputBEEFByteCount: 1,
            maximumLookupAnswerByteCount: 1,
            maximumFreeformByteCount: 1,
            maximumDependencyCount: 1,
            maximumInstructionIndexCount: 1,
            maximumAncillaryTransactionCount: 1,
            maximumSteakTopicCount: 1
        )
    }
}
