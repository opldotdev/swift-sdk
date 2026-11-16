import BSVCore
import BSVTransaction
@testable import BSVWallet
import Testing

@Suite("Wallet-wire action hostile input")
struct WalletWireActionAdversarialTests {
    @Test func boundedWriterRejectsAppendBeforeDestinationGrowth() throws {
        var writer = WalletWireWriter(maximumByteCount: 3)
        writer.writeBytes([1, 2, 3, 4])
        #expect(writer.bytes.isEmpty)
        #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "test payload", actual: 4, maximum: 3
        )) {
            try writer.requireWithinLimit(kind: "test payload")
        }
    }

    @Test func rejectsNoncanonicalAndHostileCountsBeforeCollectionWork() throws {
        let negativeOne = [UInt8](repeating: 0xff, count: 9)
        let hostileInputs = actionWireBytes([[1, 0, 0], negativeOne, [0xfd, 0x11, 0x27]])
        #expect(throws: WalletWireError.countLimitExceeded(
            kind: "inputs", actual: 10_001, maximum: 10_000
        )) {
            try WalletWireCodec.decodeActionRequest(
                hostileInputs, beefLimits: actionBEEFLimits()
            )
        }

        let noncanonical = [UInt8](arrayLiteral: 4, 0, 0xfd, 0, 0)
        #expect(throws: WalletWireError.noncanonicalCompactSize) {
            try WalletWireCodec.decodeActionRequest(
                noncanonical, beefLimits: actionBEEFLimits()
            )
        }
    }

    @Test func acceptsUnsortedSpendsButRejectsDuplicatesAndInvalidDiscriminators() throws {
        let negativeOne = [UInt8](repeating: 0xff, count: 9)
        // `@bsv/sdk` writes spends in `Object.keys(args.spends)` order
        // (packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:357),
        // so an unsorted index list is legitimate traffic.
        let unsorted = actionWireBytes([
            [2, 0, 2, 2, 0], negativeOne, [1, 0], negativeOne, [0, 0],
        ])
        #expect(throws: Never.self) {
            try WalletWireCodec.decodeActionRequest(unsorted, beefLimits: actionBEEFLimits())
        }
        let duplicate = actionWireBytes([
            [2, 0, 2, 1, 0], negativeOne, [1, 0], negativeOne, [0, 0],
        ])
        #expect(throws: WalletWireError.nonRoundTrippableValue(kind: "duplicate spend index")) {
            try WalletWireCodec.decodeActionRequest(duplicate, beefLimits: actionBEEFLimits())
        }

        // listOutputs: basket "", no tags, tag query mode 3, then absent include,
        // include flags, limit, offset and seekPermission.
        let invalidMode = actionWireBytes([
            [6, 0, 0, 0, 3, 0xff, 0xff, 0xff, 0xff], negativeOne, negativeOne, [0xff],
        ])
        #expect(throws: WalletWireError.invalidDiscriminator(
            kind: "tag query mode", value: 3
        )) {
            try WalletWireCodec.decodeActionRequest(
                invalidMode, beefLimits: actionBEEFLimits()
            )
        }
    }

    @Test func rejectsTruncationAndTrailingBytesForEveryEmptyResult() throws {
        let truncated = actionWireBytes([[7, 0, 0], [UInt8](repeating: 0, count: 31)])
        #expect(throws: WalletWireError.truncated) {
            try WalletWireCodec.decodeActionRequest(
                truncated, beefLimits: actionBEEFLimits()
            )
        }
        for call in [WalletCall.abortAction, .internalizeAction, .relinquishOutput] {
            #expect(throws: WalletWireError.trailingBytes) {
                try WalletWireCodec.decodeActionResult(
                    [0, 1], expectedCall: call, beefLimits: actionBEEFLimits()
                )
            }
        }
    }

    @Test func rejectsInvalidBEEFAndAcceptsAbsentCreateActionParts() throws {
        let invalidAtomic = [UInt8](arrayLiteral: 5, 0, 1, 0, 0, 0, 0, 0xff)
        #expect(throws: WalletWireError.nonRoundTrippableValue(kind: "Atomic BEEF")) {
            try WalletWireCodec.decodeActionRequest(
                invalidAtomic, beefLimits: actionBEEFLimits()
            )
        }

        // `@bsv/sdk` 4.1.1 createAction result with every part absent
        // (WalletWireProcessor.ts createAction: txid flag 0, tx flag 0,
        // noSendChange -1, sendWithResults -1, signableTransaction flag 0). G3.
        let negativeOne = [UInt8](repeating: 0xff, count: 9)
        let empty = actionWireBytes([[0, 0, 0], negativeOne, negativeOne, [0]])
        let decoded = try WalletWireCodec.decodeActionResult(
            empty, expectedCall: .createAction, beefLimits: actionBEEFLimits()
        )
        guard case .createAction(let result) = decoded else {
            Issue.record("expected a createAction result")
            return
        }
        #expect(result.transactionID == nil)
        #expect(result.signableTransaction == nil)
        #expect(try WalletWireCodec.encodeActionResult(decoded, beefLimits: actionBEEFLimits()) == empty)

        // The Go wire's extra leading byte is no longer read: [0, 0, 0] stops
        // at the sendWithResults count.
        #expect(throws: WalletWireError.truncated) {
            try WalletWireCodec.decodeActionResult(
                [0, 0, 0], expectedCall: .createAction, beefLimits: actionBEEFLimits()
            )
        }
    }

    @Test func answersAbortRefusalInBandAndAllowsShortPages() throws {
        // `@bsv/sdk` 4.1.1 refuses an abort with code 8 and a fixed message
        // (packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:817), and
        // its transceiver maps code 8 to `aborted: false`
        // (WalletWireTransceiver.ts:412). W5.
        let message = "The wallet refused to abort this action because it has already been broadcast"
        let refusal = try WalletWireCodec.encodeActionResult(
            .abortAction(WalletAbortActionResult(aborted: false)),
            beefLimits: actionBEEFLimits()
        )
        #expect(refusal == [8, UInt8(message.utf8.count)] + Array(message.utf8) + [0])
        let decodedRefusal = try WalletWireCodec.decodeActionResult(
            refusal, expectedCall: .abortAction, beefLimits: actionBEEFLimits()
        )
        guard case .abortAction(let abort) = decodedRefusal else {
            Issue.record("expected an abortAction result")
            return
        }
        #expect(abort.aborted == false)

        // A page shorter than its total is an ordinary paginated answer.
        let shortPage = try WalletListActionsResult(totalActions: 1, actions: [])
        #expect(try WalletWireCodec.encodeActionResult(
            .listActions(shortPage), beefLimits: actionBEEFLimits()
        ) == [0, 1])

        // More records than the declared total is still rejected.
        let absent = [UInt8](repeating: 0xff, count: 9)
        let overfull = actionWireBytes([
            [0, 0], [UInt8](repeating: 0, count: 32), [0, 1, 0, 0], absent, [0, 0], absent, absent,
        ])
        #expect(throws: WalletWireResultRejection.self) {
            try WalletWireCodec.decodeActionResult(
                overfull, expectedCall: .listActions, beefLimits: actionBEEFLimits()
            )
        }
    }

    @Test func keepsEmptyCreateActionInputsAndRejectsEmptyLockingScripts() throws {
        let beefLimits = try actionBEEFLimits()
        // `@bsv/sdk` writes `inputs: []` as count 0 and an omitted array as -1
        // (WalletWireTransceiver.ts createAction `args.inputs != null`), so
        // both forms round-trip.
        let emptyInputs = try WalletCreateActionRequest(description: "", inputs: [])
        let emptyInputsEncoded = try WalletWireCodec.encodeActionRequest(
            .createAction(emptyInputs), originator: "", beefLimits: beefLimits
        )
        guard case .createAction(let emptyInputsDecoded) = try WalletWireCodec.decodeActionRequest(
            emptyInputsEncoded, beefLimits: beefLimits
        ).request else {
            Issue.record("expected a createAction request")
            return
        }
        #expect(emptyInputsDecoded.inputs == [])

        let emptyOutput = try WalletCreateActionRequest(
            description: "",
            outputs: [WalletCreateActionOutput(
                lockingScript: [], satoshis: 0, outputDescription: "", tags: []
            )]
        )
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "empty create-action locking script"
        )) {
            try WalletWireCodec.encodeActionRequest(
                .createAction(emptyOutput), originator: "", beefLimits: beefLimits
            )
        }

        let absent = [UInt8](repeating: 0xff, count: 9)
        var emptyInputsFrame: [UInt8] = [1, 0, 0]
        emptyInputsFrame.append(contentsOf: absent)
        emptyInputsFrame.append(0)
        for _ in 0..<4 {
            emptyInputsFrame.append(contentsOf: absent)
        }
        emptyInputsFrame.append(0)
        guard case .createAction(let emptyFrameRequest) = try WalletWireCodec.decodeActionRequest(
            emptyInputsFrame, beefLimits: beefLimits
        ).request else {
            Issue.record("expected a createAction request")
            return
        }
        #expect(emptyFrameRequest.inputs == [])

        var emptyScriptFrame: [UInt8] = [1, 0, 0]
        emptyScriptFrame.append(contentsOf: absent)
        emptyScriptFrame.append(contentsOf: absent)
        emptyScriptFrame.append(contentsOf: [1, 0, 0, 0])
        emptyScriptFrame.append(contentsOf: absent)
        emptyScriptFrame.append(contentsOf: absent)
        emptyScriptFrame.append(0)
        for _ in 0..<3 {
            emptyScriptFrame.append(contentsOf: absent)
        }
        emptyScriptFrame.append(0)
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "empty create-action locking script"
        )) {
            try WalletWireCodec.decodeActionRequest(emptyScriptFrame, beefLimits: beefLimits)
        }
    }

    @Test func readsZeroLengthAndAbsentStringSliceEntriesAsEmpty() throws {
        // `@bsv/sdk` writes an empty label or tag with length 0
        // (WalletWireTransceiver.ts `#writeUTF8Array`), and earlier Go and
        // Swift peers wrote -1. Both read as "", and "" is written as 0.
        let limits = WalletWireLimits.standard
        for entry in [[UInt8(0)], [UInt8](repeating: 0xff, count: 9)] {
            var reader = WalletWireReader([1] + entry)
            #expect(try walletWireReadStringSlice(
                from: &reader, kind: "labels", optional: false, limits: limits
            ) == [""])
            #expect(reader.isAtEnd)
        }
        var writer = WalletWireWriter()
        try walletWireWriteStringSlice([""], kind: "labels", to: &writer, limits: limits)
        #expect(writer.bytes == [1, 0])
    }

    @Test func roundTripsAbsentListActionScripts() throws {
        // `@bsv/sdk` 4.1.1 writes an absent listActions script as -1 and reads
        // it back as undefined (WalletWireProcessor.ts listActions inputs and
        // outputs). G6.
        let outpoint = Outpoint(transactionID: try actionTransactionID(), outputIndex: 0)
        let action = try WalletAction(
            transactionID: try actionTransactionID(), satoshis: 0, status: .completed,
            isOutgoing: false, description: "", version: 0, lockTime: 0,
            inputs: [WalletActionInput(
                sourceOutpoint: outpoint, sourceSatoshis: 0, sourceLockingScript: nil,
                unlockingScript: nil, inputDescription: "", sequenceNumber: 0
            )],
            outputs: [WalletActionOutput(
                satoshis: 0, lockingScript: nil, spendable: true, tags: [], outputIndex: 0,
                outputDescription: "", basket: ""
            )]
        )
        let result = WalletWireActionResult.listActions(
            try WalletListActionsResult(totalActions: 1, actions: [action])
        )
        let encoded = try WalletWireCodec.encodeActionResult(result, beefLimits: actionBEEFLimits())
        let decoded = try WalletWireCodec.decodeActionResult(
            encoded, expectedCall: .listActions, beefLimits: actionBEEFLimits()
        )
        guard case .listActions(let page) = decoded,
              let input = page.actions.first?.inputs?.first,
              let output = page.actions.first?.outputs?.first else {
            Issue.record("expected one listActions input and output")
            return
        }
        #expect(input.sourceLockingScript == nil)
        #expect(input.unlockingScript == nil)
        #expect(output.lockingScript == nil)
        #expect(try WalletWireCodec.encodeActionResult(decoded, beefLimits: actionBEEFLimits()) == encoded)
    }

    @Test func rejectsHostileActionResultForms() throws {
        let absent = [UInt8](repeating: 0xff, count: 9)
        let badSignableFlag = actionWireBytes([[0, 0, 0], absent, absent, [2]])
        #expect(throws: WalletWireError.invalidDiscriminator(
            kind: "signable transaction", value: 2
        )) {
            try WalletWireCodec.decodeActionResult(
                badSignableFlag, expectedCall: .createAction, beefLimits: actionBEEFLimits()
            )
        }

        let invalidSendStatus = actionWireBytes([
            [0, 1], [UInt8](repeating: 0, count: 32), [0, 1],
            [UInt8](repeating: 0, count: 32), [4],
        ])
        #expect(throws: WalletWireError.invalidDiscriminator(
            kind: "send-with status", value: 4
        )) {
            try WalletWireCodec.decodeActionResult(
                invalidSendStatus, expectedCall: .signAction, beefLimits: actionBEEFLimits()
            )
        }

        let midAction = actionWireBytes([[0, 1], [UInt8](repeating: 0, count: 16)])
        #expect(throws: WalletWireError.truncated) {
            try WalletWireCodec.decodeActionResult(
                midAction, expectedCall: .listActions, beefLimits: actionBEEFLimits()
            )
        }

        // The total counts every matching output, not the records in this frame
        // (WalletWireTransceiver.ts listOutputs reads records until the frame
        // ends), so a large total with no records is a valid page.
        let largeTotal = actionWireBytes([[0, 0xfd, 0x11, 0x27], absent])
        guard case .listOutputs(let page) = try WalletWireCodec.decodeActionResult(
            largeTotal, expectedCall: .listOutputs, beefLimits: actionBEEFLimits()
        ) else {
            Issue.record("expected a listOutputs result")
            return
        }
        #expect(page.totalOutputs == 10_001)
        #expect(page.outputs.isEmpty)

        // Records beyond the page limit are rejected before more are read.
        #expect(throws: WalletWireResultRejection.self) {
            try walletWireRequirePageCapacity(10, limit: 10, call: "listOutputs")
        }
    }
}
