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
        let hostileInputs = [UInt8](arrayLiteral: 1, 0, 0)
            + negativeOne
            + [0xfd, 0x11, 0x27]
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

    @Test func rejectsUnsortedSpendsAndInvalidDiscriminators() throws {
        let negativeOne = [UInt8](repeating: 0xff, count: 9)
        let unsorted = [UInt8](arrayLiteral: 2, 0, 2, 2, 0)
            + negativeOne
            + [1, 0]
            + negativeOne
            + [0, 0]
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "unsorted or duplicate spend index"
        )) {
            try WalletWireCodec.decodeActionRequest(
                unsorted, beefLimits: actionBEEFLimits()
            )
        }

        let invalidMode = [UInt8](arrayLiteral: 6, 0, 0, 0, 3)
        #expect(throws: WalletWireError.invalidDiscriminator(
            kind: "tag query mode", value: 3
        )) {
            try WalletWireCodec.decodeActionRequest(
                invalidMode, beefLimits: actionBEEFLimits()
            )
        }
    }

    @Test func rejectsTruncationAndTrailingBytesForEveryEmptyResult() throws {
        let truncated = [UInt8](arrayLiteral: 7, 0, 0) + [UInt8](repeating: 0, count: 31)
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

    @Test func rejectsInvalidBEEFAndNonRoundTrippableGoUnions() throws {
        let invalidAtomic = [UInt8](arrayLiteral: 5, 0, 1, 0, 0, 0, 0, 0xff)
        #expect(throws: WalletWireError.nonRoundTrippableValue(kind: "Atomic BEEF")) {
            try WalletWireCodec.decodeActionRequest(
                invalidAtomic, beefLimits: actionBEEFLimits()
            )
        }

        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "absent pinned Go transaction ID"
        )) {
            try WalletWireCodec.decodeActionResult(
                [0, 0, 0], expectedCall: .createAction, beefLimits: actionBEEFLimits()
            )
        }
    }

    @Test func rejectsFalseImplicitResultsAndTotalMismatches() throws {
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "false abort-action result"
        )) {
            try WalletWireCodec.encodeActionResult(
                .abortAction(WalletAbortActionResult(aborted: false)),
                beefLimits: actionBEEFLimits()
            )
        }
        let mismatch = try WalletListActionsResult(totalActions: 1, actions: [])
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "total actions mismatch"
        )) {
            try WalletWireCodec.encodeActionResult(
                .listActions(mismatch), beefLimits: actionBEEFLimits()
            )
        }
    }

    @Test func rejectsCreateActionNilEmptyCollisionsOnEncodeAndDecode() throws {
        let beefLimits = try actionBEEFLimits()
        let emptyInputs = try WalletCreateActionRequest(description: "", inputs: [])
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "empty create-action inputs"
        )) {
            try WalletWireCodec.encodeActionRequest(
                .createAction(emptyInputs), originator: "", beefLimits: beefLimits
            )
        }

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
        let emptyInputsFrame = [UInt8](arrayLiteral: 1, 0, 0) + absent + [0]
            + absent + absent + absent + absent + [0]
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "empty create-action inputs"
        )) {
            try WalletWireCodec.decodeActionRequest(emptyInputsFrame, beefLimits: beefLimits)
        }

        let emptyScriptFrame = [UInt8](arrayLiteral: 1, 0, 0) + absent + absent
            + [1, 0, 0, 0] + absent + absent + [0]
            + absent + absent + absent + [0]
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "empty create-action locking script"
        )) {
            try WalletWireCodec.decodeActionRequest(emptyScriptFrame, beefLimits: beefLimits)
        }
    }

    @Test func rejectsPresentZeroLengthStringSliceEntries() throws {
        let request = [UInt8](arrayLiteral: WalletCall.listActions.rawValue, 0, 1, 0)
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "zero-length labels entry"
        )) {
            try WalletWireCodec.decodeActionRequest(request, beefLimits: actionBEEFLimits())
        }

        let result = [UInt8](arrayLiteral: 0, 1)
            + [UInt8](repeating: 0, count: 32)
            + [0, 1, 0, 0, 1, 0]
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "zero-length labels entry"
        )) {
            try WalletWireCodec.decodeActionResult(
                result, expectedCall: .listActions, beefLimits: actionBEEFLimits()
            )
        }
    }

    @Test func rejectsPinnedGoUnreadableListActionScriptSentinels() throws {
        let absent = [UInt8](repeating: 0xff, count: 9)
        let prefix = [UInt8](arrayLiteral: 0, 1) + [UInt8](repeating: 0, count: 32)
            + [0, 1, 0, 0] + absent + [0, 0]
        let inputPrefix = prefix + [1] + [UInt8](repeating: 0, count: 32) + [0, 0]
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "absent action source locking script"
        )) {
            try WalletWireCodec.decodeActionResult(
                inputPrefix + absent, expectedCall: .listActions, beefLimits: actionBEEFLimits()
            )
        }
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "absent action unlocking script"
        )) {
            try WalletWireCodec.decodeActionResult(
                inputPrefix + [1, 0x51] + absent,
                expectedCall: .listActions, beefLimits: actionBEEFLimits()
            )
        }

        let outputPrefix = prefix + absent + [1, 0, 0]
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "absent action output locking script"
        )) {
            try WalletWireCodec.decodeActionResult(
                outputPrefix + absent, expectedCall: .listActions, beefLimits: actionBEEFLimits()
            )
        }

        let outpoint = Outpoint(transactionID: try actionTransactionID(), outputIndex: 0)
        func action(
            inputs: [WalletActionInput]? = nil,
            outputs: [WalletActionOutput]? = nil
        ) throws -> WalletAction {
            try WalletAction(
                transactionID: try actionTransactionID(), satoshis: 0, status: .completed,
                isOutgoing: false, description: "", version: 0, lockTime: 0,
                inputs: inputs, outputs: outputs
            )
        }
        let lossyActions: [(WalletAction, String)] = [
            (try action(inputs: [WalletActionInput(
                sourceOutpoint: outpoint, sourceSatoshis: 0, sourceLockingScript: nil,
                unlockingScript: [0x51], inputDescription: "", sequenceNumber: 0
            )]), "absent or empty action source locking script"),
            (try action(inputs: [WalletActionInput(
                sourceOutpoint: outpoint, sourceSatoshis: 0, sourceLockingScript: [0x51],
                unlockingScript: nil, inputDescription: "", sequenceNumber: 0
            )]), "absent or empty action unlocking script"),
            (try action(outputs: [WalletActionOutput(
                satoshis: 0, lockingScript: nil, spendable: true, tags: [], outputIndex: 0,
                outputDescription: "", basket: ""
            )]), "absent or empty action output locking script"),
        ]
        for (action, kind) in lossyActions {
            #expect(throws: WalletWireError.nonRoundTrippableValue(kind: kind)) {
                try WalletWireCodec.encodeActionResult(
                    .listActions(WalletListActionsResult(totalActions: 1, actions: [action])),
                    beefLimits: actionBEEFLimits()
                )
            }
        }
    }

    @Test func rejectsRemainingHostileActionResultForms() throws {
        let absent = [UInt8](repeating: 0xff, count: 9)
        let signable = [UInt8](arrayLiteral: 0, 0, 1)
            + [UInt8](repeating: 0, count: 32) + [0] + absent + [0, 1]
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "pinned Go signable create-action result"
        )) {
            try WalletWireCodec.decodeActionResult(
                signable, expectedCall: .createAction, beefLimits: actionBEEFLimits()
            )
        }

        let invalidSendStatus = [UInt8](arrayLiteral: 0, 1)
            + [UInt8](repeating: 0, count: 32) + [0, 1]
            + [UInt8](repeating: 0, count: 32) + [4]
        #expect(throws: WalletWireError.invalidDiscriminator(
            kind: "send-with status", value: 4
        )) {
            try WalletWireCodec.decodeActionResult(
                invalidSendStatus, expectedCall: .signAction, beefLimits: actionBEEFLimits()
            )
        }

        let midAction = [UInt8](arrayLiteral: 0, 1) + [UInt8](repeating: 0, count: 16)
        #expect(throws: WalletWireError.truncated) {
            try WalletWireCodec.decodeActionResult(
                midAction, expectedCall: .listActions, beefLimits: actionBEEFLimits()
            )
        }

        let hostileCount = [UInt8](arrayLiteral: 0, 0xfd, 0x11, 0x27)
        #expect(throws: WalletWireError.countLimitExceeded(
            kind: "outputs", actual: 10_001, maximum: 10_000
        )) {
            try WalletWireCodec.decodeActionResult(
                hostileCount, expectedCall: .listOutputs, beefLimits: actionBEEFLimits()
            )
        }
    }
}
