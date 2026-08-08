import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet
import Testing

@Suite("Wallet-wire action codecs")
struct WalletWireActionTests {
    @Test func signActionSortsSpendIndexesAndRoundTrips() throws {
        let request = try WalletSignActionRequest(
            reference: WalletBase64Data([9, 8, 7]),
            spends: [
                9: WalletSignActionSpend(unlockingScript: [0x52]),
                1: WalletSignActionSpend(unlockingScript: [0x51], sequenceNumber: 4),
            ]
        )
        let encoded = try WalletWireCodec.encodeActionRequest(
            .signAction(request), originator: "app", beefLimits: actionBEEFLimits()
        )
        let decoded = try WalletWireCodec.decodeActionRequest(
            encoded, beefLimits: actionBEEFLimits()
        )
        guard case .signAction(let value) = decoded.request else {
            Issue.record("wrong request type")
            return
        }
        #expect(decoded.originator == "app")
        #expect(value == request)
        #expect(try WalletWireCodec.encodeActionRequest(
            decoded.request, originator: decoded.originator, beefLimits: actionBEEFLimits()
        ) == encoded)
    }

    @Test func createActionRoundTripsAllCanonicalFields() throws {
        let transactionID = try actionTransactionID()
        let input = try WalletCreateActionInput(
            outpoint: Outpoint(transactionID: transactionID, outputIndex: 300),
            inputDescription: "input",
            unlockingScriptLength: 107,
            sequenceNumber: 7
        )
        let output = try WalletCreateActionOutput(
            lockingScript: [0x51], satoshis: 42, outputDescription: "output",
            basket: "basket", customInstructions: "custom", tags: ["tag", ""]
        )
        let request = try WalletCreateActionRequest(
            description: "create",
            inputBEEF: actionBEEF(),
            inputs: [input], outputs: [output], lockTime: 8, version: 2,
            labels: ["label", ""],
            options: WalletCreateActionOptions(
                signAndProcess: true, acceptDelayedBroadcast: false,
                trustSelf: .known, knownTransactionIDs: [transactionID],
                returnTransactionIDOnly: false, noSend: true,
                noSendChange: [Outpoint(transactionID: transactionID, outputIndex: 1)],
                sendWith: [transactionID], randomizeOutputs: true
            )
        )
        let encoded = try WalletWireCodec.encodeActionRequest(
            .createAction(request), originator: "", beefLimits: actionBEEFLimits()
        )
        let decoded = try WalletWireCodec.decodeActionRequest(
            encoded, beefLimits: actionBEEFLimits()
        )
        guard case .createAction(let value) = decoded.request else {
            Issue.record("wrong request type")
            return
        }
        #expect(value == request)
        #expect(try WalletWireCodec.encodeActionRequest(
            decoded.request, originator: decoded.originator, beefLimits: actionBEEFLimits()
        ) == encoded)
    }

    @Test func queryAndReferenceRequestsRoundTrip() throws {
        let id = try actionTransactionID()
        let requests: [WalletWireActionRequest] = [
            .abortAction(WalletAbortActionRequest(reference: try WalletBase64Data([1, 2, 3]))),
            .listActions(try WalletListActionsRequest(
                labels: ["a", ""], labelQueryMode: .all, includeInputs: true,
                pagination: WalletPagination(limit: 10, offset: 2), seekPermission: false
            )),
            .listOutputs(try WalletListOutputsRequest(
                basket: "default", tags: ["one"], tagQueryMode: .any,
                include: .lockingScripts, includeTags: true,
                pagination: WalletPagination(limit: 5, offset: 1)
            )),
            .relinquishOutput(try WalletRelinquishOutputRequest(
                basket: "default", output: Outpoint(transactionID: id, outputIndex: 253)
            )),
        ]
        for request in requests {
            let encoded = try WalletWireCodec.encodeActionRequest(
                request, originator: "app", beefLimits: actionBEEFLimits()
            )
            let decoded = try WalletWireCodec.decodeActionRequest(
                encoded, beefLimits: actionBEEFLimits()
            )
            #expect(decoded.request.call == request.call)
            #expect(try WalletWireCodec.encodeActionRequest(
                decoded.request, originator: decoded.originator, beefLimits: actionBEEFLimits()
            ) == encoded)
        }
    }

    @Test func internalizeRequestRoundTripsBothRemittances() throws {
        var senderPrivateKeyBytes = [UInt8](repeating: 0, count: 32)
        senderPrivateKeyBytes[31] = 1
        let sender = try PrivateKey(senderPrivateKeyBytes).publicKey
        let request = try WalletInternalizeActionRequest(
            transaction: actionAtomicBEEF(),
            description: "internalize",
            labels: ["received"],
            seekPermission: true,
            outputs: [
                WalletInternalizeOutput(
                    outputIndex: 1,
                    remittance: .walletPayment(try WalletPaymentRemittance(
                        derivationPrefix: WalletBase64Data([1, 2]),
                        derivationSuffix: WalletBase64Data([3, 4]),
                        senderIdentityKey: sender
                    ))
                ),
                WalletInternalizeOutput(
                    outputIndex: 0,
                    remittance: .basketInsertion(try WalletBasketInsertion(
                        basket: "payments", customInstructions: "keep", tags: ["tag"]
                    ))
                ),
            ]
        )
        let encoded = try WalletWireCodec.encodeActionRequest(
            .internalizeAction(request), originator: "app", beefLimits: actionBEEFLimits()
        )
        let decoded = try WalletWireCodec.decodeActionRequest(
            encoded, beefLimits: actionBEEFLimits()
        )
        guard case .internalizeAction(let value) = decoded.request else {
            Issue.record("wrong request type")
            return
        }
        #expect(value == request)
    }

    @Test func actionPayloadLimitsAcceptExactSizeAndRejectTheNextByte() throws {
        let beefLimits = try actionBEEFLimits()
        let exactRequestLimits = try actionWireLimits(payload: 3)
        let request = WalletWireActionRequest.abortAction(
            WalletAbortActionRequest(reference: try WalletBase64Data([1, 2, 3]))
        )
        #expect(try WalletWireCodec.encodeActionRequest(
            request, originator: "", beefLimits: beefLimits, limits: exactRequestLimits
        ).count == 5)
        #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "request parameters", actual: 3, maximum: 2
        )) {
            try WalletWireCodec.encodeActionRequest(
                request, originator: "", beefLimits: beefLimits,
                limits: actionWireLimits(payload: 2)
            )
        }

        let result = WalletWireActionResult.listActions(
            try WalletListActionsResult(totalActions: 0, actions: [])
        )
        #expect(try WalletWireCodec.encodeActionResult(
            result, beefLimits: beefLimits, limits: actionWireLimits(payload: 1)
        ) == [0, 0])
        #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "result payload", actual: 1, maximum: 0
        )) {
            try WalletWireCodec.encodeActionResult(
                result, beefLimits: beefLimits, limits: actionWireLimits(payload: 0)
            )
        }
    }

    @Test func actionResultsRoundTrip() throws {
        let id = try actionTransactionID()
        let outpoint = Outpoint(transactionID: id, outputIndex: 3)
        let action = try WalletAction(
            transactionID: id,
            satoshis: -12,
            status: .completed,
            isOutgoing: true,
            description: "sent",
                labels: ["label", ""],
            version: 1,
            lockTime: 0,
            inputs: [try WalletActionInput(
                sourceOutpoint: outpoint, sourceSatoshis: 20,
                sourceLockingScript: [0x51], unlockingScript: [0x52],
                inputDescription: "input", sequenceNumber: 1
            )],
            outputs: [try WalletActionOutput(
                satoshis: 8, lockingScript: [0x51], spendable: true,
                customInstructions: "custom", tags: ["tag", ""], outputIndex: 0,
                outputDescription: "output", basket: "basket"
            )]
        )
        let results: [WalletWireActionResult] = [
            .createAction(try WalletCreateActionResult(
                transactionID: id, transaction: actionAtomicBEEF(),
                noSendChange: [outpoint],
                sendWithResults: [WalletSendWithResult(transactionID: id, status: .sending)]
            )),
            .signAction(try WalletSignActionResult(
                transactionID: id, transaction: actionAtomicBEEF(),
                sendWithResults: [WalletSendWithResult(transactionID: id, status: .failed)]
            )),
            .abortAction(WalletAbortActionResult(aborted: true)),
            .listActions(try WalletListActionsResult(totalActions: 1, actions: [action])),
            .internalizeAction(WalletInternalizeActionResult(accepted: true)),
            .listOutputs(try WalletListOutputsResult(
                totalOutputs: 1, beef: actionBEEF(),
                outputs: [try WalletOutput(
                    satoshis: 8, lockingScript: [0x51], spendable: true,
                    customInstructions: "custom", tags: ["tag", ""], outpoint: outpoint,
                    labels: ["label", ""]
                )]
            )),
            .relinquishOutput(WalletRelinquishOutputResult(relinquished: true)),
        ]
        for result in results {
            let encoded = try WalletWireCodec.encodeActionResult(
                result, beefLimits: actionBEEFLimits()
            )
            let decoded = try WalletWireCodec.decodeActionResult(
                encoded, expectedCall: result.call, beefLimits: actionBEEFLimits()
            )
            #expect(decoded.call == result.call)
            #expect(try WalletWireCodec.encodeActionResult(
                decoded, beefLimits: actionBEEFLimits()
            ) == encoded)
        }
    }

    @Test func outpointUsesDisplayTransactionIDAndCompactSizeIndex() throws {
        let id = try TransactionID(wireBytes: Array(0..<32))
        let request = try WalletRelinquishOutputRequest(
            basket: "b", output: Outpoint(transactionID: id, outputIndex: 253)
        )
        let bytes = try WalletWireCodec.encodeActionRequest(
            .relinquishOutput(request), originator: "", beefLimits: actionBEEFLimits()
        )
        #expect(Array(bytes[4..<36]) == Array((0..<32).reversed()))
        #expect(Array(bytes.suffix(3)) == [0xfd, 0xfd, 0x00])
    }
}

func actionTransactionID() throws -> TransactionID {
    try TransactionID(wireBytes: Array(0..<32))
}

func actionWireBytes(_ chunks: [[UInt8]]) -> [UInt8] {
    chunks.flatMap { $0 }
}

func actionBEEFLimits() throws -> BEEFLimits {
    try BEEFLimits(
        maximumByteCount: 1_000_000,
        maximumMerklePathCount: 100,
        maximumTransactionCount: 1_000,
        transactionLimits: try TransactionLimits(
            maximumTransactionByteCount: 100_000,
            maximumInputCount: 100,
            maximumOutputCount: 100,
            maximumScriptByteCount: 10_000
        ),
        merklePathLimits: try MerklePathLimits(
            maximumByteCount: 100_000,
            maximumLeavesPerLevel: 100,
            maximumTotalLeaves: 1_000
        )
    )
}

func actionBEEF() throws -> BEEF {
    try BEEF(
        version: .v2,
        merklePaths: [],
        transactions: [.transactionID(try actionTransactionID())],
        limits: actionBEEFLimits()
    )
}

func actionAtomicBEEF() throws -> AtomicBEEF {
    try AtomicBEEF(
        subjectTransactionID: try actionTransactionID(),
        beef: actionBEEF(),
        limits: actionBEEFLimits()
    )
}

func actionWireLimits(payload: Int) throws -> WalletWireLimits {
    try WalletWireLimits(maximumPayloadByteCount: payload)
}
