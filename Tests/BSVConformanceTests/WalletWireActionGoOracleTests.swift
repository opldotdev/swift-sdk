import XCTest
import BSVCore
import BSVKeys
import BSVTransaction
import BSVWallet

final class WalletWireActionGoOracleTests: XCTestCase {
    func testOnePersistentPinnedGoClientChecksAllActionCalls() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let value): client = value
        case .unavailable(let reason):
            XCTAssertFalse(configuration.required)
            print("Wallet-wire action Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        let beefLimits = try actionOracleBEEFLimits()
        let id = try TransactionID(wireBytes: Array(0..<32))
        let outpoint = Outpoint(transactionID: id, outputIndex: 253)
        var senderPrivateKeyBytes = [UInt8](repeating: 0, count: 32)
        senderPrivateKeyBytes[31] = 1
        let sender = try PrivateKey(senderPrivateKeyBytes).publicKey
        let requests: [WalletWireActionRequest] = [
            .createAction(try WalletCreateActionRequest(
                description: "create",
                inputs: [WalletCreateActionInput(
                    outpoint: outpoint, inputDescription: "input", unlockingScriptLength: 107
                )],
                outputs: [WalletCreateActionOutput(
                    lockingScript: [0x51], satoshis: 1, outputDescription: "output", tags: [""]
                )],
                labels: [""]
            )),
            .signAction(try WalletSignActionRequest(
                reference: WalletBase64Data([1, 2]),
                spends: [1: WalletSignActionSpend(unlockingScript: [0x51])]
            )),
            .abortAction(WalletAbortActionRequest(reference: try WalletBase64Data([3, 4]))),
            .listActions(try WalletListActionsRequest(labels: [""], pagination: .standard)),
            .internalizeAction(try WalletInternalizeActionRequest(
                transaction: actionOracleAtomicBEEF(limits: beefLimits, id: id),
                description: "internalize",
                labels: [""],
                outputs: [WalletInternalizeOutput(
                    outputIndex: 0,
                    remittance: .walletPayment(try WalletPaymentRemittance(
                        derivationPrefix: WalletBase64Data([1, 2]),
                        derivationSuffix: WalletBase64Data([3, 4]),
                        senderIdentityKey: sender
                    ))
                )]
            )),
            .listOutputs(try WalletListOutputsRequest(basket: "default", tags: [""])),
            .relinquishOutput(try WalletRelinquishOutputRequest(
                basket: "default", output: outpoint
            )),
        ]

        var sequence = 40_000
        for requestValue in requests {
            let encoded = try WalletWireCodec.encodeActionRequest(
                requestValue, originator: "oracle", beefLimits: beefLimits
            )
            let canonical = try oracleActionBytes(
                client, operation: "wallet.wire.request.reencode", call: requestValue.call,
                bytes: encoded, sequence: &sequence
            )
            XCTAssertEqual(canonical, encoded, "request call \(requestValue.call.rawValue)")
            XCTAssertEqual(
                try WalletWireCodec.decodeActionRequest(
                    canonical, beefLimits: beefLimits
                ).request.call,
                requestValue.call
            )
        }

        let listedAction = try WalletAction(
            transactionID: id, satoshis: 0, status: .completed, isOutgoing: false,
            description: "", labels: [""], version: 0, lockTime: 0,
            inputs: [WalletActionInput(
                sourceOutpoint: outpoint, sourceSatoshis: 1,
                sourceLockingScript: [0x51], unlockingScript: [0x52],
                inputDescription: "", sequenceNumber: 0
            )],
            outputs: [WalletActionOutput(
                satoshis: 1, lockingScript: [0x51], spendable: true, tags: [""],
                outputIndex: 0, outputDescription: "", basket: ""
            )]
        )
        let results: [WalletWireActionResult] = [
            .createAction(try WalletCreateActionResult(transactionID: id)),
            .signAction(try WalletSignActionResult(transactionID: id)),
            .abortAction(WalletAbortActionResult(aborted: true)),
            .listActions(try WalletListActionsResult(totalActions: 1, actions: [listedAction])),
            .internalizeAction(WalletInternalizeActionResult(accepted: true)),
            .listOutputs(try WalletListOutputsResult(
                totalOutputs: 1,
                outputs: [WalletOutput(
                    satoshis: 1, lockingScript: [0x51], spendable: true,
                    tags: [""], outpoint: outpoint, labels: [""]
                )]
            )),
            .relinquishOutput(WalletRelinquishOutputResult(relinquished: true)),
        ]
        for resultValue in results {
            let encoded = try WalletWireCodec.encodeActionResult(
                resultValue, beefLimits: beefLimits
            )
            let canonical = try oracleActionBytes(
                client, operation: "wallet.wire.result.reencode", call: resultValue.call,
                bytes: encoded, sequence: &sequence
            )
            XCTAssertEqual(canonical, encoded, "result call \(resultValue.call.rawValue)")
            XCTAssertEqual(
                try WalletWireCodec.decodeActionResult(
                    canonical, expectedCall: resultValue.call, beefLimits: beefLimits
                ).call,
                resultValue.call
            )
        }
    }

    func testSafeAdapterRejectsPinnedGoActionLeniencies() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let value): client = value
        case .unavailable:
            XCTAssertFalse(configuration.required)
            return
        }
        defer { client.close() }
        var sequence = 50_000

        let absentTransactionID = [UInt8](arrayLiteral: 0, 0, 0)
        let response = try oracleActionRequest(
            client, operation: "wallet.wire.result.reencode", call: .createAction,
            bytes: absentTransactionID, sequence: &sequence
        )
        XCTAssertFalse(response.ok)
        XCTAssertEqual(response.error?.category, "invalidArgument")

        let unsortedSpends = oracleActionWireBytes([
            [2, 2, 0], [UInt8](repeating: 0xff, count: 9), [1, 0],
            [UInt8](repeating: 0xff, count: 9), [0, 0],
        ])
        let framed = oracleActionWireBytes([
            [WalletCall.signAction.rawValue, 0], unsortedSpends,
        ])
        let unsortedResponse = try oracleActionRequest(
            client, operation: "wallet.wire.request.reencode", call: .signAction,
            bytes: framed, sequence: &sequence
        )
        XCTAssertFalse(unsortedResponse.ok)
        XCTAssertEqual(unsortedResponse.error?.category, "invalidArgument")

        let absent = [UInt8](repeating: 0xff, count: 9)
        var emptyInputs: [UInt8] = [WalletCall.createAction.rawValue, 0, 0]
        emptyInputs.append(contentsOf: absent)
        emptyInputs.append(0)
        for _ in 0..<4 {
            emptyInputs.append(contentsOf: absent)
        }
        emptyInputs.append(0)

        var emptyOutputScript: [UInt8] = [WalletCall.createAction.rawValue, 0, 0]
        emptyOutputScript.append(contentsOf: absent)
        emptyOutputScript.append(contentsOf: absent)
        emptyOutputScript.append(contentsOf: [1, 0, 0, 0])
        emptyOutputScript.append(contentsOf: absent)
        emptyOutputScript.append(contentsOf: absent)
        emptyOutputScript.append(0)
        for _ in 0..<3 {
            emptyOutputScript.append(contentsOf: absent)
        }
        emptyOutputScript.append(0)
        let emptyLabel = [UInt8](arrayLiteral: WalletCall.listActions.rawValue, 0, 1, 0)
        let invalidRequests: [(WalletCall, [UInt8])] = [
            (WalletCall.createAction, emptyInputs),
            (.createAction, emptyOutputScript),
            (.listActions, emptyLabel),
        ]
        for (call, bytes) in invalidRequests {
            let response = try oracleActionRequest(
                client, operation: "wallet.wire.request.reencode", call: call,
                bytes: bytes, sequence: &sequence
            )
            XCTAssertFalse(response.ok)
            XCTAssertEqual(response.error?.category, "invalidArgument")
        }

        let actionPrefix = oracleActionWireBytes([
            [0, 1], [UInt8](repeating: 0, count: 32), [0, 1, 0, 0], absent, [0, 0],
        ])
        let inputPrefix = oracleActionWireBytes([
            actionPrefix, [1], [UInt8](repeating: 0, count: 32), [0, 0],
        ])
        let unreadableResults: [[UInt8]] = [
            oracleActionWireBytes([inputPrefix, absent]),
            oracleActionWireBytes([inputPrefix, [1, 0x51], absent]),
            oracleActionWireBytes([actionPrefix, absent, [1, 0, 0], absent]),
        ]
        for bytes in unreadableResults {
            let response = try oracleActionRequest(
                client, operation: "wallet.wire.result.reencode", call: .listActions,
                bytes: bytes, sequence: &sequence
            )
            XCTAssertFalse(response.ok)
            XCTAssertEqual(response.error?.category, "invalidArgument")
        }
    }

    private func oracleActionBytes(
        _ client: GoOracleClient,
        operation: String,
        call: WalletCall,
        bytes: [UInt8],
        sequence: inout Int
    ) throws -> [UInt8] {
        let response = try oracleActionRequest(
            client, operation: operation, call: call, bytes: bytes, sequence: &sequence
        )
        XCTAssertTrue(response.ok, response.error?.category ?? "missing oracle error")
        guard case .object(let object)? = response.result,
              case .string(let hex)? = object["bytes"] else {
            throw WalletWireActionOracleError.missingBytes
        }
        return try Hex.decode(hex, maximumDecodedByteCount: 300_000)
    }

    private func oracleActionRequest(
        _ client: GoOracleClient,
        operation: String,
        call: WalletCall,
        bytes: [UInt8],
        sequence: inout Int
    ) throws -> GoOracleResponse {
        defer { sequence += 1 }
        return try client.request(
            id: "wallet-wire-action-\(sequence)",
            operation: operation,
            arguments: [
                "call": .string(String(call.rawValue)),
                "bytes": .string(Hex.encode(bytes)),
            ]
        )
    }
}

private func oracleActionWireBytes(_ chunks: [[UInt8]]) -> [UInt8] {
    chunks.flatMap { $0 }
}

private func actionOracleBEEFLimits() throws -> BEEFLimits {
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

private func actionOracleAtomicBEEF(
    limits: BEEFLimits,
    id: TransactionID
) throws -> AtomicBEEF {
    let beef = try BEEF(
        version: .v2, merklePaths: [], transactions: [.transactionID(id)], limits: limits
    )
    return try AtomicBEEF(subjectTransactionID: id, beef: beef, limits: limits)
}

private enum WalletWireActionOracleError: Error {
    case missingBytes
}
