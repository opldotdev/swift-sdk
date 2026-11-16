import Foundation
import BSVCore
import BSVKeys
import BSVTransaction
@testable import BSVWallet
import Testing

/// Fixed vectors for the `@bsv/sdk` 4.1.1 wallet behaviour Swift now follows.
/// Each cites the TypeScript source in `packages/sdk/src/wallet`. These run
/// without the TypeScript toolchain; `WalletWireTypeScriptOracleTests` checks
/// the same behaviour against live TypeScript when its vectors are provided.
@Suite("Wallet wire and ProtoWallet vectors from @bsv/sdk 4.1.1")
struct WalletWireTypeScript41VectorTests {
    private let absent = [UInt8](repeating: 0xff, count: 9)

    // MARK: W2 list totals

    /// substrates/WalletWireTransceiver.ts:455-467 (listActions), :726-742
    /// (listOutputs), :1617-1659 (listCertificates), :1818-1896 (discovery):
    /// read the total, then records until the frame ends.
    @Test func listTotalsCountEveryMatchNotTheRecordsInTheFrame() throws {
        guard case .listActions(let actions) = try WalletWireCodec.decodeActionResult(
            [0x00, 0xfa], expectedCall: .listActions, beefLimits: actionBEEFLimits()
        ) else {
            Issue.record("expected listActions")
            return
        }
        #expect(actions.totalActions == 250)
        #expect(actions.actions.isEmpty)
        #expect(try WalletWireCodec.encodeActionResult(
            .listActions(actions), beefLimits: actionBEEFLimits()
        ) == [0x00, 0xfa])

        let outputsFrame = [0x00, 0x03] + absent
        guard case .listOutputs(let outputs) = try WalletWireCodec.decodeActionResult(
            outputsFrame, expectedCall: .listOutputs, beefLimits: actionBEEFLimits()
        ) else {
            Issue.record("expected listOutputs")
            return
        }
        #expect(outputs.totalOutputs == 3)
        #expect(outputs.outputs.isEmpty)
        #expect(try WalletWireCodec.encodeActionResult(
            .listOutputs(outputs), beefLimits: actionBEEFLimits()
        ) == outputsFrame)

        for call in [WalletCall.listCertificates, .discoverByIdentityKey, .discoverByAttributes] {
            let decoded = try WalletWireCodec.decodeCertificateResult([0x00, 0x07], expectedCall: call)
            switch decoded {
            case .listCertificates(let page):
                #expect(page.totalCertificates == 7)
                #expect(page.certificates.isEmpty)
            case .discoverByIdentityKey(let page), .discoverByAttributes(let page):
                #expect(page.totalCertificates == 7)
                #expect(page.certificates.isEmpty)
            default:
                Issue.record("unexpected result for call \(call.rawValue)")
            }
            #expect(try WalletWireCodec.encodeCertificateResult(decoded) == [0x00, 0x07])
        }
    }

    // MARK: W3 BRC-112 balance

    /// moduleBalanceQuery.ts:1-21 defines the basket pattern;
    /// WalletWireProcessor.ts:1296-1308 writes the balance as a full varint.
    @Test func balanceBasketsCarryAUInt64Balance() throws {
        #expect(walletIsBalanceBasket("balance default"))
        #expect(walletIsBalanceBasket("p btms balance tokens"))
        #expect(!walletIsBalanceBasket("balance"))
        #expect(!walletIsBalanceBasket("p btms tokens"))

        let request = WalletWireActionRequest.listOutputs(
            try WalletListOutputsRequest(basket: "balance default")
        )
        let frame = [0x00, 0xff, 0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00] + absent
        let decoded = try WalletWireCodec.decodeActionResult(
            frame, expectedCall: .listOutputs, request: request, beefLimits: actionBEEFLimits()
        )
        guard case .listOutputs(let balance) = decoded else {
            Issue.record("expected listOutputs")
            return
        }
        #expect(balance.totalOutputs == 5_000_000_000)
        #expect(balance.outputs.isEmpty)
        #expect(try WalletWireCodec.encodeActionResult(
            decoded, request: request, beefLimits: actionBEEFLimits()
        ) == frame)

        let codec = try WalletBRC100JSONCodec(beefLimits: actionBEEFLimits())
        let route = try #require(WalletJSONRoute(methodName: "listOutputs"))
        let json = #"{"outputs":[],"totalOutputs":5000000000}"#
        let jsonResult = try codec.decodeResult(route: route, from: Array(json.utf8))
        guard case .action(.listOutputs(let jsonBalance)) = jsonResult else {
            Issue.record("expected a JSON listOutputs result")
            return
        }
        #expect(jsonBalance.totalOutputs == 5_000_000_000)
        #expect(String(decoding: try codec.encodeResult(jsonResult), as: UTF8.self) == json)
    }

    // MARK: W4 and G5 in-band processor errors

    /// substrates/WalletWireTransceiver.ts:124-152 downgrades only on code 2 or
    /// code 1 with exactly "Invalid call code: 29"; WalletWireProcessor.ts
    /// :2413-2441 answers parse failures in-band with code 1 and an empty stack.
    @Test func processorAnswersUnknownCallsAndBadFramesInBand() async throws {
        let processor = try vectorProcessor(result: .keyQuery(.getHeight(WalletGetHeightResult(height: 1))))
        let probe = try await processor.transmit([0x1d, 0x00, 0x00, 0x01], maximumResponseByteCount: 1 << 16)
        #expect(probe == errorFrame(code: 1, "Invalid call code: 29"))

        let unknown = try await processor.transmit([0x1e, 0x00], maximumResponseByteCount: 1 << 16)
        #expect(unknown == errorFrame(code: 1, "Invalid call code: 30"))

        let trailing = try await processor.transmit([0x19, 0x00, 0x00], maximumResponseByteCount: 1 << 16)
        #expect(trailing == errorFrame(code: 1, "Wallet Wire getHeight request contains trailing data"))

        let truncated = try await processor.transmit([0x19, 0x05, 0x61], maximumResponseByteCount: 1 << 16)
        #expect(truncated == errorFrame(code: 1, "ReaderUint8Array read exceeds available data"))
    }

    /// ProtoWallet.ts throws "HMAC is not valid" / "Signature is not valid";
    /// WalletWireProcessor.ts:1566 and :1643 send them as code 1.
    @Test func falseVerificationsCrossTheWireAsErrorFrames() async throws {
        let hmacProcessor = try vectorProcessor(
            result: .keyQuery(.verifyHMAC(WalletVerifyHMACResult(valid: false)))
        )
        let request = try WalletWireCodec.encodeKeyQueryRequest(.verifyHMAC(WalletVerifyHMACRequest(
            protocolID: try walletTestProtocol("wire test"),
            keyID: try walletTestKeyID("key"),
            data: [1],
            hmac: try WalletHMAC(bytes: [UInt8](repeating: 1, count: 32))
        )), originator: "")
        let response = try await hmacProcessor.transmit(request, maximumResponseByteCount: 1 << 16)
        #expect(response == errorFrame(code: 1, "HMAC is not valid"))
        guard case .verifyHMAC(let decoded) = try {
            do { return try WalletWireCodec.decodeKeyQueryResult(response, expectedCall: .verifyHMAC) }
            catch let remote as WalletWireRemoteError {
                #expect(remote.message == "HMAC is not valid")
                return .verifyHMAC(WalletVerifyHMACResult(valid: false))
            }
        }() else {
            Issue.record("expected verifyHMAC")
            return
        }
        #expect(decoded.valid == false)
    }

    // MARK: G2 display-order transaction IDs

    /// WalletWireProcessor.ts:604 and :640 write `toArray(txid, 'hex')`, the
    /// display order, not the internal (wire) order.
    @Test func resultTransactionIDsUseDisplayOrder() throws {
        let id = try TransactionID(wireBytes: Array(0..<32))
        let encoded = try WalletWireCodec.encodeActionResult(
            .signAction(try WalletSignActionResult(transactionID: id)),
            beefLimits: actionBEEFLimits()
        )
        #expect(Array(encoded.prefix(34)) == [0x00, 0x01] + Array((0..<32).reversed()))
        #expect(Array(encoded[2..<34]) == id.displayBytes)
    }

    // MARK: W6 revealSpecificKeyLinkage counterparty

    /// ProtoWallet.ts:235-240 resolves `self` to the identity key and `anyone`
    /// to the public key of private key 1.
    @Test func specificLinkageResolvesSelfAndAnyone() async throws {
        let root = try walletTestPrivateKey(7)
        let verifier = try walletTestPrivateKey(17).publicKey
        let wallet = ProtoWallet(rootKey: root)
        let protocolID = try walletTestProtocol("linkage vectors")
        let keyID = try walletTestKeyID("1")
        let forSelf = try await wallet.revealSpecificKeyLinkage(WalletRevealSpecificKeyLinkageRequest(
            counterparty: .self, verifier: verifier, protocolID: protocolID, keyID: keyID
        ))
        #expect(forSelf.counterparty == forSelf.prover)
        #expect(forSelf.prover == root.publicKey)
        let forAnyone = try await wallet.revealSpecificKeyLinkage(WalletRevealSpecificKeyLinkageRequest(
            counterparty: .anyone, verifier: verifier, protocolID: protocolID, keyID: keyID
        ))
        #expect(
            Hex.encode(forAnyone.counterparty.compressedBytes)
                == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
    }

    // MARK: W10 spendable listOutputs extension

    /// substrates/WalletWireTransceiver.ts:745-757 appends `01`;
    /// WalletWireProcessor.ts:1316-1327 answers with a -1 marker, the total,
    /// the BEEF, and a spendable byte after each locking script.
    @Test func spendableListOutputsExtension() throws {
        let request = WalletWireActionRequest.listOutputs(try WalletListOutputsRequest(basket: "default"))
        let legacy = try WalletWireCodec.encodeActionRequest(
            request, originator: "", beefLimits: actionBEEFLimits()
        )
        let spendable = try WalletWireCodec.encodeActionRequest(
            request, originator: "", listOutputsEncoding: .spendable, beefLimits: actionBEEFLimits()
        )
        #expect(spendable == legacy + [0x01])
        #expect(try WalletWireCodec.decodeActionRequest(spendable, beefLimits: actionBEEFLimits())
            .listOutputsEncoding == .spendable)
        #expect(try WalletWireCodec.decodeActionRequest(legacy, beefLimits: actionBEEFLimits())
            .listOutputsEncoding == .legacy)

        let output = try WalletOutput(
            satoshis: 1, lockingScript: [0x51], spendable: false,
            outpoint: Outpoint(transactionID: try actionTransactionID(), outputIndex: 0)
        )
        let result = WalletWireActionResult.listOutputs(
            try WalletListOutputsResult(totalOutputs: 1, outputs: [output])
        )
        #expect(throws: WalletWireResultRejection(
            message: "Non-spendable listOutputs records require the spendable encoding extension or JSON"
        )) {
            try WalletWireCodec.encodeActionResult(result, request: request, beefLimits: actionBEEFLimits())
        }
        let encoded = try WalletWireCodec.encodeActionResult(
            result, request: request, listOutputsEncoding: .spendable, beefLimits: actionBEEFLimits()
        )
        let header: [UInt8] = [0x00] + absent + [0x01] + absent
        #expect(Array(encoded.prefix(header.count)) == header)
        guard case .listOutputs(let decoded) = try WalletWireCodec.decodeActionResult(
            encoded, expectedCall: .listOutputs, request: request,
            listOutputsEncoding: .spendable, beefLimits: actionBEEFLimits()
        ) else {
            Issue.record("expected listOutputs")
            return
        }
        #expect(decoded.outputs.first?.spendable == false)
    }

    // MARK: W13 JSON error code

    /// substrates/HTTPWalletJSON.ts:271-279 requires a safe-integer `code`.
    @Test func redactedJSONErrorsCarryCodeOne() throws {
        let payload = WalletJSONRedactingFailureMapper().payload(for: VectorFailure(), call: .getHeight)
        #expect(payload.code == 1)
        let codec = try WalletBRC100JSONCodec(beefLimits: actionBEEFLimits())
        let body = String(decoding: try codec.encodeError(payload), as: UTF8.self)
        #expect(body.contains("\"code\":1"))
    }

    // MARK: empty keyring in JSON

    /// substrates/WalletWireTransceiver.ts:1622 returns `keyring: {}` when no
    /// keyring is present, and WalletWireProcessor.ts:2118 writes `{}` as no
    /// keyring, so a TypeScript JSON result with `{}` decodes as no keyring.
    @Test func emptyJSONKeyringReadsAsAbsent() throws {
        let fixture = try WalletWireCertificateFixture()
        let codec = try WalletBRC100JSONCodec(beefLimits: actionBEEFLimits())
        let route = try #require(WalletJSONRoute(methodName: "listCertificates"))
        let withoutKeyring = WalletResult.certificate(.listCertificates(try .init(
            totalCertificates: 1,
            certificates: [WalletCertificateResult(certificate: fixture.certificate, keyring: nil, verifier: [])]
        )))
        let json = String(decoding: try codec.encodeResult(withoutKeyring), as: UTF8.self)
        #expect(!json.contains("keyring"))
        let typeScriptJSON = json.replacingOccurrences(
            of: "\"certifier\":", with: "\"keyring\":{},\"certifier\":"
        )
        #expect(typeScriptJSON.contains("\"keyring\":{}"))
        let decoded = try codec.decodeResult(route: route, from: Array(typeScriptJSON.utf8))
        guard case .certificate(.listCertificates(let page)) = decoded else {
            Issue.record("expected listCertificates")
            return
        }
        #expect(page.certificates.first?.keyring == nil)
    }

    // MARK: helpers

    private func errorFrame(code: UInt8, _ message: String) -> [UInt8] {
        [code, UInt8(message.utf8.count)] + Array(message.utf8) + [0x00]
    }

    private func vectorProcessor(result: WalletResult) throws -> WalletWireProcessor {
        WalletWireProcessor(
            handler: VectorHandler(result: result),
            failureMapper: try WalletWireRedactingFailureMapper(limits: .standard),
            beefLimits: try actionBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: .standard
        )
    }
}

private struct VectorFailure: Error {}

private struct VectorHandler: WalletRequestHandling {
    let result: WalletResult
    func handle(_ request: WalletRequest, context: WalletRequestContext) async throws -> WalletResult {
        result
    }
}
