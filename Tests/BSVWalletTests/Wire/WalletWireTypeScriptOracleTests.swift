import Foundation
import BSVCore
import BSVTransaction
import BSVWallet
import Testing

/// Differential vectors produced by the live TypeScript `@bsv/sdk` 4.1.1
/// `WalletWireTransceiver` talking to its own `WalletWireProcessor`.
///
/// Generate the vectors with `Tools/Conformance/TSOracle/generate.sh` and point
/// `BSV_TS_WALLET_WIRE_VECTORS` at the output. Without that variable the suite
/// records a skip. Generated answers are not committed (see
/// `Documentation/Compatibility/FixtureSources.md`).
@Suite("Wallet wire against the TypeScript SDK oracle")
struct WalletWireTypeScriptOracleTests {
    @Test("the Swift processor answers every TypeScript request with the TypeScript bytes")
    func processorMatchesTypeScript() async throws {
        guard let vectors = try TSWalletWireVectors.load() else { return }
        for vector in vectors.cases where vector.transceiverOnly != true {
            try await checkProcessor(vector)
        }
    }

    @Test("the Swift transceiver sends the TypeScript request bytes and reads the TypeScript answers")
    func transceiverMatchesTypeScript() async throws {
        guard let vectors = try TSWalletWireVectors.load() else { return }
        for vector in vectors.cases where vector.raw != true && vector.processorOnly != true {
            try await checkTransceiver(vector)
        }
    }

    private func checkProcessor(_ vector: TSWalletWireVector) async throws {
        let codec = try tsOracleCodec()
        let handler = TSOracleStubHandler(vector: vector, codec: codec)
        let limits = WalletWireLimits.standard
        let processor = WalletWireProcessor(
            handler: handler,
            failureMapper: try WalletWireRedactingFailureMapper(
                code: 1,
                message: "Wallet operation failed",
                limits: limits
            ),
            beefLimits: try tsOracleBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: limits
        )
        for frame in vector.frames {
            let request = try Hex.decode(frame.request, maximumDecodedByteCount: 1 << 24)
            let expected = try Hex.decode(frame.response, maximumDecodedByteCount: 1 << 24)
            let actual: [UInt8]
            do {
                actual = try await processor.transmit(
                    request,
                    maximumResponseByteCount: limits.maximumFrameByteCount
                )
            } catch {
                Issue.record("\(vector.name): processor threw \(error)")
                continue
            }
            if vector.isLegacyCertificateTypeDivergence, !frame.request.hasPrefix("1d") {
                // A legacy (non-32-byte) certificate type has no Swift ABI value. The
                // Swift processor still answers in-band with an error frame.
                #expect(actual.first != 0, "\(vector.name): legacy type answered in-band")
                continue
            }
            #expect(Hex.encode(actual) == frame.response, "\(vector.name): processor response")
            _ = expected
        }
    }

    private func checkTransceiver(_ vector: TSWalletWireVector) async throws {
        guard let method = vector.method, let args = vector.args,
              let route = WalletJSONRoute(methodName: method) else {
            Issue.record("\(vector.name): malformed vector")
            return
        }
        let codec = try tsOracleCodec()
        let request: WalletRequest
        do { request = try codec.decodeRequest(route: route, from: Array(args.utf8)) }
        catch {
            if vector.isLegacyCertificateTypeDivergence { return }
            Issue.record("\(vector.name): Swift JSON rejected TypeScript arguments: \(error)")
            return
        }
        let transport = TSOracleReplayTransport(name: vector.name, frames: vector.frames)
        let client = try WalletWireTransceiver(
            transport: transport,
            originator: vector.originator ?? "example.com",
            beefLimits: try tsOracleBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: .standard,
            listOutputsEncoding: vector.spendable == true ? .spendable : .legacy
        )
        let adapter = WalletInterfaceRequestHandler(wallet: client)
        let context = try WalletRequestContext(rawOriginator: vector.originator ?? "example.com")
        do {
            let result = try await adapter.handle(request, context: context)
            guard let ok = vector.outcome?.ok else {
                Issue.record("\(vector.name): expected a remote failure, got a result")
                return
            }
            let expected = try codec.decodeResult(route: route, from: Array(ok.utf8))
            #expect(
                try String(decoding: codec.encodeResult(result), as: UTF8.self)
                    == String(decoding: codec.encodeResult(expected), as: UTF8.self),
                "\(vector.name): decoded result"
            )
        } catch let remote as WalletWireRemoteError {
            guard let error = vector.outcome?.error else {
                Issue.record("\(vector.name): unexpected remote failure \(remote.code) \(remote.message)")
                return
            }
            #expect(Int(remote.code) == error.code, "\(vector.name): remote code")
            #expect(remote.message == error.message, "\(vector.name): remote message")
        } catch {
            Issue.record("\(vector.name): transceiver threw \(error)")
        }
        #expect(await transport.remaining() == 0, "\(vector.name): unsent TypeScript frames")
    }
}

struct TSWalletWireVectors: Decodable {
    let source: String
    let cases: [TSWalletWireVector]

    static func load() throws -> TSWalletWireVectors? {
        guard let path = ProcessInfo.processInfo.environment["BSV_TS_WALLET_WIRE_VECTORS"],
              !path.isEmpty else {
            print("TypeScript wallet-wire oracle vectors unavailable: BSV_TS_WALLET_WIRE_VECTORS is not set")
            return nil
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(TSWalletWireVectors.self, from: data)
    }
}

struct TSWalletWireVector: Decodable, Sendable {
    struct Frame: Decodable, Sendable {
        let request: String
        let response: String
    }
    struct Outcome: Decodable, Sendable {
        let ok: String?
        let error: Failure?
    }
    struct Failure: Decodable, Sendable {
        let code: Int?
        let message: String
    }

    let name: String
    let method: String?
    let originator: String?
    let raw: Bool?
    let spendable: Bool?
    /// The TS request keeps a form the Swift ABI does not (an omitted
    /// counterparty, an explicit `false`, insertion-ordered maps).
    let processorOnly: Bool?
    /// The Swift processor writes maps sorted; TS writes insertion order.
    let transceiverOnly: Bool?
    let divergence: String?
    let args: String?
    let walletResult: String?
    let outcome: Outcome?
    let frames: [Frame]

    var isLegacyCertificateTypeDivergence: Bool { divergence == "legacy-certificate-type" }
}

private struct TSOracleStubHandler: WalletRequestHandling {
    let vector: TSWalletWireVector
    let codec: WalletBRC100JSONCodec

    func handle(_ request: WalletRequest, context: WalletRequestContext) async throws -> WalletResult {
        let route = WalletJSONRoute(call: request.call)
        if let walletResult = vector.walletResult {
            return try codec.decodeResult(route: route, from: Array(walletResult.utf8))
        }
        if let ok = vector.outcome?.ok {
            return try codec.decodeResult(route: route, from: Array(ok.utf8))
        }
        throw TSOracleWalletFailure()
    }
}

private struct TSOracleWalletFailure: Error {}

private actor TSOracleReplayTransport: WalletWireTransport {
    let name: String
    var frames: [TSWalletWireVector.Frame]

    init(name: String, frames: [TSWalletWireVector.Frame]) {
        self.name = name
        // The Swift transceiver does not probe call 29 (the certificate
        // compatibility profile), so the TS probe frames are not replayed.
        self.frames = frames.filter { !$0.request.hasPrefix("1d") }
    }

    func remaining() -> Int { frames.count }

    func transmit(_ request: [UInt8], maximumResponseByteCount: Int) async throws -> [UInt8] {
        guard !frames.isEmpty else {
            Issue.record("\(name): Swift sent an extra frame \(Hex.encode(request))")
            throw WalletWireSubstrateError.transportFailure
        }
        let frame = frames.removeFirst()
        #expect(Hex.encode(request) == frame.request, "\(name): request frame")
        return try Hex.decode(frame.response, maximumDecodedByteCount: 1 << 24)
    }
}

private func tsOracleCodec() throws -> WalletBRC100JSONCodec {
    try WalletBRC100JSONCodec(beefLimits: tsOracleBEEFLimits())
}

private func tsOracleBEEFLimits() throws -> BEEFLimits {
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
