import BSVCore
@testable import BSVCrypto
import Testing

@Suite("Symmetric key envelope conformance", .serialized)
struct SymmetricKeyConformanceTests {
    @Test("deterministic Swift envelopes exactly match pinned Go")
    func deterministicEncryption() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Symmetric-key Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let cases: [([UInt8], [UInt8], [UInt8])] = [
                ([1], [], deterministicBytes(count: 32, offset: 3)),
                (deterministicBytes(count: 31, offset: 7),
                 deterministicBytes(count: 1, offset: 11),
                 deterministicBytes(count: 32, offset: 13)),
                (deterministicBytes(count: 32, offset: 17),
                 deterministicBytes(count: 257, offset: 19),
                 deterministicBytes(count: 32, offset: 23)),
            ]

            for (index, item) in cases.enumerated() {
                let key = try SymmetricKey(item.0)
                let swiftEnvelope = try key.seal(item.1, nonce: item.2)
                let response = try client.request(
                    id: "symmetric-encrypt-\(index)",
                    operation: "symmetric.encrypt",
                    arguments: [
                        "key": .string(Hex.encode(item.0)),
                        "plaintext": .string(Hex.encode(item.1)),
                        "nonce": .string(Hex.encode(item.2)),
                    ]
                )
                #expect(response.result == .object([
                    "envelope": .string(Hex.encode(swiftEnvelope)),
                ]))
            }
        }
    }

    @Test("Swift envelopes decrypt in pinned Go and pinned Go envelopes open in Swift")
    func bidirectionalDecryption() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Symmetric-key Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let sourceKey = deterministicBytes(count: 31, offset: 29)
            let key = try SymmetricKey(sourceKey)
            let plaintext = deterministicBytes(count: 83, offset: 31)
            let nonce = deterministicBytes(count: 32, offset: 37)
            let swiftEnvelope = try key.seal(plaintext, nonce: nonce)

            let goDecryption = try client.request(
                id: "symmetric-go-decrypt",
                operation: "symmetric.decrypt",
                arguments: [
                    "key": .string(Hex.encode(sourceKey)),
                    "envelope": .string(Hex.encode(swiftEnvelope)),
                ]
            )
            #expect(goDecryption.result == .object([
                "plaintext": .string(Hex.encode(plaintext)),
            ]))

            let goEncryption = try client.request(
                id: "symmetric-go-encrypt",
                operation: "symmetric.encrypt",
                arguments: [
                    "key": .string(Hex.encode(sourceKey)),
                    "plaintext": .string(Hex.encode(plaintext)),
                    "nonce": .string(Hex.encode(nonce)),
                ]
            )
            guard case .object(let object) = goEncryption.result,
                  case .string(let envelopeText) = object["envelope"] else {
                throw SymmetricConformanceError.unexpectedOracleResult
            }
            let goEnvelope = try Hex.decode(
                envelopeText,
                maximumDecodedByteCount: 32 + plaintext.count + 16
            )
            #expect(try key.open(goEnvelope) == plaintext)

            var tampered = goEnvelope
            tampered[tampered.count - 1] ^= 1
            #expect(throws: SymmetricKeyError.authenticationFailed) {
                try key.open(tampered)
            }
            let goRejection = try client.request(
                id: "symmetric-go-tampered",
                operation: "symmetric.decrypt",
                arguments: [
                    "key": .string(Hex.encode(sourceKey)),
                    "envelope": .string(Hex.encode(tampered)),
                ]
            )
            #expect(!goRejection.ok)
        }
    }

    private func deterministicBytes(count: Int, offset: Int) -> [UInt8] {
        (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 29 &+ offset) }
    }
}

private enum SymmetricConformanceError: Error {
    case unexpectedOracleResult
}
