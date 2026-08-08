import BSVCore
import BSVSPV
import Testing

@Suite("Block header pinned-Go conformance", .serialized)
struct BlockHeaderGoOracleTests {
    private let genesisHex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

    @Test("Swift and pinned Go agree on block-header fields, hash, and bytes")
    func parity() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Block header Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let swiftHeader = try BlockHeader(hex: genesisHex)
            let inspection = try client.request(
                id: "block-header-inspect",
                operation: "block.header.inspect",
                arguments: ["bytes": .string(swiftHeader.hex)]
            )

            #expect(inspection.ok)
            #expect(inspection.result?.string(for: "bytes") == swiftHeader.hex)
            #expect(inspection.result?.string(for: "version") == String(swiftHeader.version))
            #expect(inspection.result?.string(for: "previousBlockHash") == swiftHeader.previousBlockHash.displayHex)
            #expect(inspection.result?.string(for: "merkleRoot") == Hex.encode(Array(swiftHeader.merkleRoot.bytes.reversed())))
            #expect(inspection.result?.string(for: "timestamp") == String(swiftHeader.timestamp))
            #expect(inspection.result?.string(for: "bits") == String(swiftHeader.bits))
            #expect(inspection.result?.string(for: "nonce") == String(swiftHeader.nonce))
            #expect(inspection.result?.string(for: "hash") == swiftHeader.hash.displayHex)

            let reencoded = try client.request(
                id: "block-header-reencode",
                operation: "block.header.reencode",
                arguments: ["bytes": .string(swiftHeader.hex)]
            )
            #expect(reencoded.ok)
            let goBytes = try #require(reencoded.result?.string(for: "bytes"))
            let goHeader = try BlockHeader(hex: goBytes)
            #expect(goHeader == swiftHeader)
        }
    }

    @Test("both implementations reject non-header byte counts")
    func invalidLengths() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Block header Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for (index, count) in [0, 1, 79, 81].enumerated() {
                let bytes = [UInt8](repeating: 0, count: count)
                #expect(throws: FixedByteCountError.invalidByteCount(expected: 80, actual: count)) {
                    try BlockHeader(bytes: bytes)
                }
                let response = try client.request(
                    id: "block-header-invalid-\(index)",
                    operation: "block.header.inspect",
                    arguments: ["bytes": .string(Hex.encode(bytes))]
                )
                #expect(!response.ok)
                #expect(response.error?.category == "invalidLength")
            }
        }
    }
}

private extension GoOracleJSON {
    func string(for key: String) -> String? {
        guard case .object(let object) = self,
              case .string(let value)? = object[key]
        else { return nil }
        return value
    }
}
