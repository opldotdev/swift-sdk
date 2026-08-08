import BSVCore
import BSVSPV
import Testing

@Suite("Block header")
struct BlockHeaderTests {
    private let genesisHex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

    @Test("parses, serializes, and hashes the genesis header")
    func genesisHeader() throws {
        let header = try BlockHeader(hex: genesisHex)
        let expectedMerkleRoot = try Hex.decode(
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            maximumDecodedByteCount: 32
        )

        #expect(header.version == 1)
        #expect(header.previousBlockHash.wireBytes == [UInt8](repeating: 0, count: 32))
        #expect(header.merkleRoot.bytes == expectedMerkleRoot)
        #expect(header.timestamp == 1_231_006_505)
        #expect(header.bits == 0x1d00ffff)
        #expect(header.nonce == 2_083_236_893)
        #expect(header.serializedBytes.count == BlockHeader.byteCount)
        #expect(header.hex == genesisHex)
        #expect(header.hash.displayHex == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
        #expect(header.description.contains(header.hash.displayHex))
    }

    @Test("preserves previous-block and Merkle-root wire order")
    func fieldByteOrder() throws {
        let blockOneHex = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299"
        let header = try BlockHeader(hex: blockOneHex)

        #expect(header.previousBlockHash.displayHex == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
        #expect(header.merkleRoot.bytes == Array(header.serializedBytes[36..<68]))
        #expect(header.hex == blockOneHex)
    }

    @Test("field construction preserves signed and unsigned boundaries")
    func fieldConstruction() throws {
        let header = BlockHeader(
            version: .min,
            previousBlockHash: try BlockHash(wireBytes: [UInt8](repeating: 0xaa, count: 32)),
            merkleRoot: try Hash256([UInt8](repeating: 0xbb, count: 32)),
            timestamp: .max,
            bits: .max,
            nonce: .max
        )

        let decoded = try BlockHeader(bytes: header.serializedBytes)
        #expect(decoded == header)
        #expect(decoded.version == .min)
        #expect(decoded.timestamp == .max)
        #expect(decoded.bits == .max)
        #expect(decoded.nonce == .max)
    }

    @Test("block hashes preserve wire and display order")
    func blockHashOrder() throws {
        let displayHex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        let hash = try BlockHash(displayHex: displayHex)
        let reparsed = try BlockHash(wireBytes: hash.wireBytes)

        #expect(hash.displayHex == displayHex)
        #expect(hash.wireBytes == Array(hash.displayBytes.reversed()))
        #expect(reparsed == hash)
        #expect(hash.description == displayHex)
        #expect(throws: TextEncodingError.invalidLength) {
            try BlockHash(displayHex: "00")
        }
    }

    @Test("rejects every non-header byte count", arguments: [0, 1, 79, 81, 160])
    func invalidByteCount(_ count: Int) {
        #expect(throws: FixedByteCountError.invalidByteCount(expected: 80, actual: count)) {
            try BlockHeader(bytes: [UInt8](repeating: 0, count: count))
        }
    }

    @Test("hex decoding is bounded and complete")
    func invalidHex() {
        #expect(throws: TextEncodingError.invalidCharacter(index: 0)) {
            try BlockHeader(hex: "zz")
        }
        #expect(throws: TextEncodingError.oddLength) {
            try BlockHeader(hex: "0")
        }
        #expect(throws: FixedByteCountError.invalidByteCount(expected: 80, actual: 79)) {
            try BlockHeader(hex: String(repeating: "00", count: 79))
        }
        #expect(throws: TextEncodingError.decodedSizeLimitExceeded(maximum: 80)) {
            try BlockHeader(hex: String(repeating: "00", count: 81))
        }
    }
}
