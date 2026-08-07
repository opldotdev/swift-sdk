import BSVCore
import Foundation
import Testing

@Suite("CompactSizeConformance", .serialized)
struct CompactSizeConformanceTests {
    @Test("BTCD manifest fragment and hashes verify through the P0 loader")
    func manifestVerification() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "compactsize-btcd-v0.24.2" }
        )

        #expect(group.schema == FixtureManifestLoader.schema)
        #expect(group.source.url == "https://github.com/btcsuite/btcd")
        #expect(group.source.revision == "v0.24.2")
        #expect(group.license.identifier == "ISC")
        #expect(group.license.file == "Licenses/btcd-isc.txt")
        #expect(
            group.license.sha256
                == "73b368e7df1c52ce72711298096da6dd1509a9e261b53f864d721992b3da3eb7"
        )

        let file = try #require(group.files.first)
        #expect(file.originalPath == "wire/common_test.go")
        #expect(file.localPath == "Permissive/BTCD/CompactSize/compactsize.json")
        #expect(
            file.sha256
                == "a556d0a2e279ce82e0e755051d8a8f347e1774fcecf725ee22c0dbb384d8382a"
        )
        #expect(file.transformation.contains("TestVarIntWire"))
        #expect(file.transformation.contains("TestVarBytesWire"))
    }

    @Test("Committed BTCD vectors agree with public BSVCore APIs")
    func staticVectors() throws {
        let fixture = try loadFixture()

        for testCase in fixture.compactSize {
            let value = try #require(UInt64(testCase.value))
            let image = try decodeHex(testCase.hex)
            #expect(CompactSize.encodedLength(of: value) == image.count)
            #expect(CompactSize.encode(value) == image)
            let decoded = try CompactSize.decode(image)
            #expect(decoded.value == value)
            #expect(decoded.bytesConsumed == image.count)
            #expect(decoded.isCanonical)
        }

        for testCase in fixture.nonCanonical {
            let value = try #require(UInt64(testCase.value))
            let image = try decodeHex(testCase.hex)
            #expect(throws: BinaryDecodingError.nonCanonicalCompactSize) {
                try CompactSize.decode(image)
            }
            let decoded = try CompactSize.decode(image, canonicality: .permissive)
            #expect(decoded.value == value)
            #expect(decoded.bytesConsumed == image.count)
            #expect(!decoded.isCanonical)
        }

        for testCase in fixture.varBytes {
            let value = try decodeHex(testCase.bytesHex)
            let image = try decodeHex(testCase.hex)
            #expect(CompactSize.encodeVarBytes(value) == image)
            let decoded = try CompactSize.decodeVarBytes(
                image,
                maximumLength: UInt64(value.count)
            )
            #expect(decoded.bytes == value)
            #expect(decoded.bytesConsumed == image.count)
            #expect(decoded.isCanonical)
        }
    }

    @Test("Real Go oracle differentials cover permissive noncanonical and max-u64")
    func realGoOracleDifferentials() throws {
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("CompactSize Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let fixture = try loadFixture()
            var sequence = 0

            for testCase in fixture.nonCanonical {
                sequence += 1
                let image = try decodeHex(testCase.hex)
                let swift = try CompactSize.decode(image, canonicality: .permissive)
                let response = try client.request(
                    id: "compactsize-noncanonical-\(sequence)",
                    operation: "varint.decode",
                    arguments: [
                        "bytes": .string(testCase.hex),
                        "canonical": .string("permissive"),
                    ]
                )
                #expect(response.ok)
                #expect(
                    response.result == .object([
                        "value": .string(String(swift.value)),
                        "bytesConsumed": .string(String(swift.bytesConsumed)),
                        "isCanonical": .bool(swift.isCanonical),
                    ])
                )
            }

            let maxImage = CompactSize.encode(UInt64.max)
            let swiftMax = try CompactSize.decode(maxImage, canonicality: .permissive)
            let maxResponse = try client.request(
                id: "compactsize-max-u64",
                operation: "varint.decode",
                arguments: [
                    "bytes": .string(encodeHex(maxImage)),
                    "canonical": .string("permissive"),
                ]
            )
            #expect(maxResponse.ok)
            #expect(
                maxResponse.result == .object([
                    "value": .string(String(swiftMax.value)),
                    "bytesConsumed": .string(String(swiftMax.bytesConsumed)),
                    "isCanonical": .bool(swiftMax.isCanonical),
                ])
            )
        }
    }
}

private struct CompactSizeFixture: Decodable {
    let compactSize: [CompactSizeFixtureCase]
    let nonCanonical: [CompactSizeFixtureCase]
    let varBytes: [VarBytesFixtureCase]
}

private struct CompactSizeFixtureCase: Decodable {
    let value: String
    let hex: String
}

private struct VarBytesFixtureCase: Decodable {
    let bytesHex: String
    let hex: String
}

private enum CompactSizeFixtureError: Error {
    case fixtureRootUnavailable
    case invalidHex(String)
}

private func loadFixture() throws -> CompactSizeFixture {
    guard let root = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
        throw CompactSizeFixtureError.fixtureRootUnavailable
    }
    let url = root.appendingPathComponent(
        "Permissive/BTCD/CompactSize/compactsize.json",
        isDirectory: false
    )
    return try JSONDecoder().decode(
        CompactSizeFixture.self,
        from: Data(contentsOf: url, options: [.mappedIfSafe])
    )
}

private func decodeHex(_ text: String) throws -> [UInt8] {
    guard text.utf8.count.isMultiple(of: 2) else {
        throw CompactSizeFixtureError.invalidHex(text)
    }
    var result: [UInt8] = []
    result.reserveCapacity(text.utf8.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let end = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<end], radix: 16) else {
            throw CompactSizeFixtureError.invalidHex(text)
        }
        result.append(byte)
        index = end
    }
    return result
}

private func encodeHex(_ bytes: [UInt8]) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var encoded = [UInt8]()
    encoded.reserveCapacity(bytes.count * 2)
    for byte in bytes {
        encoded.append(digits[Int(byte >> 4)])
        encoded.append(digits[Int(byte & 0x0f)])
    }
    return String(decoding: encoded, as: UTF8.self)
}
