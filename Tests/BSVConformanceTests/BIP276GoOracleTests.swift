import BSVCore
import BSVScript
import Testing

@Suite("BIP-276 Go conformance", .serialized)
struct BIP276GoOracleTests {
    @Test("pinned Go v1.3.3 agrees on deterministic BIP-276 text and fields")
    func differentials() throws {
        let limits = try BIP276Limits(
            maximumTextByteCount: 70_000,
            maximumPrefixByteCount: 128,
            maximumDataByteCount: 32 * 1_024
        )
        let cases = [
            BIP276(prefix: BIP276.scriptPrefix, version: 1, network: 1, data: []),
            BIP276(prefix: BIP276.templatePrefix, version: 1, network: 2, data: [0, 0x6a, 0xff]),
            BIP276(prefix: "synthetic", version: .max, network: .max, data: Array(repeating: 0x5a, count: 75)),
            BIP276(prefix: "synthetic-2", version: 7, network: 19, data: Array(repeating: 0xa5, count: 76)),
            BIP276(prefix: "x", version: 1, network: 2, data: Array(repeating: 0x5a, count: 32_768)),
        ]

        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BIP-276 Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for (index, value) in cases.enumerated() {
                let swiftText = try value.encoded(limits: limits)
                let encoded = try client.request(
                    id: "bip276-encode-\(index)",
                    operation: "script.bip276.encode",
                    arguments: [
                        "prefix": .string(value.prefix),
                        "version": .string(String(value.version)),
                        "network": .string(String(value.network)),
                        "data": .string(Hex.encode(value.data)),
                    ]
                )
                #expect(encoded.ok)
                #expect(encoded.result == .object(["text": .string(swiftText)]))

                let decoded = try client.request(
                    id: "bip276-decode-\(index)",
                    operation: "script.bip276.decode",
                    arguments: ["text": .string(swiftText)]
                )
                #expect(decoded.ok)
                #expect(decoded.result == .object([
                    "prefix": .string(value.prefix),
                    "version": .string(String(value.version)),
                    "network": .string(String(value.network)),
                    "data": .string(Hex.encode(value.data)),
                ]))
            }
        }
    }

    @Test("Go accepts its wider prefix domain while Swift rejects it explicitly")
    func prefixDomainDeviation() throws {
        let limits = try BIP276Limits(
            maximumTextByteCount: 1_024,
            maximumPrefixByteCount: 128,
            maximumDataByteCount: 32_768
        )
        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BIP-276 Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            for (index, prefix) in ["A", "a_b", "a.b"].enumerated() {
                #expect(throws: BIP276Error.invalidPrefix) {
                    try BIP276(prefix: prefix, version: 1, network: 1, data: [0xaf])
                        .encoded(limits: limits)
                }
                let encoded = try client.request(
                    id: "bip276-prefix-encode-\(index)",
                    operation: "script.bip276.encode",
                    arguments: [
                        "prefix": .string(prefix),
                        "version": .string("1"),
                        "network": .string("1"),
                        "data": .string("af"),
                    ]
                )
                #expect(encoded.ok)
                guard case .object(let result)? = encoded.result,
                      case .string(let text)? = result["text"] else {
                    Issue.record("Go BIP-276 encode omitted text")
                    continue
                }
                let decoded = try client.request(
                    id: "bip276-prefix-decode-\(index)",
                    operation: "script.bip276.decode",
                    arguments: ["text": .string(text)]
                )
                #expect(decoded.ok)
                #expect(decoded.result == .object([
                    "prefix": .string(prefix),
                    "version": .string("1"),
                    "network": .string("1"),
                    "data": .string("af"),
                ]))
            }
        }
    }

    @Test("32 KiB plus one and zero header bytes have stable failures")
    func adapterRejections() throws {
        let limits = try BIP276Limits(
            maximumTextByteCount: 70_000,
            maximumPrefixByteCount: 128,
            maximumDataByteCount: 32_768
        )
        let oversized = Array(repeating: UInt8(0xa5), count: 32_769)
        #expect(throws: BIP276Error.dataTooLarge(actual: 32_769, maximum: 32_768)) {
            try BIP276(prefix: "x", version: 1, network: 1, data: oversized)
                .encoded(limits: limits)
        }

        let configuration = GoOracleConfiguration.default()
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("BIP-276 Go oracle unavailable: \(reason)")
        case .available(let client):
            defer { client.close() }
            let oversizedHex = Hex.encode(oversized)
            let encode = try client.request(
                id: "bip276-32769-encode",
                operation: "script.bip276.encode",
                arguments: [
                    "prefix": .string("x"),
                    "version": .string("1"),
                    "network": .string("1"),
                    "data": .string(oversizedHex),
                ]
            )
            #expect(!encode.ok)
            #expect(encode.error?.category == "resourceLimit")

            let decode = try client.request(
                id: "bip276-32769-decode",
                operation: "script.bip276.decode",
                arguments: ["text": .string("x:0101\(oversizedHex)00000000")]
            )
            #expect(!decode.ok)
            #expect(decode.error?.category == "resourceLimit")

            for (id, version, network, category) in [
                ("version", "0", "1", "unsupportedVersion"),
                ("network", "1", "0", "unsupportedNetwork"),
            ] {
                let response = try client.request(
                    id: "bip276-zero-\(id)",
                    operation: "script.bip276.encode",
                    arguments: [
                        "prefix": .string("x"),
                        "version": .string(version),
                        "network": .string(network),
                        "data": .string(""),
                    ]
                )
                #expect(!response.ok)
                #expect(response.error?.category == category)
            }

            for (id, text, category) in [
                ("version", "x:0001ab1056ef", "unsupportedVersion"),
                ("network", "x:0100d68783ad", "unsupportedNetwork"),
            ] {
                let response = try client.request(
                    id: "bip276-zero-decode-\(id)",
                    operation: "script.bip276.decode",
                    arguments: ["text": .string(text)]
                )
                #expect(!response.ok)
                #expect(response.error?.category == category)
            }
        }
    }
}
