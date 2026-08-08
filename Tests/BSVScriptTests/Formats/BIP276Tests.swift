import BSVScript
import Testing

@Suite("BIP-276")
struct BIP276Tests {
    private func limits(text: Int = 1_024, prefix: Int = 32, data: Int = 256) throws -> BIP276Limits {
        try BIP276Limits(
            maximumTextByteCount: text,
            maximumPrefixByteCount: prefix,
            maximumDataByteCount: data
        )
    }

    @Test("canonical encode and decode preserve every field")
    func roundTrip() throws {
        let value = BIP276(
            prefix: BIP276.scriptPrefix,
            version: BIP276.currentVersion,
            network: BIP276.mainnet,
            data: Array("synthetic script".utf8)
        )
        let text = try value.encoded(limits: limits())
        #expect(text.hasPrefix("bitcoin-script:0101"))
        #expect(text == text.lowercased())
        #expect(try BIP276(text: text, limits: limits()) == value)

        let exact = try limits(text: text.utf8.count, prefix: 14, data: 16)
        #expect(try value.encoded(limits: exact) == text)
        #expect(try BIP276(text: text, limits: exact) == value)
    }

    @Test("empty data and all nonzero version and network bytes are representable")
    func byteBoundaries() throws {
        let value = BIP276(prefix: "x", version: .max, network: .max, data: [])
        let text = try value.encoded(limits: limits())
        let decoded = try BIP276(text: text, limits: limits())
        #expect(decoded.version == .max)
        #expect(decoded.network == .max)
        #expect(decoded.data.isEmpty)

        #expect(throws: BIP276Error.invalidVersion) {
            try BIP276(prefix: "x", version: 0, network: 1, data: []).encoded(limits: limits())
        }
        #expect(throws: BIP276Error.invalidNetwork) {
            try BIP276(prefix: "x", version: 1, network: 0, data: []).encoded(limits: limits())
        }
        #expect(throws: BIP276Error.invalidVersion) {
            try BIP276(text: "x:0001ab1056ef", limits: limits())
        }
        #expect(throws: BIP276Error.invalidNetwork) {
            try BIP276(text: "x:0100d68783ad", limits: limits())
        }
    }

    @Test("negative limits are rejected independently")
    func negativeLimits() {
        #expect(throws: BIP276Error.invalidLimits) {
            try BIP276Limits(
                maximumTextByteCount: -1,
                maximumPrefixByteCount: 0,
                maximumDataByteCount: 0
            )
        }
        #expect(throws: BIP276Error.invalidLimits) {
            try BIP276Limits(
                maximumTextByteCount: 0,
                maximumPrefixByteCount: -1,
                maximumDataByteCount: 0
            )
        }
        #expect(throws: BIP276Error.invalidLimits) {
            try BIP276Limits(
                maximumTextByteCount: 0,
                maximumPrefixByteCount: 0,
                maximumDataByteCount: -1
            )
        }
    }

    @Test("encode and decode accept exact limits and reject max plus one")
    func exactLimits() throws {
        let value = BIP276(prefix: "x", version: 1, network: 2, data: [0xaa, 0xbb])
        let text = try BIP276.encode(value, limits: limits())
        #expect(text.utf8.count == 18)
        #expect(try BIP276.decode(text, limits: limits(text: 18, prefix: 1, data: 2)) == value)
        #expect(try BIP276.encode(value, limits: limits(text: 18, prefix: 1, data: 2)) == text)

        #expect(throws: BIP276Error.textTooLarge(actual: 18, maximum: 17)) {
            try BIP276.encode(value, limits: limits(text: 17, prefix: 1, data: 2))
        }
        #expect(throws: BIP276Error.prefixTooLarge(actual: 1, maximum: 0)) {
            try BIP276.encode(value, limits: limits(text: 18, prefix: 0, data: 2))
        }
        #expect(throws: BIP276Error.dataTooLarge(actual: 2, maximum: 1)) {
            try BIP276.encode(value, limits: limits(text: 18, prefix: 1, data: 1))
        }
        #expect(throws: BIP276Error.textTooLarge(actual: 18, maximum: 17)) {
            try BIP276.decode(text, limits: limits(text: 17, prefix: 1, data: 2))
        }
        #expect(throws: BIP276Error.prefixTooLarge(actual: 1, maximum: 0)) {
            try BIP276.decode(text, limits: limits(text: 18, prefix: 0, data: 2))
        }
        #expect(throws: BIP276Error.dataTooLarge(actual: 2, maximum: 1)) {
            try BIP276.decode(text, limits: limits(text: 18, prefix: 1, data: 1))
        }
    }

    @Test("Swift intentionally narrows the Go prefix domain")
    func strictPrefixDomain() throws {
        for prefix in ["A", "a_b", "a.b"] {
            #expect(throws: BIP276Error.invalidPrefix) {
                try BIP276(prefix: prefix, version: 1, network: 1, data: [])
                    .encoded(limits: limits())
            }
        }
    }

    @Test("checksum, canonical form, malformed text, Unicode, and limits fail closed")
    func rejection() throws {
        let value = BIP276(prefix: BIP276.scriptPrefix, version: 1, network: 2, data: [0, 0xff])
        let text = try value.encoded(limits: limits())
        let replacement = text.last == "0" ? "1" : "0"
        #expect(throws: BIP276Error.invalidChecksum) {
            try BIP276(text: String(text.dropLast()) + replacement, limits: limits())
        }
        #expect(throws: BIP276Error.nonCanonicalText) {
            try BIP276(text: text.uppercased(), limits: limits())
        }
        #expect(throws: BIP276Error.invalidFormat) {
            try BIP276(text: "bitcoin-script:01", limits: limits())
        }
        #expect(throws: BIP276Error.invalidPrefix) {
            try BIP276(prefix: "bítcoin-script", version: 1, network: 1, data: [])
                .encoded(limits: limits())
        }
        #expect(throws: BIP276Error.dataTooLarge(actual: 3, maximum: 2)) {
            try BIP276(prefix: "x", version: 1, network: 1, data: [1, 2, 3])
                .encoded(limits: limits(data: 2))
        }
        #expect(throws: BIP276Error.textTooLarge(actual: 11, maximum: 10)) {
            try BIP276(text: String(repeating: "a", count: 1_000_000), limits: limits(text: 10))
        }
    }

    @Test("decode reports prefix and data limits directly")
    func directDecodeLimits() throws {
        let prefixText = try BIP276(prefix: "abc", version: 1, network: 1, data: [])
            .encoded(limits: limits())
        #expect(throws: BIP276Error.prefixTooLarge(actual: 3, maximum: 2)) {
            try BIP276.decode(prefixText, limits: limits(prefix: 2))
        }

        let dataText = try BIP276(prefix: "x", version: 1, network: 1, data: [1, 2, 3])
            .encoded(limits: limits())
        #expect(throws: BIP276Error.dataTooLarge(actual: 3, maximum: 2)) {
            try BIP276.decode(dataText, limits: limits(data: 2))
        }
    }

    @Test("every proper truncation of canonical text is rejected")
    func truncation() throws {
        let text = try BIP276(prefix: "x", version: 1, network: 1, data: [0xaa, 0xbb])
            .encoded(limits: limits())
        for byteCount in 0..<text.utf8.count {
            let truncated = String(decoding: text.utf8.prefix(byteCount), as: UTF8.self)
            #expect(throws: BIP276Error.self) {
                try BIP276(text: truncated, limits: limits())
            }
        }
    }

    @Test("public values satisfy Sendable constraints")
    func sendable() throws {
        func requireSendable<T: Sendable>(_: T) {}
        requireSendable(BIP276(prefix: "x", version: 1, network: 1, data: []))
        requireSendable(try limits())
        requireSendable(BIP276Error.invalidChecksum)
    }
}
