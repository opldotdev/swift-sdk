import BSVCrypto
import Testing

@Suite("HMAC-DRBG")
struct HMACDRBGTests {
    private let entropy32 = (0..<32).map { UInt8($0) }

    @Test("diagnostics and reflection redact deterministic state")
    func diagnosticRedaction() throws {
        let secretStateByte = "191"
        let generator = try HMACDRBG(entropy: entropy32)
        let described = String(describing: generator)
        let reflected = String(reflecting: generator)
        var dumped = ""
        dump(generator, to: &dumped)

        #expect(described == "<redacted HMAC-DRBG>")
        #expect(reflected == "<redacted HMAC-DRBG>")
        #expect(dumped.contains("<redacted HMAC-DRBG>"))
        #expect(Mirror(reflecting: generator).children.isEmpty)
        for diagnostic in [described, reflected, dumped] {
            #expect(!diagnostic.contains(secretStateByte))
        }
    }

    @Test("entropy minimum accepts 32 and 33 bytes but rejects 31")
    func entropyBoundaries() throws {
        #expect(
            throws: HMACDRBGError.insufficientEntropy(
                minimumByteCount: 32,
                actualByteCount: 31
            )
        ) {
            try HMACDRBG(entropy: [UInt8](repeating: 7, count: 31))
        }

        var exact = try HMACDRBG(entropy: entropy32)
        var above = try HMACDRBG(entropy: entropy32 + [32])
        #expect(try exact.generate(count: 32).count == 32)
        #expect(try above.generate(count: 32).count == 32)
    }

    @Test("empty and nonempty nonces are concatenated into deterministic seed material")
    func nonceBehavior() throws {
        var defaultNonce = try HMACDRBG(entropy: entropy32)
        var explicitEmpty = try HMACDRBG(entropy: entropy32, nonce: [])
        var nonempty = try HMACDRBG(entropy: entropy32, nonce: [0xa0, 0xa1, 0xa2])

        let defaultOutput = try defaultNonce.generate(count: 48)
        #expect(try explicitEmpty.generate(count: 48) == defaultOutput)
        #expect(try nonempty.generate(count: 48) != defaultOutput)
    }

    @Test("equal initial state repeats while sequential requests advance")
    func deterministicAndSequential() throws {
        var first = try HMACDRBG(entropy: entropy32, nonce: [1, 2, 3, 4])
        var second = try HMACDRBG(entropy: entropy32, nonce: [1, 2, 3, 4])

        let firstOutput = try first.generate(count: 64)
        #expect(try second.generate(count: 64) == firstOutput)
        #expect(try first.generate(count: 64) != firstOutput)
        #expect(first.reseedCounter == 3)
    }

    @Test("zero and maximum requests advance state; invalid sizes are transactional")
    func generationBoundariesAndTransactions() throws {
        var generator = try HMACDRBG(entropy: entropy32)
        #expect(try generator.generate(count: 0) == [])
        #expect(generator.reseedCounter == 2)
        #expect(try generator.generate(count: 937).count == 937)
        #expect(generator.reseedCounter == 3)

        var afterRejected = generator
        var untouched = generator
        #expect(throws: HMACDRBGError.invalidRequestedByteCount(-1)) {
            try afterRejected.generate(count: -1)
        }
        #expect(
            throws: HMACDRBGError.requestTooLarge(
                maximumByteCount: 937,
                actualByteCount: 938
            )
        ) {
            try afterRejected.generate(count: 938)
        }
        #expect(try afterRejected.generate(count: 32) == untouched.generate(count: 32))
        #expect(afterRejected.reseedCounter == untouched.reseedCounter)
    }

    @Test("reseed enforces its entropy minimum transactionally and resets state")
    func reseedBoundariesAndTransactions() throws {
        var rejected = try HMACDRBG(entropy: entropy32, nonce: [9])
        var untouched = rejected
        #expect(
            throws: HMACDRBGError.insufficientEntropy(
                minimumByteCount: 32,
                actualByteCount: 31
            )
        ) {
            try rejected.reseed(entropy: [UInt8](repeating: 8, count: 31))
        }
        #expect(try rejected.generate(count: 32) == untouched.generate(count: 32))

        try rejected.reseed(entropy: [UInt8](repeating: 0x55, count: 32))
        #expect(rejected.reseedCounter == 1)
        let reseededOutput = try rejected.generate(count: 32)
        #expect(reseededOutput != (try untouched.generate(count: 32)))
    }

    @Test("request 10,000 is allowed and request 10,001 requires reseeding")
    func reseedCounterBoundary() throws {
        var generator = try HMACDRBG(entropy: entropy32)
        for _ in 0..<9_999 {
            _ = try generator.generate(count: 0)
        }
        #expect(generator.reseedCounter == 10_000)
        #expect(try generator.generate(count: 0) == [])
        #expect(generator.reseedCounter == 10_001)

        #expect(throws: HMACDRBGError.reseedRequired) {
            try generator.generate(count: 0)
        }
        #expect(generator.reseedCounter == 10_001)

        try generator.reseed(entropy: [UInt8](repeating: 0x42, count: 32))
        #expect(generator.reseedCounter == 1)
        #expect(try generator.generate(count: 1).count == 1)
    }
}
