import BSVCore
import BSVKeys
import Testing

@Suite("Secp256k1PublicKey")
struct Secp256k1PublicKeyTests {
    private func generatorCompressed() throws -> [UInt8] {
        try Hex.decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            maximumDecodedByteCount: 33
        )
    }

    private func generatorUncompressed() throws -> [UInt8] {
        try Hex.decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            maximumDecodedByteCount: 65
        )
    }

    private func fieldPrime() throws -> [UInt8] {
        try Hex.decode(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            maximumDecodedByteCount: 32
        )
    }

    @Test("compressed, uncompressed, and hybrid representations normalize equally")
    func representationNormalization() throws {
        let generatorCompressed = try generatorCompressed()
        let generatorUncompressed = try generatorUncompressed()
        var hybrid = generatorUncompressed
        hybrid[0] = 0x06

        let compressed = try PublicKey(generatorCompressed)
        let uncompressed = try PublicKey(generatorUncompressed)
        let hybridKey = try PublicKey(hybrid)

        #expect(compressed == uncompressed)
        #expect(uncompressed == hybridKey)
        #expect(Set<BSVKeys.PublicKey>([compressed, uncompressed, hybridKey]).count == 1)
        #expect(hybridKey.compressedBytes == generatorCompressed)
        #expect(hybridKey.uncompressedBytes == generatorUncompressed)
        #expect(
            hybridKey.serialized(as: PublicKeyFormat.compressed) == generatorCompressed
        )
        #expect(
            hybridKey.serialized(as: PublicKeyFormat.uncompressed) == generatorUncompressed
        )
    }

    @Test("valid odd hybrid input is accepted and standardized")
    func oddHybrid() throws {
        var scalar = [UInt8](repeating: 0, count: 32)
        scalar[31] = 6
        let derived = try PrivateKey(scalar).publicKey
        #expect(derived.compressedBytes[0] == 0x03)

        var hybrid = derived.uncompressedBytes
        hybrid[0] = 0x07
        let reparsed = try PublicKey(hybrid)

        #expect(reparsed == derived)
        #expect(reparsed.compressedBytes[0] == 0x03)
        #expect(reparsed.uncompressedBytes[0] == 0x04)
    }

    @Test("length and prefix errors are stable and specific")
    func structuralErrors() throws {
        let generatorCompressed = try generatorCompressed()
        let generatorUncompressed = try generatorUncompressed()
        for count in [0, 32, 34, 64, 66] {
            #expect(throws: Secp256k1KeyError.invalidPublicKeyByteCount(count)) {
                try PublicKey([UInt8](repeating: 0, count: count))
            }
        }

        for prefix: UInt8 in [0x00, 0x01, 0x04, 0x06, 0x07, 0xff] {
            var bytes = generatorCompressed
            bytes[0] = prefix
            #expect(throws: Secp256k1KeyError.invalidPublicKeyPrefix(prefix)) {
                try PublicKey(bytes)
            }
        }

        for prefix: UInt8 in [0x00, 0x02, 0x03, 0x05, 0x08, 0xff] {
            var bytes = generatorUncompressed
            bytes[0] = prefix
            #expect(throws: Secp256k1KeyError.invalidPublicKeyPrefix(prefix)) {
                try PublicKey(bytes)
            }
        }
    }

    @Test("hybrid parity mismatch is rejected before point parsing")
    func hybridParityMismatch() throws {
        let generatorUncompressed = try generatorUncompressed()
        var evenPointAsOdd = generatorUncompressed
        evenPointAsOdd[0] = 0x07
        #expect(throws: Secp256k1KeyError.invalidHybridParity) {
            try PublicKey(evenPointAsOdd)
        }

        var malformed = [UInt8](repeating: 0, count: 65)
        malformed[0] = 0x07
        #expect(throws: Secp256k1KeyError.invalidHybridParity) {
            try PublicKey(malformed)
        }
    }

    @Test("field overflow, off-curve, and malformed points normalize to invalidPublicKey")
    func invalidPoints() throws {
        let fieldPrime = try fieldPrime()
        let generatorUncompressed = try generatorUncompressed()
        var xAtPrime = [UInt8](repeating: 0, count: 33)
        xAtPrime[0] = 0x02
        xAtPrime.replaceSubrange(1..., with: fieldPrime)
        #expect(throws: Secp256k1KeyError.invalidPublicKey) {
            try PublicKey(xAtPrime)
        }

        var xAbovePrime = fieldPrime
        xAbovePrime[31] += 1
        #expect(throws: Secp256k1KeyError.invalidPublicKey) {
            try PublicKey([0x02] + xAbovePrime)
        }

        var yAtPrime = generatorUncompressed
        yAtPrime.replaceSubrange(33..., with: fieldPrime)
        #expect(throws: Secp256k1KeyError.invalidPublicKey) {
            try PublicKey(yAtPrime)
        }

        var offCurve = generatorUncompressed
        offCurve.replaceSubrange(33..., with: [UInt8](repeating: 0, count: 32))
        #expect(throws: Secp256k1KeyError.invalidPublicKey) {
            try PublicKey(offCurve)
        }

        var hybridOffCurve = offCurve
        hybridOffCurve[0] = 0x06
        #expect(throws: Secp256k1KeyError.invalidPublicKey) {
            try PublicKey(hybridOffCurve)
        }

        var malformedCompressed = [UInt8](repeating: 0, count: 33)
        malformedCompressed[0] = 0x02
        malformedCompressed[32] = 0x05
        #expect(throws: Secp256k1KeyError.invalidPublicKey) {
            try PublicKey(malformedCompressed)
        }
    }

    @Test("deterministic valid scalars round-trip through every accepted representation")
    func deterministicRoundTrips() throws {
        for seed in UInt8(1)...UInt8(32) {
            var scalar = (0..<32).map { index in
                UInt8(truncatingIfNeeded: Int(seed) &* 73 + index &* 151 + 19)
            }
            scalar[0] = 0
            scalar[31] |= 1

            let derived = try PrivateKey(scalar).publicKey
            var hybrid = derived.uncompressedBytes
            hybrid[0] = 0x06 | (hybrid[64] & 1)

            #expect(try PublicKey(derived.compressedBytes) == derived)
            #expect(try PublicKey(derived.uncompressedBytes) == derived)
            #expect(try PublicKey(hybrid) == derived)
        }
    }
}
