import BSVCore
@testable import BSVCrypto
import Testing

@Suite("Go-compatible symmetric key envelope")
struct SymmetricKeyTests {
    @Test("short keys are left padded and Base64 round trips canonically")
    func keyConstruction() throws {
        for count in [1, 15, 16, 24, 31, 32] {
            let input = [UInt8](repeating: UInt8(count), count: count)
            let key = try SymmetricKey(input)
            #expect(key.bytes.count == 32)
            #expect(key.bytes.suffix(count) == input[...])
            #expect(key.bytes.prefix(32 - count).allSatisfy { $0 == 0 })
            #expect(try SymmetricKey(base64Encoded: key.base64Encoded).bytes == key.bytes)
            #expect(key.description == "<redacted symmetric key>")
            #expect(String(reflecting: key) == "<redacted symmetric key>")
        }
    }

    @Test("empty and oversized keys are rejected")
    func invalidKeyLengths() {
        for count in [0, 33, 1_024] {
            #expect(throws: SymmetricKeyError.invalidKeyByteCount(count)) {
                try SymmetricKey([UInt8](repeating: 1, count: count))
            }
        }
        #expect(throws: SymmetricKeyError.invalidBase64Encoding) {
            try SymmetricKey(base64Encoded: "not base64")
        }
    }

    @Test("deterministic envelope is nonce then ciphertext then tag")
    func deterministicEnvelope() throws {
        let key = try SymmetricKey(deterministicBytes(count: 31))
        let nonce = deterministicBytes(count: 32, offset: 41)
        let plaintext = deterministicBytes(count: 73, offset: 9)
        let envelope = try key.seal(plaintext, nonce: nonce)

        #expect(envelope.count == 32 + plaintext.count + 16)
        #expect(envelope.prefix(32) == nonce[...])
        #expect(try key.open(envelope) == plaintext)
    }

    @Test("empty plaintext has the minimum valid envelope")
    func emptyPlaintext() throws {
        let key = try SymmetricKey([1])
        let envelope = try key.seal([], nonce: [UInt8](repeating: 2, count: 32))
        #expect(envelope.count == SymmetricKey.minimumEnvelopeByteCount)
        #expect(try key.open(envelope).isEmpty)
    }

    @Test("random key and envelope are usable and fresh")
    func randomRoundTrip() throws {
        let key = try SymmetricKey.random()
        let plaintext = Array("cross-platform envelope".utf8)
        let first = try key.seal(plaintext)
        let second = try key.seal(plaintext)

        #expect(first != second)
        #expect(try key.open(first) == plaintext)
        #expect(try key.open(second) == plaintext)
    }

    @Test("randomness is injectable and exact-length failures are typed")
    func injectedRandomness() throws {
        let keyBytes = deterministicBytes(count: 32, offset: 47)
        let nonce = deterministicBytes(count: 32, offset: 53)
        let key = try SymmetricKey.random(using: FixedRandomSource(bytes: keyBytes))
        #expect(key.bytes == keyBytes)

        let envelope = try key.seal(
            [1, 2, 3],
            using: FixedRandomSource(bytes: nonce)
        )
        #expect(envelope.prefix(32) == nonce[...])

        #expect(throws: SymmetricKeyError.randomGenerationFailed) {
            try SymmetricKey.random(using: FixedRandomSource(bytes: [1]))
        }
        #expect(throws: SymmetricKeyError.randomGenerationFailed) {
            try key.seal([], using: FixedRandomSource(bytes: [2]))
        }
        #expect(throws: SymmetricKeyError.randomGenerationFailed) {
            try SymmetricKey.random(using: FailingRandomSource())
        }
        #expect(throws: SymmetricKeyError.randomGenerationFailed) {
            try key.seal([], using: FailingRandomSource())
        }
    }

    @Test("truncation and tampering fail without plaintext")
    func malformedEnvelopes() throws {
        let key = try SymmetricKey(deterministicBytes(count: 32))
        let envelope = try key.seal(
            deterministicBytes(count: 17),
            nonce: deterministicBytes(count: 32, offset: 7)
        )

        for count in [0, 1, 31, 32, 47] {
            #expect(throws: SymmetricKeyError.invalidEnvelopeByteCount(count)) {
                try key.open(Array(envelope.prefix(count)))
            }
        }
        for index in [0, 31, 32, envelope.count - 16, envelope.count - 1] {
            var tampered = envelope
            tampered[index] ^= 1
            #expect(throws: SymmetricKeyError.authenticationFailed) {
                try key.open(tampered)
            }
        }
    }

    private func deterministicBytes(count: Int, offset: Int = 0) -> [UInt8] {
        (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 29 &+ offset) }
    }
}

private struct FixedRandomSource: SecureRandomSource {
    let bytes: [UInt8]

    func randomBytes(count: Int) throws -> [UInt8] {
        bytes
    }
}

private struct FailingRandomSource: SecureRandomSource {
    func randomBytes(count: Int) throws -> [UInt8] {
        throw TestRandomError.failed
    }
}

private enum TestRandomError: Error {
    case failed
}
