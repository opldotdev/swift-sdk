import BSVCore
import BSVKeys
import Testing

@Suite("Recoverable signatures")
struct RecoverableSignatureTests {
    private let vectorPrivateKey =
        "5f6d5afecc677d66fb3d41eee7a8ad8195659ceff588edaf416a9a17daf38fdd"
    private let vectorDigest =
        "6021a7ea347ba2d3bf392277cd59713cb0ea590f5697d1797a7d4ab6d86d58d4"
    private let vectorCompact =
        "74b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac"
        + "566e3d0c0ee77fa15cd1a8bf3b26366908dfa42e5f0481c73f1a23a2816260f8"

    @Test("RFC 6979 exact-digest signature and recovery match the upstream known answer")
    func exactKnownAnswer() throws {
        let key = try PrivateKey(hex(vectorPrivateKey))
        let digest = try Hash256(hex(vectorDigest))

        let signature = try key.signRecoverable(digest: digest)

        #expect(signature.compactBytes == (try hex(vectorCompact)))
        #expect(signature.recoveryID == 1)
        #expect(try signature.recoverPublicKey(digest: digest) == key.publicKey)
        #expect(key.publicKey.verify(signature.ecdsaSignature, digest: digest))
    }

    @Test("fixed keys recover across zero, arbitrary, and all-ff digests")
    func fixedSignAndRecoverCases() throws {
        let cases = [
            (
                String(repeating: "00", count: 31) + "01",
                String(repeating: "00", count: 32)
            ),
            (
                String(repeating: "00", count: 31) + "02",
                "000102030405060708090a0b0c0d0e0f"
                    + "101112131415161718191a1b1c1d1e1f"
            ),
            (
                String(repeating: "00", count: 31) + "03",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                String(repeating: "ff", count: 32)
            ),
        ]
        let halfOrder = try hex(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
        )

        for (privateKeyHex, digestHex) in cases {
            let key = try PrivateKey(hex(privateKeyHex))
            let digest = try Hash256(hex(digestHex))
            let first = try key.signRecoverable(digest: digest)
            let second = try key.signRecoverable(digest: digest)

            #expect(first == second)
            #expect(Array(first.compactBytes[32..<64]).lexicographicallyPrecedes(halfOrder)
                || Array(first.compactBytes[32..<64]) == halfOrder)
            #expect(try first.recoverPublicKey(digest: digest) == key.publicKey)
        }
    }

    @Test("wrong digest returns another candidate or a typed failure")
    func wrongDigestIsNotAuthentication() throws {
        let key = try PrivateKey(hex(vectorPrivateKey))
        let signature = try key.signRecoverable(digest: Hash256(hex(vectorDigest)))
        var wrongBytes = try hex(vectorDigest)
        wrongBytes[31] ^= 1
        let wrongDigest = try Hash256(wrongBytes)

        do {
            let candidate = try signature.recoverPublicKey(digest: wrongDigest)
            #expect(candidate != key.publicKey)
        } catch {
            #expect(error as? RecoverableSignatureError == .recoveryFailed)
        }
    }

    @Test("compact parsing rejects lengths, recovery IDs, and invalid scalars")
    func rejectsMalformedInput() throws {
        let valid = [UInt8](repeating: 0, count: 31) + [1]
            + [UInt8](repeating: 0, count: 31) + [1]

        #expect(throws: RecoverableSignatureError.invalidCompactByteCount(63)) {
            try RecoverableSignature(compactBytes: Array(valid.dropLast()), recoveryID: 0)
        }
        #expect(throws: RecoverableSignatureError.invalidCompactByteCount(65)) {
            try RecoverableSignature(compactBytes: valid + [0], recoveryID: 0)
        }
        #expect(throws: RecoverableSignatureError.invalidRecoveryID(4)) {
            try RecoverableSignature(compactBytes: valid, recoveryID: 4)
        }
        #expect(throws: RecoverableSignatureError.invalidRecoveryID(255)) {
            try RecoverableSignature(compactBytes: valid, recoveryID: 255)
        }

        let zero = [UInt8](repeating: 0, count: 32)
        let one = [UInt8](repeating: 0, count: 31) + [1]
        let order = try hex(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        )
        for compact in [zero + one, one + zero, order + one, one + order] {
            #expect(throws: RecoverableSignatureError.invalidCompactSignature) {
                try RecoverableSignature(compactBytes: compact, recoveryID: 0)
            }
        }
    }

    @Test("adversarial valid-range scalars fail without entering trapping recovery")
    func adversarialRecoveryFailuresAreTyped() throws {
        // Direct libsecp256k1 recovery edge vector: parsing succeeds for all IDs,
        // while x is not a valid recovery point for IDs 0, 2, and 3.
        let upstreamCompact = try hex(
            "67cb285f9cd194e840d629397af5569662fde44649995963179a7dd17bd23532"
                + "4b1b7df34ce1f68e694ff6f11ac751dd7dd73e387ee4fc866e1be8ecc7dd9557"
        )
        let upstreamDigest = try Hash256(Array("This is a very secret message...".utf8))
        for recoveryID in [0, 2, 3] {
            let signature = try RecoverableSignature(
                compactBytes: upstreamCompact,
                recoveryID: recoveryID
            )
            #expect(throws: RecoverableSignatureError.recoveryFailed) {
                try signature.recoverPublicKey(digest: upstreamDigest)
            }
        }
        let recoverable = try RecoverableSignature(
            compactBytes: upstreamCompact,
            recoveryID: 1
        )
        _ = try recoverable.recoverPublicKey(digest: upstreamDigest)

        // For IDs 2 and 3, r == p-n is the first forbidden value for x = r+n.
        let pMinusOrder = try hex(
            "000000000000000000000000000000014551231950b75fc4402da1722fc9baee"
        )
        let one = [UInt8](repeating: 0, count: 31) + [1]
        for recoveryID in [2, 3] {
            let signature = try RecoverableSignature(
                compactBytes: pMinusOrder + one,
                recoveryID: recoveryID
            )
            #expect(throws: RecoverableSignatureError.recoveryFailed) {
                try signature.recoverPublicKey(digest: upstreamDigest)
            }
        }

        // R = G, s = 1, and m = 1 makes sR - mG the point at infinity.
        let generatorX = try hex(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        let infinitySignature = try RecoverableSignature(
            compactBytes: generatorX + one,
            recoveryID: 0
        )
        let digestOne = try Hash256(one)
        #expect(throws: RecoverableSignatureError.recoveryFailed) {
            try infinitySignature.recoverPublicKey(digest: digestOne)
        }
    }

    @Test("high-S recovery interoperates without changing the ECDSA view")
    func highSRecovery() throws {
        let highCompact = try hex(
            "74b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac"
                + "a991c2f3f118805ea32e5740c4d9c995b1cf38b850441e7480b83aea4ed3e049"
        )
        let signature = try RecoverableSignature(
            compactBytes: highCompact,
            recoveryID: 0
        )
        let digest = try Hash256(hex(vectorDigest))
        let key = try PrivateKey(hex(vectorPrivateKey))

        #expect(signature.compactBytes == highCompact)
        #expect(signature.ecdsaSignature.compactBytes == highCompact)
        #expect(try signature.recoverPublicKey(digest: digest) == key.publicKey)
        #expect(!key.publicKey.verify(signature.ecdsaSignature, digest: digest))
    }

    @Test("ECDSA conversion, equality, hashing, value semantics, and Sendable surfaces")
    func publicValueSemantics() throws {
        let compact = try hex(vectorCompact)
        let first = try RecoverableSignature(compactBytes: compact, recoveryID: 1)
        let same = try RecoverableSignature(compactBytes: compact, recoveryID: 1)
        let differentID = try RecoverableSignature(compactBytes: compact, recoveryID: 0)
        var returned = first.compactBytes
        returned[0] ^= 0xff

        #expect(first == same)
        #expect(first != differentID)
        #expect(Set([first, same, differentID]).count == 2)
        #expect(first.compactBytes == compact)
        #expect(first.ecdsaSignature == (try ECDSASignature(compactBytes: compact)))
        requireSendable(RecoverableSignature.self)
        requireSendable(RecoverableSignatureError.self)
    }

    private func hex(_ text: String) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: 256)
    }

    private func requireSendable<T: Sendable>(_: T.Type) {}
}
