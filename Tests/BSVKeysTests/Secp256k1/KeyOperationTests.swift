import BSVCore
import BSVKeys
import Testing

@Suite("Secp256k1 key operations")
struct KeyOperationTests {
    @Test("tweaks require exactly 32 bytes")
    func tweakByteCounts() throws {
        let privateKey = try PrivateKey(scalar(3))
        let publicKey = privateKey.publicKey

        for count in [31, 33] {
            let tweak = [UInt8](repeating: 1, count: count)
            #expect(throws: Secp256k1OperationError.invalidTweakByteCount(count)) {
                try privateKey.adding(tweak: tweak)
            }
            #expect(throws: Secp256k1OperationError.invalidTweakByteCount(count)) {
                try privateKey.multiplying(by: tweak)
            }
            #expect(throws: Secp256k1OperationError.invalidTweakByteCount(count)) {
                try publicKey.adding(tweak: tweak)
            }
            #expect(throws: Secp256k1OperationError.invalidTweakByteCount(count)) {
                try publicKey.multiplying(by: tweak)
            }
        }

        #expect(try privateKey.adding(tweak: scalar(1)).bytes == scalar(4))
    }

    @Test("order-or-greater tweaks are rejected")
    func invalidTweakScalars() throws {
        let privateKey = try PrivateKey(scalar(3))
        let publicKey = privateKey.publicKey
        let invalidTweaks = [
            try curveOrder(),
            [UInt8](repeating: 0xff, count: 32),
        ]

        for tweak in invalidTweaks {
            #expect(throws: Secp256k1OperationError.invalidTweak) {
                try privateKey.adding(tweak: tweak)
            }
            #expect(throws: Secp256k1OperationError.invalidTweak) {
                try privateKey.multiplying(by: tweak)
            }
            #expect(throws: Secp256k1OperationError.invalidTweak) {
                try publicKey.adding(tweak: tweak)
            }
            #expect(throws: Secp256k1OperationError.invalidTweak) {
                try publicKey.multiplying(by: tweak)
            }
        }
    }

    @Test("zero is the additive identity but is invalid for multiplication")
    func zeroTweakSemantics() throws {
        let privateKey = try PrivateKey(scalar(3))
        let publicKey = privateKey.publicKey
        let zero = [UInt8](repeating: 0, count: 32)

        #expect(try privateKey.adding(tweak: zero) == privateKey)
        #expect(try publicKey.adding(tweak: zero) == publicKey)
        #expect(throws: Secp256k1OperationError.invalidTweak) {
            try privateKey.multiplying(by: zero)
        }
        #expect(throws: Secp256k1OperationError.invalidTweak) {
            try publicKey.multiplying(by: zero)
        }
    }

    @Test("one and order minus one are valid tweaks")
    func validTweakBoundaries() throws {
        let privateKey = try PrivateKey(scalar(2))
        let one = scalar(1)
        let maximum = try curveOrderMinusOne()

        #expect(try privateKey.adding(tweak: one).bytes == scalar(3))
        #expect(try privateKey.multiplying(by: one) == privateKey)
        #expect(try privateKey.publicKey.multiplying(by: one) == privateKey.publicKey)

        let addedMaximum = try privateKey.adding(tweak: maximum)
        #expect(addedMaximum.bytes == one)
        #expect(try privateKey.publicKey.adding(tweak: maximum) == addedMaximum.publicKey)

        let multipliedMaximum = try privateKey.multiplying(by: maximum)
        #expect(try privateKey.publicKey.multiplying(by: maximum) == multipliedMaximum.publicKey)
    }

    @Test("addition rejects a zero private result and point at infinity")
    func additiveZeroResults() throws {
        let privateKey = try PrivateKey(scalar(1))
        let negatedOne = try curveOrderMinusOne()

        #expect(throws: Secp256k1OperationError.invalidTweak) {
            try privateKey.adding(tweak: negatedOne)
        }
        #expect(throws: Secp256k1OperationError.invalidTweak) {
            try privateKey.publicKey.adding(tweak: negatedOne)
        }
    }

    @Test("private and public tweaks derive identical points")
    func privatePublicConsistency() throws {
        let key = try PrivateKey(decode(
            "7da12cc39bb4189ac72d34fc2225df5cf36aaacdcac7e5a43963299bc8d888ed"
        ))
        let tweak = try decode(
            "e16c76552b2c16ca734b6454c331774fb135c6fad0a34816bcfd16ae8970db0a"
        )

        let addedPrivate = try key.adding(tweak: tweak)
        let addedPublic = try key.publicKey.adding(tweak: tweak)
        #expect(
            Hex.encode(addedPrivate.bytes)
                == "5f0da318c6e02f653a789950e55756ade9f194e1ec228d7f368de1bd821322b6"
        )
        #expect(addedPrivate.publicKey == addedPublic)

        let multipliedPrivate = try key.multiplying(by: tweak)
        let multipliedPublic = try key.publicKey.multiplying(by: tweak)
        #expect(multipliedPrivate.publicKey == multipliedPublic)
    }

    @Test("known ECDH point is returned in complete SEC1 forms")
    func exactECDHPointSerialization() throws {
        let identityPrivateKey = try PrivateKey(scalar(1))
        let peerPrivateKey = try PrivateKey(decode(
            "703d3b63e84421e59f9359f8b27c25365df9d85b6b1566e3168412fa599c12f4"
        ))
        let expectedCompressed = try decode(
            "02c9c68596824505dd6cd1993a16452b4b1a13bacde56f80e9049fd03850cce137"
        )
        let expectedUncompressed = try decode(
            "04c9c68596824505dd6cd1993a16452b4b1a13bacde56f80e9049fd03850cce137"
                + "c1fa4acb7bef7edcc04f4fa29e071ea17e34fa07fa5d87b5ebf6340df6558498"
        )

        let sharedPoint = try identityPrivateKey.sharedSecret(with: peerPrivateKey.publicKey)

        #expect(sharedPoint.compressedBytes == expectedCompressed)
        #expect(sharedPoint.uncompressedBytes == expectedUncompressed)
        #expect(sharedPoint.serialized(as: .compressed) == expectedCompressed)
        #expect(sharedPoint.serialized(as: .uncompressed) == expectedUncompressed)
        #expect(sharedPoint == peerPrivateKey.publicKey)
    }

    @Test("ECDH is symmetric and deterministic")
    func ecdhSymmetryAndDeterminism() throws {
        let alice = try PrivateKey(decode(
            "7da12cc39bb4189ac72d34fc2225df5cf36aaacdcac7e5a43963299bc8d888ed"
        ))
        let bob = try PrivateKey(decode(
            "5f6d5afecc677d66fb3d41eee7a8ad8195659ceff588edaf416a9a17daf38fdd"
        ))

        let aliceSecret = try alice.sharedSecret(with: bob.publicKey)
        let bobSecret = try bob.sharedSecret(with: alice.publicKey)
        #expect(aliceSecret == bobSecret)
        #expect(try alice.sharedSecret(with: bob.publicKey) == aliceSecret)
    }

    @Test("invalid peers are rejected by PublicKey before key agreement")
    func invalidPeersAreUnrepresentable() throws {
        var malformed = [UInt8](repeating: 0, count: 33)
        malformed[0] = 0x02
        malformed[32] = 0x05

        #expect(throws: Secp256k1KeyError.invalidPublicKey) {
            try PublicKey(malformed)
        }
    }

    @Test("rejected operations leave values unchanged")
    func rejectedOperationsAreNonmutating() throws {
        let privateKey = try PrivateKey(scalar(1))
        let publicKey = privateKey.publicKey
        let originalPrivateBytes = privateKey.bytes
        let originalPublicBytes = publicKey.compressedBytes
        let invalid = try curveOrder()

        _ = try? privateKey.adding(tweak: invalid)
        _ = try? privateKey.multiplying(by: invalid)
        _ = try? publicKey.adding(tweak: invalid)
        _ = try? publicKey.multiplying(by: invalid)

        #expect(privateKey.bytes == originalPrivateBytes)
        #expect(publicKey.compressedBytes == originalPublicBytes)
    }

    @Test("deterministic tweak cases preserve public/private consistency")
    func deterministicTweakCases() throws {
        for value in UInt8(1)...UInt8(32) {
            let key = try PrivateKey(scalar(value))
            let tweak = scalar(value &+ 1)

            #expect(
                try key.adding(tweak: tweak).publicKey
                    == key.publicKey.adding(tweak: tweak)
            )
            #expect(
                try key.multiplying(by: tweak).publicKey
                    == key.publicKey.multiplying(by: tweak)
            )
        }
    }

    private func scalar(_ value: UInt8) -> [UInt8] {
        [UInt8](repeating: 0, count: 31) + [value]
    }

    private func curveOrder() throws -> [UInt8] {
        try decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
    }

    private func curveOrderMinusOne() throws -> [UInt8] {
        try decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
    }

    private func decode(_ text: String) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: 65)
    }
}
