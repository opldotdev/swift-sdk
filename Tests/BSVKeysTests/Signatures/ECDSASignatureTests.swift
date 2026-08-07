import BSVCore
import BSVKeys
import Testing

@Suite("ECDSA signatures")
struct ECDSASignatureTests {
    private let scalarOne = "0000000000000000000000000000000000000000000000000000000000000001"
    private let digestHex = "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7"
    private let compactHex = "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09" +
        "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560"
    private let derHex = "3045022100c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09" +
        "022000ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560"

    @Test("RFC 6979 signs the exact digest to independent known-answer bytes")
    func deterministicExactDigestKnownAnswer() throws {
        let key = try PrivateKey(hex(scalarOne))
        let digest = try Hash256(hex(digestHex))
        let expectedCompact = try hex(compactHex)
        let expectedDER = try hex(derHex)

        let first = try key.sign(digest: digest)
        let second = try key.sign(digest: digest)

        #expect(first.compactBytes == expectedCompact)
        #expect(first.derBytes == expectedDER)
        #expect(first == second)
        #expect(first.compactBytes == second.compactBytes)
        #expect(key.publicKey.verify(first, digest: digest))

        // libsecp256k1's documented inclusive low-S upper bound.
        let maximumLowS = try hex(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
        )
        #expect(Array(first.compactBytes[32..<64]).lexicographicallyPrecedes(maximumLowS) ||
                Array(first.compactBytes[32..<64]) == maximumLowS)
    }

    @Test("wrong digest and wrong public key are verification mismatches")
    func verificationMismatchesReturnFalse() throws {
        let key = try PrivateKey(hex(scalarOne))
        let digest = try Hash256(hex(digestHex))
        let signature = try key.sign(digest: digest)
        var wrongDigestBytes = digest.bytes
        wrongDigestBytes[31] ^= 1
        let wrongDigest = try Hash256(wrongDigestBytes)
        let wrongKey = try PrivateKey(
            hex("0000000000000000000000000000000000000000000000000000000000000002")
        )

        #expect(!key.publicKey.verify(signature, digest: wrongDigest))
        #expect(!wrongKey.publicKey.verify(signature, digest: digest))
    }

    @Test("compact parsing enforces width, nonzero scalars, and curve order")
    func compactParserBoundaries() throws {
        let valid = try hex(compactHex)
        #expect(try ECDSASignature(compactBytes: valid).compactBytes == valid)
        #expect(throws: ECDSASignatureError.invalidCompactByteCount(63)) {
            try ECDSASignature(compactBytes: Array(valid.dropLast()))
        }
        #expect(throws: ECDSASignatureError.invalidCompactByteCount(65)) {
            try ECDSASignature(compactBytes: valid + [0])
        }

        let zero = [UInt8](repeating: 0, count: 32)
        let one = [UInt8](repeating: 0, count: 31) + [1]
        let order = try hex(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        )
        for invalid in [zero + one, one + zero, order + one, one + order] {
            #expect(throws: ECDSASignatureError.invalidCompactSignature) {
                try ECDSASignature(compactBytes: invalid)
            }
        }
    }

    @Test("DER parsing is canonical, complete, and hostile to malformed input")
    func strictDERMalformedClasses() throws {
        let minimal = try hex("3006020101020101")
        #expect(try ECDSASignature(derBytes: minimal).derBytes == minimal)

        let malformed = [
            "",
            "300602010102010100", // trailing byte
            "3106020101020101", // wrong sequence tag
            "3005020101020101", // sequence length too short
            "3007020101020101", // sequence length too long
            "308106020101020101", // noncanonical long-form length
            "3006030101020101", // wrong r tag
            "3006020101030101", // wrong s tag
            "30050200020101", // empty r
            "30050201010200", // empty s
            "3006020180020101", // negative r
            "3006020101020180", // negative s
            "300702020001020101", // unnecessary r leading zero
            "300702010102020001", // unnecessary s leading zero
            "3006020100020101", // r is zero
            "3006020101020100", // s is zero
            "3045022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" +
                "0220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
            "304502204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41" +
                "022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        ]

        for encoded in malformed {
            #expect(throws: ECDSASignatureError.invalidDEREncoding) {
                try ECDSASignature(derBytes: hex(encoded))
            }
        }
    }

    @Test("compact and DER forms round-trip to one identity")
    func representationIndependentRoundTripAndHashing() throws {
        let compact = try ECDSASignature(compactBytes: hex(compactHex))
        let der = try ECDSASignature(derBytes: hex(derHex))
        let expectedCompact = try hex(compactHex)
        let expectedDER = try hex(derHex)

        #expect(compact == der)
        #expect(Set([compact, der]).count == 1)
        #expect(try ECDSASignature(compactBytes: der.compactBytes).derBytes == expectedDER)
        #expect(try ECDSASignature(derBytes: compact.derBytes).compactBytes == expectedCompact)
    }

    @Test("well-formed high-S signatures parse but verification rejects them")
    func highSParsesWithoutNormalizationAndDoesNotVerify() throws {
        let highSCompact = try hex(
            "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09" +
                "ff45decaeca8d1ca6bc2a5322e8deaa89faaebd04c2f75c96db8f1c41d8cabe1"
        )
        let highSDER = try hex(
            "3046022100c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09" +
                "022100ff45decaeca8d1ca6bc2a5322e8deaa89faaebd04c2f75c96db8f1c41d8cabe1"
        )
        let fromCompact = try ECDSASignature(compactBytes: highSCompact)
        let fromDER = try ECDSASignature(derBytes: highSDER)
        let key = try PrivateKey(hex(scalarOne))
        let digest = try Hash256(hex(digestHex))

        #expect(fromCompact.compactBytes == highSCompact)
        #expect(fromCompact.derBytes == highSDER)
        #expect(fromDER.compactBytes == highSCompact)
        #expect(!key.publicKey.verify(fromCompact, digest: digest))
        #expect(!key.publicKey.verify(fromDER, digest: digest))
    }

    @Test("signature public values are Sendable")
    func sendableSurface() throws {
        requireSendable(try ECDSASignature(compactBytes: hex(compactHex)))
        requireSendable(ECDSASignatureError.invalidDEREncoding)
    }

    private func hex(_ text: String) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: 256)
    }

    private func requireSendable<T: Sendable>(_ value: T) {
        _ = value
    }
}
