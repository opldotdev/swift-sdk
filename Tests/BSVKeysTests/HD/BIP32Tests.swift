import BSVCore
import BSVKeys
import Testing

@Suite("BIP-32 extended keys")
struct BIP32Tests {
    private let vectorOneSeed: [UInt8] = Array(UInt8(0x00)...UInt8(0x0f))
    private let vectorOneXprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    private let vectorOneXpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

    @Test("master metadata and mainnet/testnet versions round trip")
    func masterAndNetworks() throws {
        let main = try ExtendedPrivateKey(seed: vectorOneSeed, network: .mainnet)
        #expect(main.depth == 0)
        #expect(main.parentFingerprint == 0)
        #expect(main.childNumber == 0)
        #expect(main.serialized == vectorOneXprv)
        #expect(main.description == "<redacted extended private key>")
        #expect(String(reflecting: main) == "<redacted extended private key>")
        #expect(main.neutered.serialized == vectorOneXpub)

        let test = try ExtendedPrivateKey(seed: vectorOneSeed, network: .testnet)
        #expect(test.serialized.hasPrefix("tprv"))
        #expect(test.neutered.serialized.hasPrefix("tpub"))
        #expect(try ExtendedPrivateKey(test.serialized) == test)
        #expect(try ExtendedPublicKey(test.neutered.serialized) == test.neutered)
        #expect(main != test)
        #expect(Set([main, test]).count == 2)
    }

    @Test("seed policy is the BIP-32 128...512-bit range")
    func seedPolicy() throws {
        for count in [0, 15, 65, 1_000] {
            #expect(throws: ExtendedKeyError.invalidSeedByteCount(count)) {
                try ExtendedPrivateKey(seed: [UInt8](repeating: 0, count: count), network: .mainnet)
            }
        }
        _ = try ExtendedPrivateKey(seed: [UInt8](repeating: 1, count: 16), network: .mainnet)
        _ = try ExtendedPrivateKey(seed: [UInt8](repeating: 1, count: 64), network: .mainnet)
    }

    @Test("child numbers make hardened offset and overflow explicit")
    func childNumbers() throws {
        let normal = try HDChildNumber.normal(7)
        let hardened = try HDChildNumber.hardened(7)
        #expect(normal.rawValue == 7)
        #expect(!normal.isHardened)
        #expect(normal.description == "7")
        #expect(hardened.rawValue == 0x8000_0007)
        #expect(hardened.isHardened)
        #expect(hardened.index == 7)
        #expect(hardened.description == "7'")
        #expect(
            throws: ExtendedKeyError.invalidChildIndex(0x8000_0000)
        ) {
            try HDChildNumber.hardened(0x8000_0000)
        }
    }

    @Test("paths are bounded and canonicalized deterministically")
    func paths() throws {
        #expect(try HDKeyPath("m").description == "m")
        #expect(try HDKeyPath("M/0/2/3").description == "M/0/2/3")
        #expect(try HDKeyPath("m/0007'/01").description == "m/7'/1")

        let malformed = [
            "", "x", "m/", "m//1", "m/-1", "m/1h", "m/1H", "m/1''",
            "m/2147483648", "m/1/", "m /1", "m/é", String(repeating: "1", count: 2_049),
        ]
        for path in malformed {
            #expect(throws: ExtendedKeyError.invalidPath) {
                try HDKeyPath(path)
            }
        }
        let tooDeep = "m/" + [String](repeating: "0", count: 256).joined(separator: "/")
        #expect(throws: ExtendedKeyError.invalidPath) {
            try HDKeyPath(tooDeep)
        }
    }

    @Test("private and public normal child derivation stay identical")
    func generatedConsistency() throws {
        let master = try ExtendedPrivateKey(seed: vectorOneSeed, network: .mainnet)
        var state: UInt32 = 0x6d2b_79f5
        for _ in 0..<64 {
            state = state &* 1_664_525 &+ 1_013_904_223
            let index = state & 0x7fff_ffff
            let privateChild = try master.derived(at: index)
            let publicChild = try master.neutered.derived(at: index)
            #expect(privateChild.neutered == publicChild)
        }
    }

    @Test("public hardened derivation and mismatched absolute roots are rejected")
    func publicAndPathRejections() throws {
        let master = try ExtendedPrivateKey(seed: vectorOneSeed, network: .mainnet)
        #expect(
            throws: ExtendedKeyError.hardenedPublicDerivation(childNumber: 0x8000_0000)
        ) {
            try master.neutered.derived(at: 0x8000_0000)
        }
        #expect(
            throws: ExtendedKeyError.pathRootMismatch(
                expected: .privateKey,
                actual: .publicKey
            )
        ) {
            try master.derived(path: "M/0")
        }
        #expect(
            throws: ExtendedKeyError.pathRootMismatch(
                expected: .publicKey,
                actual: .privateKey
            )
        ) {
            try master.neutered.derived(path: "m/0")
        }
        #expect(throws: ExtendedKeyError.pathRequiresRootKey) {
            try master.derived(at: 0).derived(path: "m/1")
        }
    }

    @Test("serialized payload structure and parsing failures are typed")
    func parsingFailures() throws {
        let valid = try Base58Check.decode(vectorOneXprv, maximumPayloadByteCount: 78)

        let shortPayloadText = Base58Check.encode([0x7f] + [UInt8](repeating: 0, count: 76))
        #expect(shortPayloadText.utf8.count == 111)
        #expect(throws: ExtendedKeyError.invalidPayloadByteCount(77)) {
            try ExtendedPrivateKey(shortPayloadText)
        }
        #expect(
            throws: ExtendedKeyError.invalidEncoding(
                .payloadSizeLimitExceeded(maximum: 78)
            )
        ) {
            try ExtendedPrivateKey(String(repeating: "1", count: 111))
        }
        for invalidLengthText in [
            String(vectorOneXprv.dropLast()),
            vectorOneXprv + "1",
            String(repeating: "1", count: 1_000_000),
            String(repeating: "é", count: 56),
        ] {
            #expect(throws: ExtendedKeyError.invalidSerializedTextLength) {
                try ExtendedPrivateKey(invalidLengthText)
            }
        }

        var unknownVersion = valid
        unknownVersion.replaceSubrange(0..<4, with: [0x04, 0x88, 0xad, 0xe5])
        #expect(throws: ExtendedKeyError.unknownVersion(0x0488_ade5)) {
            try ExtendedPrivateKey(Base58Check.encode(unknownVersion))
        }

        var marker = valid
        marker[45] = 1
        #expect(throws: ExtendedKeyError.invalidPrivateKeyMarker(1)) {
            try ExtendedPrivateKey(Base58Check.encode(marker))
        }

        var zeroKey = valid
        zeroKey.replaceSubrange(46..<78, with: [UInt8](repeating: 0, count: 32))
        #expect(throws: ExtendedKeyError.invalidPrivateKey) {
            try ExtendedPrivateKey(Base58Check.encode(zeroKey))
        }

        var badRootFingerprint = valid
        badRootFingerprint[5] = 1
        #expect(throws: ExtendedKeyError.inconsistentRootMetadata) {
            try ExtendedPrivateKey(Base58Check.encode(badRootFingerprint))
        }

        var badRootChild = valid
        badRootChild[12] = 1
        #expect(throws: ExtendedKeyError.inconsistentRootMetadata) {
            try ExtendedPrivateKey(Base58Check.encode(badRootChild))
        }

        let publicPayload = try Base58Check.decode(vectorOneXpub, maximumPayloadByteCount: 78)
        var badPublic = publicPayload
        badPublic[45] = 4
        #expect(throws: ExtendedKeyError.invalidPublicKey) {
            try ExtendedPublicKey(Base58Check.encode(badPublic))
        }

        #expect(
            throws: ExtendedKeyError.unexpectedKeyKind(
                expected: .privateKey,
                actual: .publicKey
            )
        ) {
            try ExtendedPrivateKey(vectorOneXpub)
        }

        let badChecksum = String(vectorOneXprv.dropLast()) + "L"
        #expect(
            throws: ExtendedKeyError.invalidEncoding(.checksumMismatch)
        ) {
            try ExtendedPrivateKey(badChecksum)
        }
    }

    @Test("depth 255 cannot derive another child")
    func depthExhaustion() throws {
        var privatePayload = try Base58Check.decode(vectorOneXprv, maximumPayloadByteCount: 78)
        privatePayload[4] = 255
        let privateKey = try ExtendedPrivateKey(Base58Check.encode(privatePayload))
        #expect(throws: ExtendedKeyError.depthExhausted) {
            try privateKey.derived(at: 0)
        }

        var publicPayload = try Base58Check.decode(vectorOneXpub, maximumPayloadByteCount: 78)
        publicPayload[4] = 255
        let publicKey = try ExtendedPublicKey(Base58Check.encode(publicPayload))
        #expect(throws: ExtendedKeyError.depthExhausted) {
            try publicKey.derived(at: 0)
        }
    }
}
