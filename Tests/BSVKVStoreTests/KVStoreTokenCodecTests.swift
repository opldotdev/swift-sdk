import BSVCore
import BSVCrypto
import BSVKeys
import BSVKVStore
import BSVScript
import BSVWallet
import Testing

/// Vectors follow TypeScript `packages/sdk/src/kvstore/LocalKVStore.ts`
/// (`@bsv/sdk` 4.1.1): written with `pushdrop.lock([value], [2, context],
/// key, "self")` (lines 492-497), which appends a signature over the value
/// (script/templates/PushDrop.ts:175-187), and read with
/// `decodeCanonicalPushDrop(..., { fieldCount: 2 })` plus
/// `verifySignature(..., counterparty: "self")` (lines 283-302).
@Suite("TypeScript LocalKVStore tokens")
struct KVStoreTokenCodecTests {
    private let ownerKeyBytes = [UInt8](repeating: 0, count: 31) + [0x2b]

    @Test("hand-built TypeScript token decodes and re-encodes byte for byte")
    func handBuiltTypeScriptToken() async throws {
        let owner = try PrivateKey(ownerKeyBytes)
        // counterparty "self": the owner's child derived with its own public key.
        let lockingKey = try owner.derivedChild(
            with: owner.publicKey,
            invoiceNumber: "2-kvstore default-greeting"
        )
        let value: [UInt8] = [0xff, 0x00, 0x80]
        let signature = try lockingKey.sign(digest: BSVHashing.sha256(value))
        var expectedBytes: [UInt8] = [0x21]
        expectedBytes += lockingKey.publicKey.compressedBytes
        expectedBytes += [0xac, 0x03]
        expectedBytes += value
        expectedBytes += [UInt8(signature.derBytes.count)]
        expectedBytes += signature.derBytes
        expectedBytes += [0x6d]
        let script = try Script(bytes: expectedBytes, maximumByteCount: 1_000)

        let token = try KVStoreTokenCodec.decode(script)
        #expect(token.value == value)
        #expect(token.lockingPublicKey == lockingKey.publicKey)
        #expect(token.signature == signature)
        #expect(try KVStoreTokenCodec.lockingScript(for: token).bytes == expectedBytes)

        let wallet = ProtoWallet(rootKey: owner)
        let locator = try KVStoreLocator(context: "kvstore default", key: "greeting")
        #expect(try await KVStoreTokenCodec.decode(script, locator: locator, using: wallet) == token)
        let otherLocator = try KVStoreLocator(context: "kvstore default", key: "other")
        await #expect(throws: KVStoreError.lockingKeyMismatch) {
            try await KVStoreTokenCodec.decode(script, locator: otherLocator, using: wallet)
        }
    }

    @Test("wallet write uses [2, context], key ID key, counterparty self")
    func walletWrite() async throws {
        let owner = try PrivateKey(ownerKeyBytes)
        let wallet = ProtoWallet(rootKey: owner)
        let locator = try KVStoreLocator(context: "kvstore default", key: "greeting")
        let value = Array("hello".utf8)

        let script = try await KVStoreTokenCodec.lockingScript(
            value: value,
            locator: locator,
            using: wallet
        )
        let decoded = try PushDrop.decode(script, lockPosition: .beforeCompatibility)
        #expect(decoded.fields.count == 2)
        #expect(decoded.fields[0] == value)
        let lockingKey = try owner.derivedChild(
            with: owner.publicKey,
            invoiceNumber: "2-kvstore default-greeting"
        )
        #expect(decoded.publicKey == lockingKey.publicKey)
        let verified = try await wallet.verifySignature(.init(
            protocolID: try locator.walletProtocolID(),
            keyID: try locator.walletKeyID(),
            counterparty: .self,
            payload: .data(value),
            signature: try ECDSASignature(derBytes: decoded.fields[1])
        ))
        #expect(verified.valid)
        #expect(try await KVStoreTokenCodec.decode(script, locator: locator, using: wallet).value == value)
    }

    @Test("the previous one-field Swift token is rejected")
    func rejectsOneFieldToken() throws {
        let publicKey = try PrivateKey(ownerKeyBytes).publicKey
        let oneField = try PushDrop.lockingScript(
            fields: [[0xaa, 0xbb]],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.invalidTokenFieldCount(actual: 1)) {
            try KVStoreTokenCodec.decode(oneField)
        }
    }

    @Test("decoder requires two fields, a valid signature, and the lock-before layout")
    func decoderRejectsOtherShapes() throws {
        let key = try PrivateKey(ownerKeyBytes)
        let publicKey = key.publicKey
        let signature = try key.sign(digest: BSVHashing.sha256([0xaa]))

        let zeroFields = try PushDrop.lockingScript(
            fields: [],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.invalidTokenFieldCount(actual: 0)) {
            try KVStoreTokenCodec.decode(zeroFields)
        }

        let threeFields = try PushDrop.lockingScript(
            fields: [[0xaa], signature.derBytes, [0xbb]],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.invalidTokenFieldCount(actual: 3)) {
            try KVStoreTokenCodec.decode(threeFields)
        }

        let notDER = try PushDrop.lockingScript(
            fields: [[0xaa], [0x30, 0x01, 0x02]],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.invalidSignatureEncoding) {
            try KVStoreTokenCodec.decode(notDER)
        }

        let wrongValue = try PushDrop.lockingScript(
            fields: [[0xab], signature.derBytes],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.invalidSignature) {
            try KVStoreTokenCodec.decode(wrongValue)
        }

        let otherKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [9]).publicKey
        let wrongKey = try PushDrop.lockingScript(
            fields: [[0xaa], signature.derBytes],
            publicKey: otherKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.invalidSignature) {
            try KVStoreTokenCodec.decode(wrongKey)
        }

        let lockAfter = try PushDrop.lockingScript(
            fields: [[0xaa], signature.derBytes],
            publicKey: publicKey,
            lockPosition: .after
        )
        #expect(throws: KVStoreError.invalidLockingScript(
            .invalidLockingScriptLayout(.beforeCompatibility)
        )) {
            try KVStoreTokenCodec.decode(lockAfter)
        }

        var nonMinimalBytes: [UInt8] = [0x21]
        nonMinimalBytes += publicKey.compressedBytes
        nonMinimalBytes += [0xac, 0x4c, 0x01, 0xaa]
        nonMinimalBytes += [UInt8(signature.derBytes.count)]
        nonMinimalBytes += signature.derBytes
        nonMinimalBytes += [0x6d]
        let nonMinimal = try Script(bytes: nonMinimalBytes, maximumByteCount: 200)
        #expect(throws: KVStoreError.invalidLockingScript(
            .nonMinimalFieldPush(index: 0)
        )) {
            try KVStoreTokenCodec.decode(nonMinimal)
        }
    }

    @Test("token values preserve non-UTF-8 bytes")
    func preservesRawBytes() throws {
        let token = try signedToken([0xc3, 0x28, 0xff])
        let decoded = try KVStoreTokenCodec.decode(
            KVStoreTokenCodec.lockingScript(for: token)
        )
        #expect(decoded.value == token.value)
    }

    @Test("a token value always carries a signature that verifies")
    func tokenRequiresValidSignature() throws {
        let key = try PrivateKey(ownerKeyBytes)
        let signature = try key.sign(digest: BSVHashing.sha256([1]))
        #expect(throws: KVStoreError.invalidSignature) {
            try KVStoreToken(value: [2], lockingPublicKey: key.publicKey, signature: signature)
        }
        #expect(throws: KVStoreError.emptyValue) {
            try KVStoreToken(value: [], lockingPublicKey: key.publicKey, signature: signature)
        }
    }

    @Test("locator validates empty and exact UTF-8 bounds")
    func locatorBounds() throws {
        let limits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 3,
            maximumValueByteCount: 1,
            maximumScriptByteCount: 111
        )
        #expect(throws: KVStoreError.emptyContext) {
            try KVStoreLocator(context: "", key: "key", limits: limits)
        }
        #expect(throws: KVStoreError.emptyKey) {
            try KVStoreLocator(context: "ctx", key: "", limits: limits)
        }
        #expect(try KVStoreLocator(context: "é", key: "abc", limits: limits).key == "abc")
        #expect(throws: KVStoreError.locatorByteCountExceedsLimit(
            kind: "key",
            actual: 4,
            maximum: 3
        )) {
            try KVStoreLocator(context: "ctx", key: "abcd", limits: limits)
        }
    }

    @Test("standard limits accept the 2 MiB value TypeScript reads")
    func standardLimitsMatchTypeScript() throws {
        // TypeScript LocalKVStore.ts:21 MAX_LOCAL_TOKEN_BYTES = 2 MiB.
        #expect(KVStoreLimits.standard.maximumValueByteCount == 2 * 1_024 * 1_024)
        let token = try signedToken(
            [UInt8](repeating: 0x5a, count: 2 * 1_024 * 1_024)
        )
        let script = try KVStoreTokenCodec.lockingScript(for: token)
        #expect(try KVStoreTokenCodec.decode(script) == token)
    }

    @Test("value and script limits accept their exact maximum and reject plus one")
    func tokenBounds() throws {
        // lock 35 + value push 4 + signature push 73 + OP_2DROP 1.
        let limits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 1,
            maximumValueByteCount: 3,
            maximumScriptByteCount: 113
        )
        let exact = try signedToken([0xaa, 0xbb, 0xcc], limits: limits)
        let script = try KVStoreTokenCodec.lockingScript(for: exact, limits: limits)
        #expect(script.byteCount == 35 + 4 + 1 + exact.signature.derBytes.count + 1)
        #expect(try KVStoreTokenCodec.decode(script, limits: limits) == exact)

        let key = try PrivateKey(ownerKeyBytes)
        let longer: [UInt8] = [0xaa, 0xbb, 0xcc, 0xdd]
        #expect(throws: KVStoreError.valueByteCountExceedsLimit(actual: 4, maximum: 3)) {
            try KVStoreToken(
                value: longer,
                lockingPublicKey: key.publicKey,
                signature: try key.sign(digest: BSVHashing.sha256(longer)),
                limits: limits
            )
        }
    }

    @Test("decoder enforces the value bound after script parsing")
    func decoderValueBounds() throws {
        let key = try PrivateKey(ownerKeyBytes)
        let value: [UInt8] = [0xaa, 0xbb, 0xcc, 0xdd]
        let signature = try key.sign(digest: BSVHashing.sha256(value))
        let script = try PushDrop.lockingScript(
            fields: [value, signature.derBytes],
            publicKey: key.publicKey,
            lockPosition: .beforeCompatibility
        )
        let limits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 1,
            maximumValueByteCount: 3,
            maximumScriptByteCount: 200
        )
        #expect(throws: KVStoreError.valueByteCountExceedsLimit(actual: 4, maximum: 3)) {
            try KVStoreTokenCodec.decode(script, limits: limits)
        }
    }

    @Test("deterministic raw payloads round-trip over PushDrop size boundaries")
    func deterministicRawPayloadRoundTrips() throws {
        let limits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 1,
            maximumValueByteCount: 65_536,
            maximumScriptByteCount: 65_650
        )
        for byteCount in [1, 2, 3, 75, 76, 255, 256, 65_535, 65_536] {
            let payload = (0..<byteCount).map {
                UInt8(truncatingIfNeeded: $0 &* 31 &+ 17)
            }
            let token = try signedToken(payload, limits: limits)
            let script = try KVStoreTokenCodec.lockingScript(for: token, limits: limits)
            #expect(try KVStoreTokenCodec.decode(script, limits: limits) == token)
        }
    }

    @Test("limits reject nonpositive, overflow-prone, and inconsistent configurations")
    func invalidLimits() {
        #expect(throws: KVStoreError.invalidLimits) {
            try KVStoreLimits(
                maximumLocatorUTF8ByteCount: 0,
                maximumValueByteCount: 1,
                maximumScriptByteCount: 111
            )
        }
        #expect(throws: KVStoreError.invalidLimits) {
            try KVStoreLimits(
                maximumLocatorUTF8ByteCount: 1,
                maximumValueByteCount: Int(UInt32.max) + 1,
                maximumScriptByteCount: Int.max
            )
        }
        #expect(throws: KVStoreError.invalidLimits) {
            try KVStoreLimits(
                maximumLocatorUTF8ByteCount: 1,
                maximumValueByteCount: 3,
                maximumScriptByteCount: 112
            )
        }
    }

    @Test("diagnostics and reflection do not disclose locators or values")
    func diagnosticsAreRedacted() throws {
        let locator = try KVStoreLocator(context: "private context", key: "private key")
        let token = try signedToken(Array("private value".utf8))

        #expect(locator.description == "<redacted key-value locator>")
        #expect(token.description == "<redacted key-value token>")
        #expect(Array(Mirror(reflecting: locator).children).isEmpty)
        #expect(Array(Mirror(reflecting: token).children).isEmpty)
    }

    private func signedToken(
        _ value: [UInt8],
        limits: KVStoreLimits = .standard
    ) throws -> KVStoreToken {
        let key = try PrivateKey(ownerKeyBytes)
        return try KVStoreToken(
            value: value,
            lockingPublicKey: key.publicKey,
            signature: try key.sign(digest: BSVHashing.sha256(value)),
            limits: limits
        )
    }
}
