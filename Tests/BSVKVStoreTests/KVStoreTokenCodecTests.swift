import BSVKeys
import BSVKVStore
import BSVScript
import Testing

@Suite("BRC-35 compatible key-value tokens")
struct KVStoreTokenCodecTests {
    private let privateKeyBytes = [UInt8](repeating: 0, count: 31) + [1]

    @Test("one raw value uses Go's lock-before compatibility layout")
    func roundTripsGoCompatibleToken() throws {
        let publicKey = try PrivateKey(privateKeyBytes).publicKey
        let token = try KVStoreToken(
            value: [0xff, 0x00, 0x80],
            lockingPublicKey: publicKey
        )

        let script = try KVStoreTokenCodec.lockingScript(for: token)
        let expectedBytes = [UInt8(0x21)]
            + publicKey.compressedBytes
            + [0xac, 0x03, 0xff, 0x00, 0x80, 0x75]
        let decodedPushDrop = try PushDrop.decode(
            script,
            lockPosition: .beforeCompatibility
        )

        #expect(script.bytes == expectedBytes)
        #expect(decodedPushDrop.fields == [[0xff, 0x00, 0x80]])
        #expect(decodedPushDrop.publicKey == publicKey)
        #expect(try KVStoreTokenCodec.decode(script) == token)
    }

    @Test("token values preserve non-UTF-8 bytes")
    func preservesRawBytes() throws {
        let token = try KVStoreToken(
            value: [0xc3, 0x28, 0xff],
            lockingPublicKey: try PrivateKey(privateKeyBytes).publicKey
        )

        let decoded = try KVStoreTokenCodec.decode(
            KVStoreTokenCodec.lockingScript(for: token)
        )
        #expect(decoded.value == token.value)
    }

    @Test("locator validates empty and exact UTF-8 bounds")
    func locatorBounds() throws {
        let limits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 3,
            maximumValueByteCount: 1,
            maximumScriptByteCount: 38
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

    @Test("value and script limits accept their exact maximum and reject plus one")
    func tokenBounds() throws {
        let limits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 1,
            maximumValueByteCount: 3,
            maximumScriptByteCount: 40
        )
        let publicKey = try PrivateKey(privateKeyBytes).publicKey
        let exact = try KVStoreToken(
            value: [0xaa, 0xbb, 0xcc],
            lockingPublicKey: publicKey,
            limits: limits
        )
        let script = try KVStoreTokenCodec.lockingScript(for: exact, limits: limits)

        #expect(script.byteCount == 40)
        #expect(try KVStoreTokenCodec.decode(script, limits: limits) == exact)
        #expect(throws: KVStoreError.valueByteCountExceedsLimit(actual: 4, maximum: 3)) {
            try KVStoreToken(
                value: [0xaa, 0xbb, 0xcc, 0xdd],
                lockingPublicKey: publicKey,
                limits: limits
            )
        }
    }

    @Test("decoder enforces the value bound after script parsing")
    func decoderValueBounds() throws {
        let publicKey = try PrivateKey(privateKeyBytes).publicKey
        let exactLimits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 1,
            maximumValueByteCount: 3,
            maximumScriptByteCount: 40
        )
        let exactScript = try PushDrop.lockingScript(
            fields: [[0xaa, 0xbb, 0xcc]],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(try KVStoreTokenCodec.decode(exactScript, limits: exactLimits).value == [0xaa, 0xbb, 0xcc])

        let plusOneLimits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 1,
            maximumValueByteCount: 3,
            maximumScriptByteCount: 41
        )
        let plusOneScript = try PushDrop.lockingScript(
            fields: [[0xaa, 0xbb, 0xcc, 0xdd]],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.valueByteCountExceedsLimit(actual: 4, maximum: 3)) {
            try KVStoreTokenCodec.decode(plusOneScript, limits: plusOneLimits)
        }
    }

    @Test("empty values are never valid tokens")
    func rejectsEmptyValue() throws {
        #expect(throws: KVStoreError.emptyValue) {
            try KVStoreToken(
                value: [],
                lockingPublicKey: try PrivateKey(privateKeyBytes).publicKey
            )
        }
    }

    @Test("deterministic raw payloads round-trip over PushDrop size boundaries")
    func deterministicRawPayloadRoundTrips() throws {
        let publicKey = try PrivateKey(privateKeyBytes).publicKey
        let limits = try KVStoreLimits(
            maximumLocatorUTF8ByteCount: 1,
            maximumValueByteCount: 65_536,
            maximumScriptByteCount: 65_577
        )
        let byteCounts = [1, 2, 3, 75, 76, 255, 256, 65_535, 65_536]

        for byteCount in byteCounts {
            let payload = (0..<byteCount).map {
                UInt8(truncatingIfNeeded: $0 &* 31 &+ 17)
            }
            let token = try KVStoreToken(
                value: payload,
                lockingPublicKey: publicKey,
                limits: limits
            )
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
                maximumScriptByteCount: 38
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
                maximumScriptByteCount: 39
            )
        }
    }

    @Test("decoder requires exactly one field and the compatibility layout")
    func decoderRejectsOtherPushDropShapes() throws {
        let publicKey = try PrivateKey(privateKeyBytes).publicKey
        let zeroFields = try PushDrop.lockingScript(
            fields: [],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.invalidTokenFieldCount(actual: 0)) {
            try KVStoreTokenCodec.decode(zeroFields)
        }

        let twoFields = try PushDrop.lockingScript(
            fields: [[0xaa], [0xbb]],
            publicKey: publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: KVStoreError.invalidTokenFieldCount(actual: 2)) {
            try KVStoreTokenCodec.decode(twoFields)
        }

        let lockAfter = try PushDrop.lockingScript(
            fields: [[0xaa]],
            publicKey: publicKey,
            lockPosition: .after
        )
        #expect(throws: KVStoreError.invalidLockingScript(
            .invalidLockingScriptLayout(.beforeCompatibility)
        )) {
            try KVStoreTokenCodec.decode(lockAfter)
        }

        let nonMinimal = try Script(
            bytes: [UInt8(0x21)] + publicKey.compressedBytes + [0xac, 0x4c, 0x01, 0xaa, 0x75],
            maximumByteCount: 40
        )
        #expect(throws: KVStoreError.invalidLockingScript(
            .nonMinimalFieldPush(index: 0)
        )) {
            try KVStoreTokenCodec.decode(nonMinimal)
        }
    }

    @Test("diagnostics and reflection do not disclose locators or values")
    func diagnosticsAreRedacted() throws {
        let locator = try KVStoreLocator(context: "private context", key: "private key")
        let token = try KVStoreToken(
            value: Array("private value".utf8),
            lockingPublicKey: try PrivateKey(privateKeyBytes).publicKey
        )

        #expect(locator.description == "<redacted key-value locator>")
        #expect(token.description == "<redacted key-value token>")
        #expect(Array(Mirror(reflecting: locator).children).isEmpty)
        #expect(Array(Mirror(reflecting: token).children).isEmpty)
    }
}
