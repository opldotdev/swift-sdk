import BSVCore
import BSVCrypto
import BSVKeys
import BSVRegistry
import BSVScript
import BSVTransaction
import BSVWallet
import XCTest

final class RegistryDefinitionCodecTests: XCTestCase {
    func testClosedKindMappingsMatchPinnedRegistryNames() throws {
        XCTAssertEqual(RegistryDefinitionKind.basket.basketName, "basketmap")
        XCTAssertEqual(RegistryDefinitionKind.protocol.basketName, "protomap")
        XCTAssertEqual(RegistryDefinitionKind.certificate.basketName, "certmap")
        XCTAssertEqual(try RegistryDefinitionKind.basket.topic().rawValue, "tm_basketmap")
        XCTAssertEqual(try RegistryDefinitionKind.protocol.service().rawValue, "ls_protomap")
        // TypeScript registry/registryTokenValidation.ts:13-17 and
        // RegistryClient.ts:792-801 use security level 1 for all three.
        XCTAssertEqual(
            try RegistryDefinitionKind.basket.walletProtocolID(),
            try WalletProtocolID(securityLevel: .everyApp, name: "basketmap"))
        XCTAssertEqual(
            try RegistryDefinitionKind.protocol.walletProtocolID(),
            try WalletProtocolID(securityLevel: .everyApp, name: "protomap"))
        XCTAssertEqual(
            try RegistryDefinitionKind.certificate.walletProtocolID(),
            try WalletProtocolID(securityLevel: .everyApp, name: "certmap"))
        XCTAssertEqual(RegistryDefinitionKind.basket.dataFieldCount, 6)
        XCTAssertEqual(RegistryDefinitionKind.protocol.dataFieldCount, 6)
        XCTAssertEqual(RegistryDefinitionKind.certificate.dataFieldCount, 7)
    }

    func testBasketDataFieldsKeepTypeScriptOrder() throws {
        let definition = RegistryDefinition.basket(try basketDefinition())
        let fields = try RegistryDefinitionCodec.fields(for: definition)
        XCTAssertEqual(fields.count, 6)
        XCTAssertEqual(String(decoding: fields[0], as: UTF8.self), "basket.id")
        XCTAssertEqual(String(decoding: fields[2], as: UTF8.self), "")
        XCTAssertEqual(
            try RegistryDefinitionCodec.definition(kind: .basket, fields: fields),
            definition)
    }

    /// Hand-built from the TypeScript layout: data fields from
    /// RegistryClient.ts:688-722, operator key last; locked and signed by
    /// `pushdrop.lock(fields, [1, "basketmap"], "1", "anyone", true)`
    /// (RegistryClient.ts:320, PushDrop.ts:148-204); checked by
    /// registryTokenValidation.ts:20-52.
    func testDecodesHandBuiltTypeScriptBasketToken() throws {
        let operatorKey = try operatorPrivateKey()
        let operatorHex = Hex.encode(operatorKey.publicKey.compressedBytes)
        let text = [
            "basket.id", "Example", "https://icon.example/i.png", "description",
            "https://docs.example/", operatorHex,
        ]
        let fields = text.map { Array($0.utf8) }
        let lockingKey = try linkedPrivateKey(operatorKey, invoice: "1-basketmap-1")
        let signature = try lockingKey.sign(digest: BSVHashing.sha256(Array(fields.joined())))

        var bytes: [UInt8] = [0x21] + lockingKey.publicKey.compressedBytes + [0xac]
        for field in fields { bytes += [UInt8(field.count)] + field }
        bytes += [UInt8(signature.derBytes.count)] + signature.derBytes
        bytes += [0x6d, 0x6d, 0x6d, 0x75]
        let script = try Script(bytes: bytes, maximumByteCount: 10_000)

        let expected = RegistryDefinition.basket(
            try RegistryBasketDefinition(
                basketID: "basket.id",
                metadata: try RegistryMetadata(
                    name: "Example", iconURL: "https://icon.example/i.png",
                    description: "description", documentationURL: "https://docs.example/"),
                registryOperator: try RegistryOperator(compressedHex: operatorHex)))
        XCTAssertEqual(try RegistryDefinitionCodec.decode(script, kind: .basket), expected)
    }

    func testWalletLockMatchesTypeScriptAndRoundTrips() async throws {
        let operatorKey = try operatorPrivateKey()
        let wallet = ProtoWallet(rootKey: operatorKey)
        let registryOperator = RegistryOperator(publicKey: operatorKey.publicKey)
        let metadata = try RegistryMetadata(
            name: "Example", iconURL: "https://icon.example/i.png",
            description: "description", documentationURL: "https://docs.example/")
        let definitions: [RegistryDefinition] = [
            .basket(
                try RegistryBasketDefinition(
                    basketID: "basket.id", metadata: metadata, registryOperator: registryOperator)),
            .protocolDefinition(
                try RegistryProtocolDefinition(
                    protocolID: try WalletProtocolID(securityLevel: .everyApp, name: "example value"),
                    metadata: metadata,
                    registryOperator: registryOperator)),
            .certificate(
                try RegistryCertificateDefinition(
                    type: "example certificate", metadata: metadata,
                    fields: ["a": try descriptor("aye"), "z": try descriptor("zee")],
                    registryOperator: registryOperator)),
        ]
        let invoices = ["1-basketmap-1", "1-protomap-1", "1-certmap-1"]
        for (definition, invoice) in zip(definitions, invoices) {
            let script = try await RegistryDefinitionCodec.lockingScript(
                for: definition, using: wallet)
            let decoded = try PushDrop.decode(script, lockPosition: .beforeCompatibility)
            XCTAssertEqual(decoded.fields.count, definition.kind.dataFieldCount + 1)
            XCTAssertEqual(
                decoded.publicKey,
                try linkedPrivateKey(operatorKey, invoice: invoice).publicKey)
            XCTAssertEqual(
                Array(decoded.fields.dropLast()),
                try RegistryDefinitionCodec.fields(for: definition))
            XCTAssertEqual(
                try RegistryDefinitionCodec.decode(script, kind: definition.kind), definition)
        }

        // An empty field is written as OP_0 and read back as [0], so its
        // signature could never verify (TypeScript PushDrop.ts:103-107).
        do {
            _ = try await RegistryDefinitionCodec.lockingScript(
                for: .basket(try basketDefinition(registryOperator: registryOperator)),
                using: wallet)
            XCTFail("expected an empty-field error")
        } catch {
            // The error names the empty field.
            XCTAssertEqual(error as? RegistryError, .emptyField(name: "iconURL"))
        }

        let other = ProtoWallet(rootKey: try PrivateKey(Array(repeating: 0, count: 31) + [0x44]))
        do {
            _ = try await RegistryDefinitionCodec.lockingScript(for: definitions[0], using: other)
            XCTFail("expected an operator mismatch")
        } catch {
            XCTAssertEqual(error as? RegistryError, .walletIdentityIsNotRegistryOperator)
        }
    }

    func testRejectsTokensTypeScriptRejects() throws {
        let operatorKey = try operatorPrivateKey()
        let fields = try publishableBasketFields(operatorKey)
        let linked = try linkedPrivateKey(operatorKey, invoice: "1-basketmap-1")

        // The previous Swift shape: six unsigned fields.
        let unsigned = try PushDrop.lockingScript(
            fields: fields, publicKey: linked.publicKey, lockPosition: .beforeCompatibility)
        XCTAssertThrowsError(try RegistryDefinitionCodec.decode(unsigned, kind: .basket)) { error in
            XCTAssertEqual(
                error as? RegistryError,
                .unexpectedFieldCount(kind: .basket, actual: 6, expected: 7))
        }

        // Signed under the previous Swift protocol level, [2, "basketmap"].
        let levelTwo = try linkedPrivateKey(operatorKey, invoice: "2-basketmap-1")
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.decode(
                try signedScript(fields: fields, key: levelTwo), kind: .basket)
        ) { error in
            XCTAssertEqual(error as? RegistryError, .lockingKeyNotLinkedToOperator)
        }

        // Locked to the operator key itself.
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.decode(
                try signedScript(fields: fields, key: operatorKey), kind: .basket)
        ) { error in
            XCTAssertEqual(error as? RegistryError, .lockingKeyNotLinkedToOperator)
        }

        // Linked key, but the signature covers other bytes.
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.decode(
                try signedScript(fields: fields, key: linked, signedSuffix: [1]), kind: .basket)
        ) { error in
            XCTAssertEqual(error as? RegistryError, .invalidSignature)
        }

        // A basket token is not a protocol token.
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.decode(
                try signedScript(fields: fields, key: linked), kind: .protocol))
    }

    /// TypeScript reads an OP_0 field as "\u{0}" (PushDropValidation.ts) and
    /// RegistryClient.ts:66-75 rejects that text, so an operator-signed token
    /// with an OP_0 field is refused rather than read as empty text.
    func testRejectsOperatorSignedOPZeroField() throws {
        let operatorKey = try operatorPrivateKey()
        let linked = try linkedPrivateKey(operatorKey, invoice: "1-basketmap-1")
        var fields = try publishableBasketFields(operatorKey)
        fields[3] = [0]
        let script = try signedScript(fields: fields, key: linked)
        // The script really carries OP_0 for that field.
        XCTAssertEqual(
            try PushDrop.decode(script, lockPosition: .beforeCompatibility).fields[3], [0])
        XCTAssertThrowsError(try RegistryDefinitionCodec.decode(script, kind: .basket)) { error in
            XCTAssertEqual(error as? RegistryError, .emptyField(name: "description"))
        }
    }

    /// registryTokenValidation.ts:10-11, 28-32: at most 16 KiB per field and
    /// 64 KiB for all fields, signature included.
    func testEnforcesTypeScriptTokenSizeBounds() async throws {
        XCTAssertEqual(RegistryDefinitionCodec.maximumTokenFieldByteCount, 16_384)
        XCTAssertEqual(RegistryDefinitionCodec.maximumTokenPayloadByteCount, 65_536)
        let operatorKey = try operatorPrivateKey()
        let linked = try linkedPrivateKey(operatorKey, invoice: "1-basketmap-1")
        let base = try publishableBasketFields(operatorKey)

        var largest = base
        largest[3] = [UInt8](repeating: 0x61, count: 16_384)
        XCTAssertNoThrow(
            try RegistryDefinitionCodec.decode(
                try signedScript(fields: largest, key: linked), kind: .basket))

        var tooLarge = base
        tooLarge[3] = [UInt8](repeating: 0x61, count: 16_385)
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.decode(
                try signedScript(fields: tooLarge, key: linked), kind: .basket)
        ) { error in
            XCTAssertEqual(
                error as? RegistryError,
                .textTooLong(field: "description", actual: 16_385, maximum: 16_384))
        }

        var tooMuch = base
        for index in 0..<4 { tooMuch[index] = [UInt8](repeating: 0x61, count: 16_384) }
        let signature = try linked.sign(digest: BSVHashing.sha256(Array(tooMuch.joined())))
        let total = tooMuch.reduce(0) { $0 + $1.count } + signature.derBytes.count
        XCTAssertGreaterThan(total, 65_536)
        let script = try PushDrop.lockingScript(
            fields: tooMuch + [signature.derBytes],
            publicKey: linked.publicKey,
            lockPosition: .beforeCompatibility)
        XCTAssertThrowsError(try RegistryDefinitionCodec.decode(script, kind: .basket)) { error in
            XCTAssertEqual(
                error as? RegistryError, .aggregateTooLarge(actual: total, maximum: 65_536))
        }

        // The writer refuses before asking the wallet to sign.
        let wallet = ProtoWallet(rootKey: operatorKey)
        let definition = try RegistryDefinitionCodec.definition(kind: .basket, fields: tooLarge)
        do {
            _ = try await RegistryDefinitionCodec.lockingScript(for: definition, using: wallet)
            XCTFail("expected a field size error")
        } catch {
            XCTAssertEqual(
                error as? RegistryError,
                .textTooLong(field: "description", actual: 16_385, maximum: 16_384))
        }
    }

    /// TypeScript verifies without a low-S rule (only its signer forces
    /// low-S), so a high-S operator signature is accepted.
    func testAcceptsHighSSignature() throws {
        let operatorKey = try operatorPrivateKey()
        let linked = try linkedPrivateKey(operatorKey, invoice: "1-basketmap-1")
        let fields = try publishableBasketFields(operatorKey)
        let digest = BSVHashing.sha256(Array(fields.joined()))
        let high = try highS(try linked.sign(digest: digest))
        XCTAssertFalse(linked.publicKey.verify(high, digest: digest))
        let script = try PushDrop.lockingScript(
            fields: fields + [high.derBytes],
            publicKey: linked.publicKey,
            lockPosition: .beforeCompatibility)
        XCTAssertNoThrow(try RegistryDefinitionCodec.decode(script, kind: .basket))
    }

    func testRejectsNonCanonicalDERSignature() throws {
        let operatorKey = try operatorPrivateKey()
        let linked = try linkedPrivateKey(operatorKey, invoice: "1-basketmap-1")
        let fields = try publishableBasketFields(operatorKey)
        let der = try linked.sign(digest: BSVHashing.sha256(Array(fields.joined()))).derBytes
        // Long-form length byte (0x81) where the short form is required.
        let nonCanonical = [der[0], 0x81] + der[1...]
        let script = try PushDrop.lockingScript(
            fields: fields + [Array(nonCanonical)],
            publicKey: linked.publicKey,
            lockPosition: .beforeCompatibility)
        XCTAssertThrowsError(try RegistryDefinitionCodec.decode(script, kind: .basket)) { error in
            XCTAssertEqual(error as? RegistryError, .invalidSignatureEncoding)
        }
    }

    func testPushDropFailureKeepsItsCause() throws {
        let script = try Script(bytes: [0x51], maximumByteCount: 16)
        XCTAssertThrowsError(try RegistryDefinitionCodec.decode(script, kind: .basket)) { error in
            guard case .pushDropFailure(let cause) = error as? RegistryError else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertTrue(
                (error as? RegistryError)?.description.contains("\(cause)") ?? false)
        }
    }

    func testProtocolCanonicalJSONRoundTrip() throws {
        let definition = RegistryDefinition.protocolDefinition(
            try RegistryProtocolDefinition(
                protocolID: try WalletProtocolID(
                    securityLevel: .everyAppAndCounterparty,
                    name: "example value"),
                metadata: try fixtureMetadata(),
                registryOperator: try fixtureOperator()))
        let fields = try RegistryDefinitionCodec.fields(for: definition)
        XCTAssertEqual(String(decoding: fields[0], as: UTF8.self), "[2,\"example value\"]")
        XCTAssertEqual(
            try RegistryDefinitionCodec.definition(kind: .protocol, fields: fields),
            definition)
    }

    func testCertificateFieldsUseByteSortedCanonicalMap() throws {
        let certificate = try RegistryCertificateDefinition(
            type: "example certificate",
            metadata: try fixtureMetadata(),
            fields: [
                "é": try descriptor("accent"),
                "z": try descriptor("zee"),
            ],
            registryOperator: try fixtureOperator())
        let fields = try RegistryDefinitionCodec.fields(for: .certificate(certificate))
        XCTAssertEqual(
            String(decoding: fields[5], as: UTF8.self),
            "{\"z\":{\"friendlyName\":\"zee\",\"description\":\"description\",\"type\":\"text\",\"fieldIcon\":\"icon\"},\"é\":{\"friendlyName\":\"accent\",\"description\":\"description\",\"type\":\"text\",\"fieldIcon\":\"icon\"}}"
        )
        XCTAssertEqual(
            try RegistryDefinitionCodec.definition(kind: .certificate, fields: fields),
            .certificate(certificate))
    }

    func testMalformedFieldsFailBeforeIndexingOrJSONParsing() throws {
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.definition(kind: .basket, fields: [])
        ) { error in
            XCTAssertEqual(
                error as? RegistryError,
                .unexpectedFieldCount(kind: .basket, actual: 0, expected: 6))
        }

        var fields = try RegistryDefinitionCodec.fields(for: .basket(try basketDefinition()))
        fields[3] = [0xFF]
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.definition(kind: .basket, fields: fields)
        ) { error in
            XCTAssertEqual(error as? RegistryError, .invalidText(field: "definitionField"))
        }

        fields = try RegistryDefinitionCodec.fields(for: .basket(try basketDefinition()))
        fields[5] = Array("not-a-public-key".utf8)
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.definition(kind: .basket, fields: fields)
        ) { error in
            XCTAssertEqual(error as? RegistryError, .invalidRegistryOperator)
        }
    }

    func testNonCanonicalEmbeddedJSONIsRejected() throws {
        var fields = try RegistryDefinitionCodec.fields(
            for: .protocolDefinition(
                try RegistryProtocolDefinition(
                    protocolID: try WalletProtocolID(
                        securityLevel: .everyAppAndCounterparty,
                        name: "example value"),
                    metadata: try fixtureMetadata(),
                    registryOperator: try fixtureOperator())))
        fields[0] = Array("[2, \"example value\"]".utf8)
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.definition(kind: .protocol, fields: fields)
        ) { error in
            XCTAssertEqual(error as? RegistryError, .nonCanonicalEmbeddedJSON(field: "protocolID"))
        }

    }

    /// TypeScript writes `JSON.stringify(data.fields)` in caller order and
    /// reads it with `JSON.parse` (RegistryClient.ts:711, 765), so any key
    /// order or spacing is valid. Unknown descriptor keys are rejected, as
    /// RegistryClient.ts:131-134 does.
    func testCertificateFieldsJSONAcceptsAnyOrder() throws {
        let canonical = try certificateDefinition()
        var fields = try RegistryDefinitionCodec.fields(for: .certificate(canonical))
        fields[5] = Array(
            "{\"z\":{\"type\":\"text\",\"fieldIcon\":\"icon\",\"friendlyName\":\"zee\",\"description\":\"description\"}, \"a\": {\"friendlyName\":\"aye\",\"description\":\"description\",\"type\":\"text\",\"fieldIcon\":\"icon\"}}"
                .utf8)
        XCTAssertEqual(
            try RegistryDefinitionCodec.definition(kind: .certificate, fields: fields),
            .certificate(canonical))

        fields[5] = Array(
            "{\"a\":{\"friendlyName\":\"aye\",\"description\":\"d\",\"type\":\"text\",\"fieldIcon\":\"icon\",\"extra\":\"x\"}}"
                .utf8)
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.definition(kind: .certificate, fields: fields)
        ) { error in
            XCTAssertEqual(
                error as? RegistryError, .malformedEmbeddedJSON(field: "certificateFields"))
        }

        fields[5] = Array("{\"a\":{\"friendlyName\":\"aye\"}}".utf8)
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.definition(kind: .certificate, fields: fields))
    }

    func testExplicitLimitsApplyBeforeMaterialization() throws {
        let limits = try RegistryLimits(
            maximumDefinitionTextUTF8ByteCount: 16,
            maximumDefinitionAggregateUTF8ByteCount: 24,
            maximumCertificateFieldCount: 1,
            maximumCertificateFieldNameUTF8ByteCount: 8,
            maximumCertificateFieldTextUTF8ByteCount: 8,
            maximumQueryOperatorCount: 1,
            maximumRecordCount: 1,
            maximumTokenBEEFByteCount: 16,
            maximumTokenLockingScriptByteCount: 16,
            pushDropLimits: try PushDropLimits(
                maximumFieldCount: 8,
                maximumFieldByteCount: 16,
                maximumScriptByteCount: 256))
        XCTAssertThrowsError(try basketDefinition(limits: limits))
        XCTAssertThrowsError(
            try RegistryQueryOperators(
                [try fixtureOperator(), try fixtureOperator()], limits: limits))
        XCTAssertThrowsError(
            try RegistryCertificateDefinition(
                type: "type",
                metadata: try fixtureMetadata(limits: limits),
                fields: [
                    "a": try descriptor("a", limits: limits),
                    "b": try descriptor("b", limits: limits),
                ],
                registryOperator: try fixtureOperator(),
                limits: limits))

        let aggregateLimits = try RegistryLimits(
            maximumDefinitionTextUTF8ByteCount: 128,
            maximumDefinitionAggregateUTF8ByteCount: 90,
            maximumCertificateFieldCount: 1,
            maximumCertificateFieldNameUTF8ByteCount: 8,
            maximumCertificateFieldTextUTF8ByteCount: 16,
            maximumQueryOperatorCount: 1,
            maximumRecordCount: 1,
            maximumTokenBEEFByteCount: 16,
            maximumTokenLockingScriptByteCount: 16,
            pushDropLimits: try PushDropLimits(
                maximumFieldCount: 8,
                maximumFieldByteCount: 128,
                maximumScriptByteCount: 256))
        XCTAssertThrowsError(
            try RegistryBasketDefinition(
                basketID: "basket.id",
                metadata: try fixtureMetadata(),
                registryOperator: try fixtureOperator(),
                limits: aggregateLimits)
        ) { error in
            XCTAssertEqual(
                error as? RegistryError,
                .aggregateTooLarge(actual: 93, maximum: 90))
        }
    }

    func testOperatorDiagnosticsAreRedactedAndValuesAreSendable() throws {
        let operatorValue = try fixtureOperator()
        XCTAssertEqual(operatorValue.description, "<redacted registry operator>")
        XCTAssertFalse(operatorValue.description.contains(operatorValue.compressedHex))
        XCTAssertTrue(operatorValue.customMirror.children.isEmpty)
        assertSendable(RegistryLimits.self)
        assertSendable(RegistryDefinition.self)
        assertSendable(RegistryDefinitionCodec.self)
    }

    func testTokenAndRecordLimitsAreExplicitAndRedacted() throws {
        let token = try RegistryToken(
            outpoint: Outpoint(
                transactionID: try TransactionID(displayHex: String(repeating: "01", count: 32)),
                outputIndex: 1),
            satoshis: 1,
            lockingScript: try Script(bytes: [], maximumByteCount: 16),
            beef: [1, 2, 3])
        XCTAssertEqual(token.description, "<redacted registry token>")
        XCTAssertTrue(token.customMirror.children.isEmpty)
        let record = RegistryRecord(
            definition: .basket(try basketDefinition()),
            token: token)
        XCTAssertEqual(record.description, "<redacted registry record>")
        XCTAssertTrue(record.customMirror.children.isEmpty)
        XCTAssertThrowsError(try RegistryRecords([record, record], limits: try recordLimits()))
        XCTAssertThrowsError(
            try RegistryToken(
                outpoint: token.outpoint,
                satoshis: 1,
                lockingScript: token.lockingScript,
                beef: Array(repeating: 0, count: 17),
                limits: try recordLimits()))
    }

    func testQueryValuesAreTypedAndBounded() throws {
        let limits = try recordLimits()
        XCTAssertEqual(try RegistryBasketQuery(limits: limits).registryOperators, .empty)
        XCTAssertNoThrow(
            try RegistryProtocolQuery(
                protocolID: try WalletProtocolID(securityLevel: .everyApp, name: "example value"),
                limits: limits))
        XCTAssertThrowsError(
            try RegistryCertificateQuery(
                registryOperators: try RegistryQueryOperators(
                    [try fixtureOperator(), try fixtureOperator()]),
                limits: limits))
    }

    private func basketDefinition(
        limits: RegistryLimits = .standard,
        registryOperator: RegistryOperator? = nil
    ) throws -> RegistryBasketDefinition {
        try RegistryBasketDefinition(
            basketID: "basket.id",
            metadata: try fixtureMetadata(limits: limits),
            registryOperator: try registryOperator ?? fixtureOperator(),
            limits: limits)
    }

    private func certificateDefinition(
        registryOperator: RegistryOperator? = nil
    ) throws -> RegistryCertificateDefinition {
        try RegistryCertificateDefinition(
            type: "example certificate",
            metadata: try fixtureMetadata(),
            fields: ["a": try descriptor("aye"), "z": try descriptor("zee")],
            registryOperator: try registryOperator ?? fixtureOperator())
    }

    /// Basket data fields with every field non-empty, so a token can verify.
    private func publishableBasketFields(_ operatorKey: PrivateKey) throws -> [[UInt8]] {
        [
            "basket.id", "Example", "https://icon.example/i.png", "description",
            "https://docs.example/", Hex.encode(operatorKey.publicKey.compressedBytes),
        ].map { Array($0.utf8) }
    }

    /// The same signature with S replaced by n - S.
    private func highS(_ signature: ECDSASignature) throws -> ECDSASignature {
        let order: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ]
        let s = Array(signature.compactBytes[32...])
        var negated = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in (0..<32).reversed() {
            var digit = Int(order[index]) - Int(s[index]) - borrow
            borrow = digit < 0 ? 1 : 0
            if digit < 0 { digit += 256 }
            negated[index] = UInt8(digit)
        }
        return try ECDSASignature(compactBytes: Array(signature.compactBytes[..<32]) + negated)
    }

    private func operatorPrivateKey() throws -> PrivateKey {
        try PrivateKey(Array(repeating: 0, count: 31) + [0x33])
    }

    /// The operator's BRC-42 child with the anyone key (scalar 1) as the
    /// other party, which is what TypeScript locks and signs with.
    private func linkedPrivateKey(_ key: PrivateKey, invoice: String) throws -> PrivateKey {
        let anyone = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        return try key.derivedChild(with: anyone.publicKey, invoiceNumber: invoice)
    }

    private func signedScript(
        fields: [[UInt8]],
        key: PrivateKey,
        signedSuffix: [UInt8] = []
    ) throws -> Script {
        let signature = try key.sign(
            digest: BSVHashing.sha256(Array(fields.joined()) + signedSuffix))
        return try PushDrop.lockingScript(
            fields: fields + [signature.derBytes],
            publicKey: key.publicKey,
            lockPosition: .beforeCompatibility)
    }

    private func fixtureMetadata(
        limits: RegistryLimits = .standard
    ) throws -> RegistryMetadata {
        try RegistryMetadata(
            name: "Example",
            iconURL: "",
            description: "description",
            documentationURL: "",
            limits: limits)
    }

    private func descriptor(
        _ name: String,
        limits: RegistryLimits = .standard
    ) throws -> RegistryCertificateFieldDescriptor {
        try RegistryCertificateFieldDescriptor(
            friendlyName: name,
            description: "description",
            type: .text,
            fieldIcon: "icon",
            limits: limits)
    }

    private func fixtureOperator() throws -> RegistryOperator {
        try RegistryOperator(
            compressedHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    }

    private func recordLimits() throws -> RegistryLimits {
        try RegistryLimits(
            maximumDefinitionTextUTF8ByteCount: 16,
            maximumDefinitionAggregateUTF8ByteCount: 256,
            maximumCertificateFieldCount: 1,
            maximumCertificateFieldNameUTF8ByteCount: 8,
            maximumCertificateFieldTextUTF8ByteCount: 16,
            maximumQueryOperatorCount: 1,
            maximumRecordCount: 1,
            maximumTokenBEEFByteCount: 16,
            maximumTokenLockingScriptByteCount: 16,
            pushDropLimits: try PushDropLimits(
                maximumFieldCount: 8,
                maximumFieldByteCount: 16,
                maximumScriptByteCount: 256))
    }
}

private func assertSendable<T: Sendable>(_ type: T.Type) {}
