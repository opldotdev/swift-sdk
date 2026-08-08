import BSVCore
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
        XCTAssertEqual(
            try RegistryDefinitionKind.certificate.walletProtocolID(),
            try WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: "certmap"))
    }

    func testBasketFieldsAndCompatibilityScriptRoundTrip() throws {
        let definition = RegistryDefinition.basket(try basketDefinition())
        let fields = try RegistryDefinitionCodec.fields(for: definition)
        XCTAssertEqual(fields.count, 6)
        XCTAssertEqual(String(decoding: fields[0], as: UTF8.self), "basket.id")
        XCTAssertEqual(String(decoding: fields[2], as: UTF8.self), "")

        let script = try RegistryDefinitionCodec.lockingScript(
            for: definition,
            publicKey: try fixturePublicKey())
        XCTAssertEqual(
            try RegistryDefinitionCodec.decode(script, kind: .basket),
            definition)
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

        fields = try RegistryDefinitionCodec.fields(for: .certificate(try certificateDefinition()))
        fields[5] = Array(
            "{\"z\":{\"friendlyName\":\"zee\",\"description\":\"description\",\"type\":\"text\",\"fieldIcon\":\"icon\"},\"a\":{\"friendlyName\":\"aye\",\"description\":\"description\",\"type\":\"text\",\"fieldIcon\":\"icon\"}}"
                .utf8)
        XCTAssertThrowsError(
            try RegistryDefinitionCodec.definition(kind: .certificate, fields: fields)
        ) { error in
            XCTAssertEqual(
                error as? RegistryError, .nonCanonicalEmbeddedJSON(field: "certificateFields"))
        }
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
                maximumFieldCount: 7,
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
                maximumFieldCount: 7,
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
        limits: RegistryLimits = .standard
    ) throws -> RegistryBasketDefinition {
        try RegistryBasketDefinition(
            basketID: "basket.id",
            metadata: try fixtureMetadata(limits: limits),
            registryOperator: try fixtureOperator(),
            limits: limits)
    }

    private func certificateDefinition() throws -> RegistryCertificateDefinition {
        try RegistryCertificateDefinition(
            type: "example certificate",
            metadata: try fixtureMetadata(),
            fields: ["a": try descriptor("aye"), "z": try descriptor("zee")],
            registryOperator: try fixtureOperator())
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

    private func fixturePublicKey() throws -> PublicKey {
        try PublicKey(
            Hex.decode(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                maximumDecodedByteCount: 33))
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
                maximumFieldCount: 7,
                maximumFieldByteCount: 16,
                maximumScriptByteCount: 256))
    }
}

private func assertSendable<T: Sendable>(_ type: T.Type) {}
