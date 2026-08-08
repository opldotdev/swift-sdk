import BSVCore
import BSVScript
import BSVTransaction
import Foundation
import Testing

@Suite("Strict transaction JSON")
struct TransactionJSONTests {
    private let rawHex = "0100000001abad53d72f342dd3f338e5e3346b492440f8ea821f8b8800e318f461cc5ea5a20100000000ffffffff02000000000000000008006a0548656c6c6f7f030000000000001976a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac00000000"

    @Test("canonical field order and compact bytes are deterministic")
    func canonicalTransaction() throws {
        let limits = try makeLimits()
        let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
        let transactionID = try transaction.transactionID(limits: limits.transactionLimits).displayHex
        let expected = "{\"txid\":\"\(transactionID)\",\"hex\":\"\(rawHex)\",\"inputs\":[{\"unlockingScript\":\"\",\"txid\":\"a2a55ecc61f418e300888b1f82eaf84024496b34e3e538f3d32d342fd753adab\",\"vout\":1,\"sequence\":4294967295}],\"outputs\":[{\"satoshis\":0,\"lockingScript\":\"006a0548656c6c6f\"},{\"satoshis\":895,\"lockingScript\":\"76a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac\"}],\"version\":1,\"lockTime\":0}"

        let document = try transaction.jsonBytes(limits: limits)
        #expect(String(decoding: document, as: UTF8.self) == expected)
        #expect(try Transaction(jsonBytes: document, limits: limits) == transaction)
    }

    @Test("input and output values use the shared Script JSON codec")
    func componentRoundTrips() throws {
        let limits = try makeLimits()
        let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
        let inputJSON = try transaction.inputs[0].jsonBytes(limits: limits)
        let outputJSON = try transaction.outputs[1].jsonBytes(limits: limits)

        #expect(try TransactionInput(jsonBytes: inputJSON, limits: limits) == transaction.inputs[0])
        #expect(try TransactionOutput(jsonBytes: outputJSON, limits: limits) == transaction.outputs[1])
        #expect(String(decoding: inputJSON, as: UTF8.self).hasPrefix("{\"unlockingScript\":\"\",\"txid\":"))
        #expect(String(decoding: outputJSON, as: UTF8.self) == "{\"satoshis\":895,\"lockingScript\":\"76a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac\"}")

        #expect(try TransactionInput(
            jsonBytes: Array((" \n" + String(decoding: inputJSON, as: UTF8.self) + "\t").utf8),
            limits: limits
        ) == transaction.inputs[0])
        #expect(throws: TransactionJSONError.self) {
            try TransactionInput(jsonBytes: inputJSON + Array(" null".utf8), limits: limits)
        }
        #expect(throws: TransactionJSONError.self) {
            try TransactionOutput(jsonBytes: outputJSON + Array(" null".utf8), limits: limits)
        }
    }

    @Test("empty transaction arrays use pinned Go null representation")
    func emptyTransactionNullArrays() throws {
        let limits = try makeLimits()
        let transaction = Transaction()
        let document = try transaction.jsonBytes(limits: limits)
        let transactionID = try transaction.transactionID(limits: limits.transactionLimits).displayHex
        let expected = "{\"txid\":\"\(transactionID)\",\"hex\":\"01000000000000000000\",\"inputs\":null,\"outputs\":null,\"version\":1,\"lockTime\":0}"
        #expect(String(decoding: document, as: UTF8.self) == expected)
        #expect(try Transaction(jsonBytes: document, limits: limits) == transaction)

        let arrays = expected
            .replacingOccurrences(of: "\"inputs\":null", with: "\"inputs\":[]")
            .replacingOccurrences(of: "\"outputs\":null", with: "\"outputs\":[]")
        #expect(try Transaction(jsonBytes: Array(arrays.utf8), limits: limits) == transaction)
    }

    @Test("construction metadata stays outside raw transaction JSON")
    func constructionMetadata() throws {
        let limits = try makeLimits()
        var transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
        transaction.inputs[0].sourceOutput = TransactionOutput(
            satoshis: 2_000,
            lockingScript: try Script(hex: "51", maximumByteCount: 1)
        )
        transaction.inputs[0].estimatedUnlockingScriptByteCount = 107
        transaction.outputs[0].isChange = true

        let decoded = try Transaction(
            jsonBytes: transaction.jsonBytes(limits: limits),
            limits: limits
        )
        #expect(decoded == transaction)
        #expect(decoded.inputs[0].sourceOutput == nil)
        #expect(decoded.inputs[0].estimatedUnlockingScriptByteCount == nil)
        #expect(!decoded.outputs[0].isChange)
        #expect(try decoded.hex(format: .raw, limits: limits.transactionLimits) == rawHex)
    }

    @Test("object order is flexible but unknown, duplicate, missing, and trailing data fail")
    func strictObjectBoundary() throws {
        let limits = try makeLimits()
        let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
        let canonical = String(decoding: try transaction.jsonBytes(limits: limits), as: UTF8.self)
        let transactionID = try transaction.transactionID(limits: limits.transactionLimits).displayHex
        let reordered = "{\"lockTime\":0,\"version\":1,\"outputs\":[{\"lockingScript\":\"006a0548656c6c6f\",\"satoshis\":0},{\"lockingScript\":\"76a914b85524abf8202a961b847a3bd0bc89d3d4d41cc588ac\",\"satoshis\":895}],\"inputs\":[{\"sequence\":4294967295,\"vout\":1,\"txid\":\"a2a55ecc61f418e300888b1f82eaf84024496b34e3e538f3d32d342fd753adab\",\"unlockingScript\":\"\"}],\"hex\":\"\(rawHex)\",\"txid\":\"\(transactionID)\"}"
        #expect(try Transaction(jsonBytes: Array(reordered.utf8), limits: limits) == transaction)

        let duplicate = canonical.replacingOccurrences(of: "{\"txid\":", with: "{\"txid\":\"\(transactionID)\",\"txid\":")
        #expect(throws: TransactionJSONError.duplicateKey("txid")) {
            try Transaction(jsonBytes: Array(duplicate.utf8), limits: limits)
        }
        let unknown = canonical.replacingOccurrences(of: "{\"txid\":", with: "{\"extra\":0,\"txid\":")
        #expect(throws: TransactionJSONError.unknownKey("extra")) {
            try Transaction(jsonBytes: Array(unknown.utf8), limits: limits)
        }
        let missing = canonical.replacingOccurrences(of: ",\"lockTime\":0", with: "")
        #expect(throws: TransactionJSONError.missingKey("lockTime")) {
            try Transaction(jsonBytes: Array(missing.utf8), limits: limits)
        }
        expectMalformed(Array((canonical + " null").utf8), limits: limits)
    }

    @Test("noncanonical text, invalid UTF-8, and unsafe numbers fail closed")
    func hostileScalars() throws {
        let limits = try makeLimits()
        let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
        let canonical = String(decoding: try transaction.jsonBytes(limits: limits), as: UTF8.self)
        let uppercaseHex = canonical.replacingOccurrences(of: rawHex, with: rawHex.uppercased())
        #expect(throws: TransactionJSONError.nonCanonicalHex(field: "hex")) {
            try Transaction(jsonBytes: Array(uppercaseHex.utf8), limits: limits)
        }
        let escapedKey = canonical.replacingOccurrences(of: "\"txid\"", with: "\"tx\\u0069d\"")
        expectMalformed(Array(escapedKey.utf8), limits: limits)
        expectMalformed(Array(canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":01").utf8), limits: limits)
        expectMalformed(Array(canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":1.0").utf8), limits: limits)

        #expect(throws: TransactionJSONError.invalidUTF8) {
            try Transaction(jsonBytes: [0x7b, 0x22, 0xff, 0x22, 0x7d], limits: limits)
        }
        #expect(throws: TransactionJSONError.unsafeJSONNumber(field: "satoshis", value: 9_007_199_254_740_992)) {
            try TransactionOutput(
                jsonBytes: Array("{\"satoshis\":9007199254740992,\"lockingScript\":\"\"}".utf8),
                limits: limits
            )
        }
        let exactSafe = try TransactionOutput(
            jsonBytes: Array("{\"satoshis\":9007199254740991,\"lockingScript\":\"\"}".utf8),
            limits: limits
        )
        #expect(exactSafe.satoshis == 9_007_199_254_740_991)
        let unsafeOutput = TransactionOutput(
            satoshis: 9_007_199_254_740_992,
            lockingScript: try Script(bytes: [], maximumByteCount: 0)
        )
        #expect(throws: TransactionJSONError.unsafeJSONNumber(field: "satoshis", value: 9_007_199_254_740_992)) {
            try unsafeOutput.jsonBytes(limits: limits)
        }
    }

    @Test("every redundant transaction field is verified against hex")
    func consistencyChecks() throws {
        let limits = try makeLimits()
        let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
        let canonical = String(decoding: try transaction.jsonBytes(limits: limits), as: UTF8.self)
        let transactionID = try transaction.transactionID(limits: limits.transactionLimits).displayHex
        let wrongID = String(repeating: "0", count: 64)
        #expect(throws: TransactionJSONError.transactionIDMismatch(expected: transactionID, actual: wrongID)) {
            try Transaction(jsonBytes: Array(canonical.replacingOccurrences(of: transactionID, with: wrongID).utf8), limits: limits)
        }
        #expect(throws: TransactionJSONError.versionMismatch(expected: 1, actual: 2)) {
            try Transaction(jsonBytes: Array(canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":2").utf8), limits: limits)
        }
        #expect(throws: TransactionJSONError.lockTimeMismatch(expected: 0, actual: 1)) {
            try Transaction(jsonBytes: Array(canonical.replacingOccurrences(of: "\"lockTime\":0", with: "\"lockTime\":1").utf8), limits: limits)
        }
        #expect(throws: TransactionJSONError.inputMismatch(index: 0)) {
            try Transaction(jsonBytes: Array(canonical.replacingOccurrences(of: "\"vout\":1", with: "\"vout\":2").utf8), limits: limits)
        }
        #expect(throws: TransactionJSONError.outputMismatch(index: 0)) {
            try Transaction(jsonBytes: Array(canonical.replacingOccurrences(of: "\"satoshis\":0", with: "\"satoshis\":1").utf8), limits: limits)
        }
    }

    @Test("document, array, script, and raw transaction limits are independent")
    func limitsAreExplicit() throws {
        let limits = try makeLimits()
        let transaction = try Transaction(hex: rawHex, limits: limits.transactionLimits)
        let document = try transaction.jsonBytes(limits: limits)
        let exact = try TransactionJSONLimits(
            maximumJSONByteCount: document.count,
            transactionLimits: limits.transactionLimits
        )
        #expect(try Transaction(jsonBytes: document, limits: exact) == transaction)
        let short = try TransactionJSONLimits(
            maximumJSONByteCount: document.count - 1,
            transactionLimits: limits.transactionLimits
        )
        #expect(throws: TransactionJSONError.documentTooLarge(actual: document.count, maximum: document.count - 1)) {
            try Transaction(jsonBytes: document, limits: short)
        }
        #expect(throws: TransactionJSONError.documentTooLarge(actual: document.count, maximum: document.count - 1)) {
            try transaction.jsonBytes(limits: short)
        }

        let largeTransactionLimits = try TransactionLimits(
            maximumTransactionByteCount: 256 * 1_024,
            maximumInputCount: 8,
            maximumOutputCount: 8,
            maximumScriptByteCount: 128 * 1_024
        )
        let largeJSONLimits = try TransactionJSONLimits(
            maximumJSONByteCount: 32,
            transactionLimits: largeTransactionLimits
        )
        let largeTransaction = Transaction(
            outputs: [TransactionOutput(
                satoshis: 1,
                lockingScript: try Script(
                    bytes: [UInt8](repeating: 0x51, count: 128 * 1_024),
                    maximumByteCount: 128 * 1_024
                )
            )]
        )
        #expect(throws: TransactionJSONError.self) {
            try largeTransaction.jsonBytes(limits: largeJSONLimits)
        }

        let noInputs = try TransactionJSONLimits(
            maximumJSONByteCount: 16_384,
            transactionLimits: TransactionLimits(
                maximumTransactionByteCount: 1_024,
                maximumInputCount: 0,
                maximumOutputCount: 8,
                maximumScriptByteCount: 256
            )
        )
        #expect(throws: TransactionJSONError.inputCountExceedsLimit(actual: 1, maximum: 0)) {
            try Transaction(jsonBytes: document, limits: noInputs)
        }

        let noScripts = try TransactionJSONLimits(
            maximumJSONByteCount: 16_384,
            transactionLimits: TransactionLimits(
                maximumTransactionByteCount: 1_024,
                maximumInputCount: 8,
                maximumOutputCount: 8,
                maximumScriptByteCount: 0
            )
        )
        #expect(throws: TransactionJSONError.valueTooLarge(field: "lockingScript", actual: 8, maximum: 0)) {
            try Transaction(jsonBytes: document, limits: noScripts)
        }

        #expect(throws: TransactionJSONError.invalidMaximumJSONByteCount(-1)) {
            try TransactionJSONLimits(maximumJSONByteCount: -1, transactionLimits: limits.transactionLimits)
        }
    }

    @Test("object keys are capped before allocation or error retention")
    func boundedObjectKeys() throws {
        let limits = try makeLimits()
        let overlongKey = String(repeating: "a", count: 65)
        let document = Array("{\"\(overlongKey)\":0}".utf8)
        #expect(throws: TransactionJSONError.valueTooLarge(
            field: "objectKey",
            actual: 65,
            maximum: 64
        )) {
            try Transaction(jsonBytes: document, limits: limits)
        }
    }

    private func makeLimits() throws -> TransactionJSONLimits {
        try TransactionJSONLimits(
            maximumJSONByteCount: 16_384,
            transactionLimits: TransactionLimits(
                maximumTransactionByteCount: 1_024,
                maximumInputCount: 8,
                maximumOutputCount: 8,
                maximumScriptByteCount: 256
            )
        )
    }

    private func expectMalformed(_ bytes: [UInt8], limits: TransactionJSONLimits) {
        do {
            _ = try Transaction(jsonBytes: bytes, limits: limits)
            Issue.record("accepted malformed JSON")
        } catch is TransactionJSONError {
            // The exact byte offset is intentionally diagnostic, not a fixture contract.
        } catch {
            Issue.record("unexpected error: \(error)")
        }
    }
}
