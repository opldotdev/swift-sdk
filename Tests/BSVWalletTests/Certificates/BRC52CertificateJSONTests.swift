import Foundation
import XCTest
import BSVCore
import BSVKeys
import BSVTransaction
@testable import BSVWallet

final class BRC52CertificateJSONTests: XCTestCase {
    func testStrictJSONRoundTripPreservesCanonicalCertificateShape() throws {
        let certificate = try makeCertificate(fields: [("field", [1, 2, 3])])
        let data = try certificate.jsonData()

        XCTAssertEqual(try Certificate(json: data), certificate)
        XCTAssertEqual(try Certificate(json: [UInt8](data)), certificate)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        XCTAssertEqual(
            Set(object.keys),
            Set([
                "type", "serialNumber", "subject", "certifier",
                "revocationOutpoint", "fields",
            ])
        )
        XCTAssertEqual((object["fields"] as? [String: String])?["field"], "AQID")

        let withNullSignature = json(
            fields: "\"field\":\"AQID\"",
            trailingMembers: ",\"signature\":null"
        )
        XCTAssertEqual(try Certificate(json: Data(withNullSignature.utf8)), certificate)
    }

    func testDuplicateTopLevelKeysIncludingEscapedEquivalentAreRejected() throws {
        let duplicate = json(
            fields: "\"field\":\"AQID\"",
            trailingMembers: ",\"type\":\"\(typeBase64)\""
        )
        assertCertificateError(.invalidJSON) {
            try Certificate(json: Data(duplicate.utf8))
        }

        let escapedEquivalent = json(
            fields: "\"field\":\"AQID\"",
            trailingMembers: ",\"t\\u0079pe\":\"\(typeBase64)\""
        )
        assertCertificateError(.invalidJSON) {
            try Certificate(json: Data(escapedEquivalent.utf8))
        }
    }

    func testDuplicateFieldKeysIncludingEscapedEquivalentAreRejected() throws {
        let duplicate = json(fields: "\"name\":\"AQ==\",\"name\":\"Ag==\"")
        assertCertificateError(.duplicateFieldName) {
            try Certificate(json: Data(duplicate.utf8))
        }

        let escapedEquivalent = json(
            fields: "\"name\":\"AQ==\",\"na\\u006de\":\"Ag==\""
        )
        assertCertificateError(.duplicateFieldName) {
            try Certificate(json: Data(escapedEquivalent.utf8))
        }
    }

    func testCanonicallyEquivalentFieldNamesCannotCollideDuringJSONEncoding() throws {
        let precomposed = try CertificateFieldName("\u{00e9}")
        let decomposed = try CertificateFieldName("e\u{0301}")
        XCTAssertEqual(precomposed.value, decomposed.value)
        XCTAssertNotEqual(precomposed.utf8Bytes, decomposed.utf8Bytes)

        let fields = [
            precomposed: try CertificateCiphertext([1]),
            decomposed: try CertificateCiphertext([2]),
        ]
        XCTAssertEqual(fields.count, 2)
        assertCertificateError(.duplicateFieldName) {
            try makeCertificate(fields: fields)
        }
    }

    func testUnknownMembersAndNonStringFieldValuesAreRejected() throws {
        let unknown = json(
            fields: "\"field\":\"AQID\"",
            trailingMembers: ",\"unknown\":\"value\""
        )
        assertCertificateError(.invalidJSON) {
            try Certificate(json: Data(unknown.utf8))
        }
        let nonString = json(fields: "\"field\":{}")
        assertCertificateError(.invalidJSON) {
            try Certificate(json: Data(nonString.utf8))
        }
    }

    func testExactAndMaximumPlusOneJSONInputLimits() throws {
        let data = Data(json(fields: "\"field\":\"AQID\"").utf8)
        let exact = try CertificateLimits(maximumJSONByteCount: data.count)
        XCTAssertNoThrow(try Certificate(json: data, limits: exact))

        let oneShort = try CertificateLimits(maximumJSONByteCount: data.count - 1)
        assertCertificateError(
            .certificateJSONTooLarge(actual: data.count, maximum: data.count - 1)
        ) {
            try Certificate(json: data, limits: oneShort)
        }
        XCTAssertThrowsError(try CertificateLimits(maximumJSONByteCount: -1)) {
            XCTAssertEqual($0 as? CertificateError, .invalidLimits)
        }
    }

    func testExactAndMaximumPlusOneFieldBodyAndNameLimits() throws {
        let bodyLimits = try CertificateLimits(
            maximumFieldCiphertextByteCount: 3
        )
        XCTAssertNoThrow(try Certificate(
            json: Data(json(fields: "\"field\":\"AQID\"").utf8),
            limits: bodyLimits
        ))
        assertCertificateError(.fieldValueTooLarge(actual: 4, maximum: 3)) {
            try Certificate(
                json: Data(json(fields: "\"field\":\"AQIDBA==\"").utf8),
                limits: bodyLimits
            )
        }

        let exactName = String(repeating: "n", count: 50)
        XCTAssertNoThrow(try Certificate(
            json: Data(json(fields: "\"\(exactName)\":\"AQ==\"").utf8)
        ))
        let overlongName = String(repeating: "n", count: 51)
        assertCertificateError(.fieldNameTooLong(actual: 51, maximum: 50)) {
            try Certificate(
                json: Data(json(fields: "\"\(overlongName)\":\"AQ==\"").utf8)
            )
        }
    }

    func testExactAndMaximumPlusOneFieldCountLimit() throws {
        let limits = try CertificateLimits(maximumFieldCount: 2)
        let exact = json(fields: "\"a\":\"AQ==\",\"b\":\"Ag==\"")
        XCTAssertNoThrow(try Certificate(json: Data(exact.utf8), limits: limits))

        let over = json(
            fields: "\"a\":\"AQ==\",\"b\":\"Ag==\",\"c\":\"Aw==\""
        )
        assertCertificateError(.tooManyFields(actual: 3, maximum: 2)) {
            try Certificate(json: Data(over.utf8), limits: limits)
        }
    }

    func testMultiMegabyteHostileInputIsRejectedByByteCountBeforeParsing() throws {
        let limits = try CertificateLimits(maximumJSONByteCount: 1_024)
        var hostile = Data("{\"type\":\"".utf8)
        hostile.append(Data(repeating: 0x41, count: 4 * 1_024 * 1_024))

        assertCertificateError(
            .certificateJSONTooLarge(actual: hostile.count, maximum: 1_024)
        ) {
            try Certificate(json: hostile, limits: limits)
        }
    }

    private var typeBase64: String {
        Base64Encoding.encode([UInt8](repeating: 1, count: 32))
    }

    private var serialBase64: String {
        Base64Encoding.encode([UInt8](repeating: 2, count: 32))
    }

    private func json(fields: String, trailingMembers: String = "") -> String {
        let subject = try! key(7).publicKey
        let certifier = try! key(9).publicKey
        let outpoint = Outpoint(
            transactionID: TransactionID(
                exactDigestBytesGuaranteed: [UInt8](repeating: 3, count: 32)
            ),
            outputIndex: 1
        )
        return """
        {"type":"\(typeBase64)","serialNumber":"\(serialBase64)","subject":"\(Hex.encode(subject.compressedBytes))","certifier":"\(Hex.encode(certifier.compressedBytes))","revocationOutpoint":"\(outpoint)","fields":{\(fields)}\(trailingMembers)}
        """
    }

    private func makeCertificate(fields: [(String, [UInt8])]) throws -> Certificate {
        var values: [CertificateFieldName: CertificateCiphertext] = [:]
        for (name, bytes) in fields {
            values[try CertificateFieldName(name)] = try CertificateCiphertext(bytes)
        }
        return try Certificate(
            type: CertificateTypeID([UInt8](repeating: 1, count: 32)),
            serialNumber: CertificateSerialNumber([UInt8](repeating: 2, count: 32)),
            subject: key(7).publicKey,
            certifier: key(9).publicKey,
            revocationOutpoint: Outpoint(
                transactionID: TransactionID(
                    exactDigestBytesGuaranteed: [UInt8](repeating: 3, count: 32)
                ),
                outputIndex: 1
            ),
            fields: values
        )
    }

    private func makeCertificate(
        fields: [CertificateFieldName: CertificateCiphertext]
    ) throws -> Certificate {
        try Certificate(
            type: CertificateTypeID([UInt8](repeating: 1, count: 32)),
            serialNumber: CertificateSerialNumber([UInt8](repeating: 2, count: 32)),
            subject: key(7).publicKey,
            certifier: key(9).publicKey,
            revocationOutpoint: Outpoint(
                transactionID: TransactionID(
                    exactDigestBytesGuaranteed: [UInt8](repeating: 3, count: 32)
                ),
                outputIndex: 1
            ),
            fields: fields
        )
    }

    private func key(_ scalar: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [scalar])
    }

    private func assertCertificateError<T>(
        _ expected: CertificateError,
        _ expression: () throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            XCTAssertEqual(error as? CertificateError, expected, file: file, line: line)
        }
    }
}
