import BSVCore
import BSVKeys
import BSVStorage
import XCTest

final class UHRPURLTests: XCTestCase {
    private let testHashHex = "1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca"
    private let testURL = "XUT6PqWb3GP3LR7dmBMCJwZ3oo5g1iGCF3CrpzyuJCemkGu1WGoq"

    func testHashEncodingMatchesPinnedTypeScriptVector() throws {
        let hash = try Hash256(Hex.decode(testHashHex, maximumDecodedByteCount: 32))
        let identifier = UHRPURL(hash: hash)

        XCTAssertEqual(identifier.encoded, testURL)
        XCTAssertEqual(identifier.description, testURL)
        XCTAssertEqual(identifier.uhrpURL, "uhrp://\(testURL)")
        XCTAssertEqual(identifier.webUHRPURL, "web+uhrp://\(testURL)")
    }

    func testFileHashingMatchesPinnedTypeScriptVector() throws {
        let file = try Hex.decode(
            "687da27f04a112aa48f1cab2e7949f1eea4f7ba28319c1e999910cd561a634a05a3516e6db",
            maximumDecodedByteCount: 64)

        XCTAssertEqual(try UHRPURL(fileBytes: file).encoded, testURL)
    }

    func testParsesBareAndCaseInsensitiveProtocolPrefixesCanonically() throws {
        let expectedHash = try Hash256(Hex.decode(testHashHex, maximumDecodedByteCount: 32))
        for input in [
            testURL,
            "uhrp://\(testURL)",
            "UHRP://\(testURL)",
            "web+uhrp://\(testURL)",
            "WEB+UHRP://\(testURL)",
        ] {
            let identifier = try UHRPURL(parsing: input)
            XCTAssertEqual(identifier.hash, expectedHash)
            XCTAssertEqual(identifier.encoded, testURL)
        }
    }

    func testRejectsMalformedChecksumAndVersion() throws {
        XCTAssertThrowsError(
            try UHRPURL(parsing: "XUU7cTfy6fA6q2neLDmzPqJnGB6o18PXKoGaWLPrH1SeWLKgdCKq")
        ) { error in
            XCTAssertEqual(error as? UHRPError, .invalidIdentifier)
        }

        let unsupportedVersion = Base58Check.encode([0x00, 0x00] + Array(repeating: 0, count: 32))
        XCTAssertThrowsError(try UHRPURL(parsing: unsupportedVersion)) { error in
            XCTAssertEqual(error as? UHRPError, .invalidVersion)
        }

        for payloadByteCount in [33, 35] {
            let payload: [UInt8] = [0xce, 0x00] + Array(repeating: 0, count: payloadByteCount - 2)
            XCTAssertThrowsError(try UHRPURL(parsing: Base58Check.encode(payload))) { error in
                XCTAssertEqual(error as? UHRPError, .invalidIdentifier)
            }
        }
    }

    func testInputLimitIsAppliedBeforeBase58Decoding() throws {
        let exactLimits = try UHRPLimits(
            maximumURLUTF8ByteCount: testURL.utf8.count,
            maximumContentByteCount: 64,
            maximumMIMETypeUTF8ByteCount: 32)
        XCTAssertNoThrow(try UHRPURL(parsing: testURL, limits: exactLimits))
        XCTAssertThrowsError(try UHRPURL(parsing: testURL + "1", limits: exactLimits)) { error in
            XCTAssertEqual(
                error as? UHRPError,
                .limitExceeded(
                    name: "URL", actual: testURL.utf8.count + 1,
                    maximum: testURL.utf8.count))
        }
    }

    func testLimitsAndValuesAreSendable() throws {
        XCTAssertThrowsError(
            try UHRPLimits(
                maximumURLUTF8ByteCount: 0,
                maximumContentByteCount: 1,
                maximumMIMETypeUTF8ByteCount: 1))
        assertSendable(UHRPLimits.self)
        assertSendable(UHRPURL.self)
    }

    func testFileByteLimitIsExact() throws {
        let limits = try UHRPLimits(
            maximumURLUTF8ByteCount: 64,
            maximumContentByteCount: 3,
            maximumMIMETypeUTF8ByteCount: 16)
        XCTAssertNoThrow(try UHRPURL(fileBytes: [1, 2, 3], limits: limits))
        XCTAssertThrowsError(try UHRPURL(fileBytes: [1, 2, 3, 4], limits: limits)) { error in
            XCTAssertEqual(
                error as? UHRPError,
                .limitExceeded(name: "content", actual: 4, maximum: 3))
        }
    }

    func testIdentifierReflectionIsEmptyAndDoesNotExposeStorage() throws {
        let identifier = try UHRPURL(parsing: testURL)

        XCTAssertEqual(identifier.description, testURL)
        XCTAssertEqual(identifier.debugDescription, testURL)
        XCTAssertTrue(identifier.customMirror.children.isEmpty)
    }
}

private func assertSendable<T: Sendable>(_ type: T.Type) {}
