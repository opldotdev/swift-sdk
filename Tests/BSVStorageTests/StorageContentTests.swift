import BSVStorage
import XCTest

final class StorageContentTests: XCTestCase {
    func testBoundedContentMatchesItsUHRPIdentifier() throws {
        let bytes = Array("hello UHRP".utf8)
        let identifier = try UHRPURL(fileBytes: bytes)
        let content = try StorageContent(bytes: bytes, mimeType: "text/plain")

        XCTAssertTrue(content.matches(identifier))
        XCTAssertFalse(
            try StorageContent(bytes: Array("different".utf8), mimeType: "text/plain")
                .matches(identifier))
    }

    func testContentLimitsAndMIMEValidationAreStrict() throws {
        let limits = try UHRPLimits(
            maximumURLUTF8ByteCount: 64,
            maximumContentByteCount: 3,
            maximumMIMETypeUTF8ByteCount: 10)
        XCTAssertNoThrow(
            try StorageContent(bytes: [1, 2, 3], mimeType: "text/plain", limits: limits))
        XCTAssertNoThrow(try StorageContent(bytes: [], mimeType: "", limits: limits))
        XCTAssertThrowsError(
            try StorageContent(bytes: [1, 2, 3, 4], mimeType: "text/plain", limits: limits))
        XCTAssertThrowsError(
            try StorageContent(bytes: [], mimeType: "text/plain; charset=utf-8", limits: limits))
        XCTAssertThrowsError(try StorageContent(bytes: [], mimeType: "text\nplain", limits: limits))
    }

    func testContentDiagnosticsAndReflectionAreRedacted() throws {
        let content = try StorageContent(bytes: Array("secret bytes".utf8), mimeType: "text/plain")

        XCTAssertEqual(content.description, "<redacted UHRP content>")
        XCTAssertEqual(content.debugDescription, "<redacted UHRP content>")
        XCTAssertTrue(content.customMirror.children.isEmpty)
        assertStorageSendable(StorageContent.self)
    }

    func testProviderBoundaryIsSendableAndTransportNeutral() async throws {
        let provider = FixtureProvider()
        let identifier = try UHRPURL(fileBytes: Array("fixture".utf8))

        let content = try await provider.content(for: identifier)
        XCTAssertTrue(content.matches(identifier))
        assertStorageSendable(FixtureProvider.self)
    }
}

private func assertStorageSendable<T: Sendable>(_ type: T.Type) {}

private actor FixtureProvider: UHRPContentProvider {
    func content(for identifier: UHRPURL) async throws -> StorageContent {
        try StorageContent(bytes: Array("fixture".utf8), mimeType: "text/plain")
    }
}
