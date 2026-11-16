import BSVStorage
import Foundation
import XCTest

final class UHRPAdvertisementErrorDescriptionTests: XCTestCase {
    func testPlainSentencesKeepDetailForLogs() {
        XCTAssertEqual(
            UHRPAdvertisementError.unexpectedFieldCount(actual: 4).localizedDescription,
            "The file host's offer is not in the expected format.")
        XCTAssertEqual(
            UHRPAdvertisementError.lockingKeyNotLinkedToHost.localizedDescription,
            "The file host's offer was not made by the host it names.")
        XCTAssertEqual(
            UHRPAdvertisementError.invalidURL.localizedDescription,
            "The file host's offer does not give a safe HTTPS address.")
        XCTAssertEqual(
            String(reflecting: UHRPAdvertisementError.unexpectedFieldCount(actual: 4)),
            "UHRP advertisement must have 6 fields (found 4)")
    }
}
