import BSVOverlay
import Foundation
import Testing

@Suite("Overlay error descriptions")
struct OverlayErrorDescriptionTests {
    @Test("overlay errors have plain sentences and keep detail for logs")
    func plainSentences() {
        #expect(
            OverlayAdminTokenError.unlinkedLockingKey.localizedDescription
                == "The overlay advertisement was not made by the identity it names."
        )
        #expect(
            OverlayPolicyError.invalidSteak.localizedDescription
                == "An overlay host sent an answer that does not match the transaction it was sent."
        )
        #expect(
            OverlayPolicyError.invalidLookupOutput.localizedDescription
                == "The overlay hosts answered, but none of their results could be read."
        )
        #expect(
            OverlayPolicyError.uncertainDelivery.localizedDescription.hasPrefix(
                "The transaction may have reached an overlay host")
        )
        #expect(
            OverlayError.duplicateValue(name: "hosts").localizedDescription
                == "The same overlay address is listed twice."
        )
        let limit = OverlayError.limitExceeded(name: "resolvedHosts", actual: 65, maximum: 64)
        #expect(limit.localizedDescription == "The overlay request is larger than the wallet accepts.")
        #expect(String(reflecting: limit).contains("resolvedHosts"))
        #expect(String(reflecting: limit).contains("65"))
    }
}
