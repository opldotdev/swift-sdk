import BSVAuth
import Foundation
import Testing

/// What an app shows when an authenticated HTTP message is refused.
@Suite("BRC-104 error descriptions")
struct BRC104ErrorDescriptionTests {
    @Test("payload errors say what is wrong with the request or response")
    func payloadSentences() {
        #expect(
            BRC104Error.invalidStatus.localizedDescription
                == "The response status is not one an authenticated server may send.")
        #expect(
            BRC104Error.invalidMethod.localizedDescription
                == "The request method is not one the server accepts.")
        #expect(
            BRC104Error.invalidPath.localizedDescription
                == "The request address is not valid or is too long.")
        #expect(String(reflecting: BRC104Error.invalidPath).hasSuffix("invalidPath"))
    }

    @Test("framing errors say what is wrong with the headers")
    func framingSentences() {
        #expect(
            BRC104HTTPFramingError.invalidAuthenticationHeader.localizedDescription
                == "The server's authentication headers are not valid.")
        #expect(
            BRC104HTTPFramingError.resourceLimit.localizedDescription
                == "The request or response is larger than the app can handle.")
        #expect(
            BRC104HTTPFramingError.invalidFrame.localizedDescription
                == "The request or response is not one an authenticated server accepts.")
    }
}
