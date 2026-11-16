import BSVAuth
import Foundation
import Testing

/// What an app shows when authentication fails. The sentences hold whether
/// the app is the client or the server.
@Suite("BRC-103/104 error descriptions")
struct BRC104ErrorDescriptionTests {
    @Test("payload errors say what is wrong with the request or response")
    func payloadSentences() {
        #expect(
            BRC104Error.invalidStatus.localizedDescription
                == "The response status is not one that authenticated HTTP allows.")
        #expect(
            BRC104Error.invalidMethod.localizedDescription
                == "The request method is not one that authenticated HTTP allows.")
        #expect(
            BRC104Error.invalidPath.localizedDescription
                == "The request address is not valid or is too long.")
        #expect(String(reflecting: BRC104Error.invalidPath).hasSuffix("invalidPath"))
    }

    @Test("framing errors say what is wrong with the headers")
    func framingSentences() {
        #expect(
            BRC104HTTPFramingError.invalidAuthenticationHeader.localizedDescription
                == "The authentication headers are not valid.")
        #expect(
            BRC104HTTPFramingError.missingAuthenticationHeader.localizedDescription
                == "The request or response is missing authentication headers.")
        #expect(
            BRC104HTTPFramingError.resourceLimit.localizedDescription
                == "The request or response is too large.")
        #expect(
            BRC104HTTPFramingError.invalidFrame.localizedDescription
                == "The request or response is not one that authenticated HTTP allows.")
    }

    @Test("authentication and certificate errors name no side")
    func roleNeutralSentences() {
        let all: [AuthError] = [
            .invalidMessage, .invalidNonce, .invalidSignature, .replay, .sessionNotFound,
            .unexpectedMessage, .peerMismatch, .notAuthenticated, .certificateExchangeUnavailable,
            .invalidCertificateRequest, .certificateValidationFailed, .resourceLimit,
            .handshakeTimedOut, .randomGenerationFailed,
        ]
        let framing: [BRC104HTTPFramingError] = [
            .invalidFrame, .invalidAuthenticationHeader, .duplicateAuthenticationHeader,
            .missingAuthenticationHeader, .unknownAuthenticationHeader,
            .certificateExchangeUnavailable, .requestIDMismatch, .resourceLimit,
        ]
        let text = all.map(\.localizedDescription) + framing.map(\.localizedDescription)
        for sentence in text {
            #expect(!sentence.lowercased().contains("server"), "\(sentence)")
            #expect(!sentence.lowercased().contains("storage"), "\(sentence)")
        }
        #expect(
            AuthError.certificateValidationFailed.localizedDescription
                == "The certificates do not match what was requested or could not be verified.")
        #expect(
            AuthError.notAuthenticated.localizedDescription
                == "The connection has not been authenticated yet.")
        #expect(
            CertificateFieldNameError.nonASCII.localizedDescription
                == "Certificate field names must use only plain ASCII letters, digits, spaces and symbols.")
    }
}
