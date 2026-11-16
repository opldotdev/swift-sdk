import BSVCore
import BSVStorage
import Foundation
import Testing

@testable import BSVNetwork

/// What a wallet shows for a network failure, and what the log line carries.
@Suite("Network error descriptions")
struct NetworkErrorDescriptionTests {
    @Test("an HTTP status names the status and the provider's short reason")
    func httpStatusSentence() {
        #expect(
            NetworkServiceError.httpStatus(code: 400, message: "unexpected response code 500: Missing inputs")
                .localizedDescription
                == "The network service refused the request (HTTP 400): unexpected response code 500: Missing inputs."
        )
        #expect(
            NetworkServiceError.httpStatus(code: 503, message: "<html><body>down</body></html>")
                .localizedDescription
                == "The network service could not answer (HTTP 503). Try again in a minute."
        )
        #expect(
            NetworkServiceError.httpStatus(code: 429, message: nil).localizedDescription
                == "The network service could not answer (HTTP 429). Try again in a minute."
        )
        #expect(
            NetworkServiceError.timedOut.localizedDescription
                == "The network service did not answer in time. Check your connection and try again."
        )
    }

    @Test("a provider reason is read from JSON and kept to one short line")
    func providerReason() {
        #expect(oneLineProviderReason(#"{"code":1,"message":"fee too low"}"#) == "fee too low")
        #expect(oneLineProviderReason(#"{"code":1}"#) == nil)
        #expect(oneLineProviderReason("first line\nsecond line") == "first line")
        let reason = oneLineProviderReason(String(repeating: "x", count: 300))
        #expect(reason?.count == 120)
        #expect(reason?.hasSuffix("…") == true)
    }

    @Test("ARC errors say what ARC answered and what to do")
    func arcSentences() throws {
        let transactionID = try TransactionID(displayHex: String(repeating: "ab", count: 32))
        let body = Data("""
        {"status":461,"title":"Malformed transaction","txStatus":"REJECTED",
         "extraInfo":"arc error 461: script verification failed","detail":"Transaction is malformed",
         "txid":"\(transactionID.displayHex)"}
        """.utf8)
        let response = try ARCResponse(body: body, redacting: [])
        #expect(
            ARCError.rejected(httpStatusCode: 461, response: response).localizedDescription
                == "ARC rejected the transaction: REJECTED arc error 461: script verification failed."
        )
        #expect(
            ARCError.uncertainDelivery(transactionID: transactionID, cause: .timedOut).localizedDescription
                == "The transaction may have reached ARC, but ARC did not answer in time. "
                + "Check its status before sending it again."
        )
    }

    @Test("the log line has the call, host, path, status and redacted body, and no query")
    func logLine() throws {
        let request = HTTPRequest(
            method: .get,
            url: try #require(URL(string: "https://headers.example/api/v1/chain/tip?token=secret-token")),
            headers: ["Authorization": "Bearer secret-token"]
        )
        let line = NetworkLog.line(
            "BlockHeadersServiceClient",
            request: request,
            statusCode: 401,
            body: Data(#"{"error":"bad key secret-token"}"#.utf8),
            redacting: ["secret-token"]
        )
        #expect(line.contains("BlockHeadersServiceClient: GET headers.example/api/v1/chain/tip -> HTTP 401"))
        #expect(line.contains("bad key [redacted]"))
        #expect(!line.contains("secret-token"))
        #expect(!line.contains("token="))
        #expect(!line.contains("Bearer"))
    }

    @Test("UHRP download errors are one plain sentence; the log form lists every reason")
    func uhrpDownloadSentences() throws {
        let rejected = [
            UHRPAdvertisementRejection(answerIndex: 0, reason: .hashMismatch),
            UHRPAdvertisementRejection(answerIndex: 1, reason: .invalidAdvertisement(.invalidSignature)),
        ]
        let none = UHRPDownloadError.noAvailableHosts(rejected: rejected)
        #expect(
            none.localizedDescription
                == "No host is offering this file right now. 2 offers were found, but none could be used."
        )
        #expect(String(reflecting: none).contains("output 1: UHRP advertisement signature is invalid"))
        #expect(UHRPDownloadError.noAvailableHosts(rejected: []).localizedDescription == "No host is offering this file.")

        let failed = UHRPDownloadError.allHostsFailed([
            UHRPHostFailure(host: URL(string: "https://a.example/f")!, reason: .httpStatus(503)),
            UHRPHostFailure(host: URL(string: "https://b.example/f")!, reason: .contentHashMismatch),
        ])
        #expect(
            failed.localizedDescription
                == "The file could not be downloaded from any of its 2 hosts. Try again later."
        )
        #expect(String(reflecting: failed).contains("- https://a.example/f: HTTP status 503"))
    }
}
