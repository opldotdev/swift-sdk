import BSVAuth
import Testing

@Suite("BRC-104 payload codec")
struct BRC104PayloadTests {
    @Test("request and response round-trip with canonical headers")
    func roundTrip() throws {
        let id = [UInt8](repeating: 7, count: 32)
        let request = try BRC104Request(
            requestID: id, method: "POST", path: "/v1/items", query: "?a=b",
            headers: [
                .init(name: "X-BSV-Trace", value: "1"),
                .init(name: "Content-Type", value: "application/json; charset=utf-8"),
            ],
            body: Array("{}".utf8)
        )
        let bytes = try BRC104Codec.encode(request)
        let decoded = try BRC104Codec.decodeRequest(bytes)
        let expected = try BRC104Request(
            requestID: id, method: "POST", path: "/v1/items", query: "?a=b",
            headers: [
                .init(name: "content-type", value: "application/json"),
                .init(name: "x-bsv-trace", value: "1"),
            ], body: Array("{}".utf8))
        #expect(decoded == expected)
        let response = try BRC104Response(
            requestID: id, status: 201, headers: [.init(name: "x-bsv-result", value: "ok")])
        #expect(try BRC104Codec.decodeResponse(BRC104Codec.encode(response)) == response)
    }

    @Test("rejects excluded and noncanonical header forms")
    func rejectsHeaders() {
        #expect(throws: BRC104Error.self) {
            try BRC104Request(
                requestID: [UInt8](repeating: 0, count: 32), method: "GET", path: "/",
                headers: [.init(name: "x-bsv-auth-signature", value: "x")])
        }
        #expect(throws: BRC104Error.self) {
            try BRC104Request(
                requestID: [UInt8](repeating: 0, count: 32), method: "GET", path: "/",
                headers: [.init(name: "x-bsv-a", value: "x"), .init(name: "X-BSV-A", value: "y")])
        }
        #expect(throws: BRC104Error.invalidHeader) {
            try BRC104Request(
                requestID: [UInt8](repeating: 0, count: 32), method: "POST", path: "/",
                headers: [.init(name: "content-type", value: "; charset=utf-8")])
        }
    }

    @Test("checks complete payload limits and path components")
    func payloadAndPathLimits() throws {
        let requestID = [UInt8](repeating: 4, count: 32)
        let request = try BRC104Request(requestID: requestID, method: "GET", path: "/items")
        let encoded = try BRC104Codec.encode(request)
        let exact = try BRC104Limits(maximumPayloadBytes: encoded.count)
        #expect(try BRC104Codec.decodeRequest(encoded, limits: exact) == request)

        let tooSmall = try BRC104Limits(maximumPayloadBytes: encoded.count - 1)
        #expect(throws: BRC104Error.resourceLimit) {
            try BRC104Codec.encode(request, limits: tooSmall)
        }
        #expect(throws: BRC104Error.resourceLimit) {
            try BRC104Codec.decodeRequest(encoded, limits: tooSmall)
        }

        for path in ["/items?x=1", "/items#part"] {
            #expect(throws: BRC104Error.invalidPath) {
                try BRC104Request(requestID: requestID, method: "GET", path: path)
            }
        }
        #expect(throws: BRC104Error.invalidPath) {
            try BRC104Request(
                requestID: requestID, method: "GET", path: "/items", query: "?x=1#part")
        }

        let extendedHeaderLimits = try BRC104Limits(
            maximumHeaderNameBytes: 300,
            maximumHeaderBytes: 1_000
        )
        let extendedName = "x-bsv-" + String(repeating: "a", count: 251)
        let extendedRequest = try BRC104Request(
            requestID: requestID,
            method: "GET",
            path: "/items",
            headers: [.init(name: extendedName, value: "1")],
            limits: extendedHeaderLimits
        )
        #expect(
            try BRC104Codec.decodeRequest(
                BRC104Codec.encode(extendedRequest, limits: extendedHeaderLimits),
                limits: extendedHeaderLimits
            ) == extendedRequest
        )
    }

    @Test("refuses statuses, methods and request targets that @bsv/sdk rejects")
    func typeScriptRequestLimits() throws {
        let requestID = [UInt8](repeating: 4, count: 32)
        // `AuthFetch.ts:587-589` rejects an authenticated status outside 200...599.
        for status in [100, 101, 199, 600] {
            #expect(throws: BRC104Error.invalidStatus) {
                try BRC104Response(requestID: requestID, status: status)
            }
        }
        for status in [200, 204, 599] {
            #expect(try BRC104Response(requestID: requestID, status: status).status == status)
        }
        var informational = try BRC104Codec.encode(
            try BRC104Response(requestID: requestID, status: 200))
        #expect(informational[32] == 200)
        informational[32] = 199
        #expect(throws: BRC104Error.invalidStatus) {
            try BRC104Codec.decodeResponse(informational)
        }

        // The middleware accepts 1 to 32 uppercase token characters
        // (`auth-express-middleware/src/index.ts:2002`).
        for method in ["get", "Post", "M1", "", "GET ", String(repeating: "A", count: 33)] {
            #expect(throws: BRC104Error.invalidMethod) {
                try BRC104Request(requestID: requestID, method: method, path: "/")
            }
        }
        for method in ["GET", "PROPFIND", "M-SEARCH", "!#$%&'*+.^_`|~-", String(repeating: "A", count: 32)] {
            #expect(try BRC104Request(requestID: requestID, method: method, path: "/").method == method)
        }

        // `originalUrl`, the path and query, is limited to 8192 characters
        // (`auth-express-middleware/src/index.ts:2024`).
        let path = "/" + String(repeating: "p", count: 4_095)
        let exactQuery = "?" + String(repeating: "q", count: 4_095)
        #expect(
            try BRC104Request(requestID: requestID, method: "GET", path: path, query: exactQuery)
                .query == exactQuery)
        #expect(throws: BRC104Error.invalidPath) {
            try BRC104Request(
                requestID: requestID, method: "GET", path: path, query: exactQuery + "q")
        }
        #expect(throws: BRC104Error.invalidPath) {
            try BRC104Request(
                requestID: requestID, method: "GET", path: path + String(repeating: "p", count: 4_097))
        }
    }

    @Test("response correlation is exact")
    func responseCorrelation() throws {
        let requestID = [UInt8](repeating: 1, count: 32)
        let response = try BRC104Response(requestID: requestID, status: 200)
        try BRC104Codec.requireCorrelation(requestID: requestID, response: response)
        #expect(throws: BRC104Error.self) {
            try BRC104Codec.requireCorrelation(
                requestID: [UInt8](repeating: 2, count: 32), response: response)
        }
    }
}
