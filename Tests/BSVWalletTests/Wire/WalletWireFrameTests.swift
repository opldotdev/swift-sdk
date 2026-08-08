import XCTest
@testable import BSVWallet

final class WalletWireFrameTests: XCTestCase {
    func testRawRequestRoundTripsEveryDefinedCall() throws {
        for call in WalletCall.allCases {
            let frame = WalletWireRequestFrame(
                call: call,
                originator: "app-\(call.rawValue)",
                parameters: [call.rawValue, 0xAA]
            )
            let encoded = try WalletWireCodec.encodeRequestFrame(frame)
            XCTAssertEqual(try WalletWireCodec.decodeRequestFrame(encoded), frame)
        }
    }

    func testRequestGrammarUsesUTF8ByteCountAndHardOriginatorMaximum() throws {
        let multibyte = WalletWireRequestFrame(
            call: .getHeight,
            originator: "é世",
            parameters: []
        )
        XCTAssertEqual(try WalletWireCodec.encodeRequestFrame(multibyte)[1], 5)
        XCTAssertEqual(
            try WalletWireCodec.decodeRequestFrame(WalletWireCodec.encodeRequestFrame(multibyte)),
            multibyte
        )

        let exact = WalletWireRequestFrame(
            call: .getHeight,
            originator: String(repeating: "a", count: 255),
            parameters: []
        )
        XCTAssertEqual(try WalletWireCodec.encodeRequestFrame(exact).count, 257)
        XCTAssertThrowsError(try WalletWireCodec.encodeRequestFrame(WalletWireRequestFrame(
            call: .getHeight,
            originator: String(repeating: "a", count: 256),
            parameters: []
        )))
    }

    func testRequestRejectsEveryTruncationInvalidCallAndInvalidUTF8() throws {
        XCTAssertEqual(
            try error(encoding: []),
            .truncated
        )
        XCTAssertEqual(try error(encoding: [25]), .truncated)
        XCTAssertEqual(try error(encoding: [25, 2, 0x61]), .truncated)
        XCTAssertEqual(try error(encoding: [25, 1, 0xFF]), .invalidUTF8(kind: "originator"))
        for call in [UInt8(0), 29, 128, 255] {
            XCTAssertEqual(try error(encoding: [call, 0]), .invalidCall(call))
        }
    }

    func testResultSuccessAndFailureFramesAreExact() throws {
        let success = WalletWireResultFrame.success([1, 2, 3])
        XCTAssertEqual(try WalletWireCodec.encodeResultFrame(success), [0, 1, 2, 3])
        XCTAssertEqual(try WalletWireCodec.decodeResultFrame([0, 1, 2, 3]), success)

        let remote = try WalletWireRemoteError(code: 7, message: "bad", stack: "one")
        let failure = WalletWireResultFrame.failure(remote)
        XCTAssertEqual(
            try WalletWireCodec.encodeResultFrame(failure),
            [7, 3, 0x62, 0x61, 0x64, 3, 0x6F, 0x6E, 0x65]
        )
        XCTAssertEqual(
            try WalletWireCodec.decodeResultFrame(WalletWireCodec.encodeResultFrame(failure)),
            failure
        )
        XCTAssertThrowsError(try WalletWireCodec.decodeResultFrame([7, 0, 0, 0])) { error in
            XCTAssertEqual(error as? WalletWireError, .trailingBytes)
        }
    }

    func testCanonicalCompactSizeBoundariesThroughHeight() throws {
        let vectors: [(UInt32, [UInt8])] = [
            (0, [0]), (252, [252]), (253, [0xFD, 0xFD, 0]),
            (65_535, [0xFD, 0xFF, 0xFF]),
            (65_536, [0xFE, 0, 0, 1, 0]),
            (.max, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF]),
        ]
        for (height, payload) in vectors {
            let encoded = try WalletWireCodec.encodeKeyQueryResult(
                .getHeight(WalletGetHeightResult(height: height))
            )
            XCTAssertEqual(encoded, [0] + payload)
            guard case .getHeight(let decoded) = try WalletWireCodec.decodeKeyQueryResult(
                encoded,
                expectedCall: .getHeight
            ) else { return XCTFail("wrong result case") }
            XCTAssertEqual(decoded.height, height)
        }
        for payload in [
            [UInt8](arrayLiteral: 0, 0xFD, 0, 0),
            [0, 0xFE, 0xFF, 0, 0, 0],
            [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0],
        ] {
            XCTAssertThrowsError(try WalletWireCodec.decodeKeyQueryResult(
                payload,
                expectedCall: .getHeight
            )) { error in
                XCTAssertEqual(error as? WalletWireError, .noncanonicalCompactSize)
            }
        }
    }

    func testExactFramePayloadTextAndErrorLimits() throws {
        let limits = try WalletWireLimits(
            maximumFrameByteCount: 8,
            maximumOriginatorUTF8ByteCount: 2,
            maximumPayloadByteCount: 4,
            maximumTextUTF8ByteCount: 4,
            maximumRemoteMessageUTF8ByteCount: 2,
            maximumRemoteStackUTF8ByteCount: 2
        )
        XCTAssertNoThrow(try WalletWireCodec.encodeRequestFrame(
            WalletWireRequestFrame(call: .getHeight, originator: "aa", parameters: [1, 2, 3, 4]),
            limits: limits
        ))
        XCTAssertThrowsError(try WalletWireCodec.encodeRequestFrame(
            WalletWireRequestFrame(call: .getHeight, originator: "aaa", parameters: []),
            limits: limits
        ))
        XCTAssertThrowsError(try WalletWireCodec.encodeResultFrame(.success([0, 1, 2, 3, 4]), limits: limits))
        XCTAssertNoThrow(try WalletWireRemoteError(code: 1, message: "aa", stack: "bb", limits: limits))
        XCTAssertThrowsError(try WalletWireRemoteError(code: 1, message: "aaa", stack: "", limits: limits))
    }

    func testResultEncodingPreflightsExactTotalFrameSize() throws {
        let successExact = try WalletWireLimits(
            maximumFrameByteCount: 5,
            maximumPayloadByteCount: 4,
            maximumTextUTF8ByteCount: 5,
            maximumRemoteMessageUTF8ByteCount: 5,
            maximumRemoteStackUTF8ByteCount: 5
        )
        XCTAssertEqual(
            try WalletWireCodec.encodeResultFrame(.success([1, 2, 3, 4]), limits: successExact),
            [0, 1, 2, 3, 4]
        )

        let successTooSmall = try WalletWireLimits(
            maximumFrameByteCount: 4,
            maximumPayloadByteCount: 4,
            maximumTextUTF8ByteCount: 4,
            maximumRemoteMessageUTF8ByteCount: 4,
            maximumRemoteStackUTF8ByteCount: 4
        )
        XCTAssertThrowsError(
            try WalletWireCodec.encodeResultFrame(.success([1, 2, 3, 4]), limits: successTooSmall)
        ) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .byteLimitExceeded(kind: "result frame", actual: 5, maximum: 4)
            )
        }

        let failure = WalletWireResultFrame.failure(try WalletWireRemoteError(
            code: 1,
            message: "aa",
            stack: "bb"
        ))
        let failureExact = try WalletWireLimits(
            maximumFrameByteCount: 7,
            maximumPayloadByteCount: 7,
            maximumTextUTF8ByteCount: 7,
            maximumRemoteMessageUTF8ByteCount: 2,
            maximumRemoteStackUTF8ByteCount: 2
        )
        XCTAssertEqual(
            try WalletWireCodec.encodeResultFrame(failure, limits: failureExact).count,
            7
        )
        let failureTooSmall = try WalletWireLimits(
            maximumFrameByteCount: 6,
            maximumPayloadByteCount: 6,
            maximumTextUTF8ByteCount: 6,
            maximumRemoteMessageUTF8ByteCount: 2,
            maximumRemoteStackUTF8ByteCount: 2
        )
        XCTAssertThrowsError(try WalletWireCodec.encodeResultFrame(failure, limits: failureTooSmall)) {
            error in
            XCTAssertEqual(
                error as? WalletWireError,
                .byteLimitExceeded(kind: "result frame", actual: 7, maximum: 6)
            )
        }

        let compactBoundaryFailure = WalletWireResultFrame.failure(try WalletWireRemoteError(
            code: 2,
            message: String(repeating: "a", count: 253),
            stack: ""
        ))
        let compactBoundaryExact = try WalletWireLimits(
            maximumFrameByteCount: 258,
            maximumPayloadByteCount: 258,
            maximumTextUTF8ByteCount: 258,
            maximumRemoteMessageUTF8ByteCount: 253,
            maximumRemoteStackUTF8ByteCount: 0
        )
        XCTAssertEqual(
            try WalletWireCodec.encodeResultFrame(
                compactBoundaryFailure,
                limits: compactBoundaryExact
            ).count,
            258
        )
    }

    func testCheckedFrameArithmeticAndLimitRelationshipsRejectBeforeAllocation() throws {
        XCTAssertThrowsError(
            try walletWireCheckedByteCount(
                Int.max,
                1,
                maximum: Int.max,
                kind: "result frame"
            )
        ) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .byteLimitExceeded(kind: "result frame", actual: Int.max, maximum: Int.max)
            )
        }
        XCTAssertThrowsError(try WalletWireLimits(
            maximumFrameByteCount: 3,
            maximumPayloadByteCount: 4
        ))
        XCTAssertThrowsError(try WalletWireLimits(
            maximumFrameByteCount: 3,
            maximumPayloadByteCount: 3,
            maximumRemoteMessageUTF8ByteCount: 4
        ))
    }

    private func error(encoding bytes: [UInt8]) throws -> WalletWireError? {
        do {
            _ = try WalletWireCodec.decodeRequestFrame(bytes)
            return nil
        } catch {
            return error as? WalletWireError
        }
    }
}
