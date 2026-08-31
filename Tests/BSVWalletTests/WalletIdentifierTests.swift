import XCTest
import BSVCore
import BSVKeys
@testable import BSVWallet

func walletTestPrivateKey(_ scalar: UInt8) throws -> PrivateKey {
    try PrivateKey([UInt8](repeating: 0, count: 31) + [scalar])
}

func walletTestProtocol(_ name: String = "testprotocol") throws -> WalletProtocolID {
    try WalletProtocolID(securityLevel: .silent, name: name)
}

func walletTestKeyID(_ value: String = "12345") throws -> WalletKeyID {
    try WalletKeyID(value)
}

func walletTestHex(_ text: String, maximum: Int = 4_096) throws -> [UInt8] {
    try Hex.decode(text, maximumDecodedByteCount: maximum)
}

final class WalletIdentifierTests: XCTestCase {
    func testSecurityLevelsAndProtocolArrayJSON() throws {
        for level in WalletSecurityLevel.allCases {
            let value = try WalletProtocolID(securityLevel: level, name: "Test Name")
            let bytes = try WalletJSON.encode(value)
            XCTAssertEqual(String(decoding: bytes, as: UTF8.self), "[\(level.rawValue),\"test name\"]")
            XCTAssertEqual(try WalletJSON.decode(WalletProtocolID.self, from: bytes), value)
        }
        for json in ["[-1,\"valid name\"]", "[3,\"valid name\"]", "[1.5,\"valid name\"]", "[true,\"valid name\"]", "[null,\"valid name\"]", "[\"1\",\"valid name\"]", "[]", "[0]", "[0,\"valid name\",1]"] {
            XCTAssertThrowsError(try WalletJSON.decode(WalletProtocolID.self, from: Array(json.utf8)))
        }
    }

    func testProtocolNormalizationBoundsAndReservedNames() throws {
        XCTAssertEqual(try WalletProtocolID(securityLevel: .silent, name: " \tA Valid NAME\n").name, "a valid name")
        XCTAssertThrowsError(try walletTestProtocol(String(repeating: "a", count: 4)))
        XCTAssertEqual(try walletTestProtocol(String(repeating: "a", count: 5)).name.utf8.count, 5)
        XCTAssertEqual(try walletTestProtocol(String(repeating: "a", count: 400)).name.utf8.count, 400)
        XCTAssertThrowsError(try walletTestProtocol(String(repeating: "a", count: 401)))

        for allowed in ["abcde", "12345", "ab 12"].filter({ !$0.contains("  ") }) {
            XCTAssertNoThrow(try walletTestProtocol(allowed))
        }
        for invalid in ["ab_cd", "abcd-", "abc.d", "abc/d", "abc\tb", "abcd!", "éabcd"] {
            XCTAssertThrowsError(try walletTestProtocol(invalid))
        }
        for adjacent in ["aa  b", "a  bcd", "abc  d"] {
            XCTAssertThrowsError(try walletTestProtocol(adjacent))
        }
        for suffix in ["test protocol", "TEST PROTOCOL", " Test Protocol "] {
            XCTAssertThrowsError(try walletTestProtocol(suffix))
        }
        XCTAssertNoThrow(try walletTestProtocol("test protocols"))
        for reserved in ["admin", "administrator", "admin foo", "AdMiN foo", " admin foo "] {
            XCTAssertThrowsError(try walletTestProtocol(reserved))
        }
        XCTAssertThrowsError(try walletTestProtocol("admi")) // short, not reserved
        XCTAssertNoThrow(try walletTestProtocol("admi1"))
    }

    func testWalletInternalAdminProtocolsStayOffExternalBoundaries() throws {
        let factoryValue = try WalletProtocolID.walletInternalAdmin(
            securityLevel: .everyAppAndCounterparty,
            name: " \tAdMiN Metadata Encryption\n"
        )
        let value = WalletProtocolID.walletMetadataEncryption
        XCTAssertEqual(value.securityLevel, .everyAppAndCounterparty)
        XCTAssertEqual(value.name, "admin metadata encryption")
        XCTAssertEqual(value, factoryValue)

        XCTAssertThrowsError(try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: value.name
        )) { error in
            XCTAssertEqual(error as? WalletValidationError, .reservedAdminProtocol)
        }
        XCTAssertThrowsError(try WalletJSON.decode(
            WalletProtocolID.self,
            from: Array("[2,\"admin metadata encryption\"]".utf8)
        ))
        XCTAssertThrowsError(try WalletJSON.encode(value))

        for invalid in [
            "metadata encryption",
            "admi1 metadata encryption",
            "admin_metadata encryption",
            "admin  metadata encryption",
            "admin metadata encryption protocol",
        ] {
            XCTAssertThrowsError(try WalletProtocolID.walletInternalAdmin(
                securityLevel: .everyAppAndCounterparty,
                name: invalid
            ), "expected internal factory to reject \(invalid)")
        }

        let wireRequest = WalletWireKeyQueryRequest.encrypt(WalletEncryptRequest(
            protocolID: value,
            keyID: try WalletKeyID("1"),
            plaintext: [1]
        ))
        XCTAssertThrowsError(try WalletWireCodec.encodeKeyQueryRequest(
            wireRequest,
            originator: "wallet.example"
        )) { error in
            XCTAssertEqual(
                error as? WalletWireError,
                .nonRoundTrippableValue(kind: "BRC-44 wallet-internal protocol identifier")
            )
        }
    }

    func testSpecificLinkageRevelationHasTheOnlyExtendedProtocolLimit() throws {
        let prefix = "specific linkage revelation "
        let exact = prefix + "2 " + String(repeating: "a", count: 400)
        XCTAssertEqual(exact.utf8.count, 430)
        XCTAssertEqual(
            try WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: exact).name,
            exact
        )

        let tooLong = prefix + "2 " + String(repeating: "a", count: 401)
        XCTAssertEqual(tooLong.utf8.count, 431)
        XCTAssertThrowsError(try walletTestProtocol(tooLong)) { error in
            XCTAssertEqual(
                error as? WalletValidationError,
                .protocolNameTooLong(actualUTF8ByteCount: 431, maximum: 430)
            )
        }

        for malformed in [
            prefix + "3 " + String(repeating: "a", count: 371),
            prefix + "x " + String(repeating: "a", count: 371),
            "specific linkage revelation2 " + String(repeating: "a", count: 372),
        ] {
            XCTAssertEqual(malformed.utf8.count, 401)
            XCTAssertThrowsError(try walletTestProtocol(malformed)) { error in
                XCTAssertEqual(
                    error as? WalletValidationError,
                    .protocolNameTooLong(actualUTF8ByteCount: 401, maximum: 400)
                )
            }
        }
    }

    func testEveryASCIIProtocolCharacterAndSuffixCaseVariant() throws {
        let allowed = Set(Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ".utf8))
        for byte in UInt8.min...127 {
            let candidate = String(decoding: Array("abcde".utf8) + [byte] + Array("z".utf8), as: UTF8.self)
            if allowed.contains(byte) {
                XCTAssertNoThrow(try walletTestProtocol(candidate), "expected ASCII byte \(byte) to be accepted")
            } else {
                XCTAssertThrowsError(try walletTestProtocol(candidate), "expected ASCII byte \(byte) to be rejected")
            }
        }

        let suffix = Array("protocol".utf8)
        for mask in 0..<(1 << suffix.count) {
            let variant = suffix.enumerated().map { index, byte in
                mask & (1 << index) == 0 ? byte : byte - 32
            }
            XCTAssertThrowsError(try walletTestProtocol("valid " + String(decoding: variant, as: UTF8.self)))
        }
    }

    func testProtocolInvalidCharacterReportsUTF8ByteOffset() {
        XCTAssertThrowsError(try walletTestProtocol("abcdeé")) { error in
            XCTAssertEqual(error as? WalletValidationError, .invalidProtocolCharacter(asciiByteOffset: 5))
        }
    }

    func testKeyIDPreservationAndUTF8Bounds() throws {
        XCTAssertThrowsError(try WalletKeyID(""))
        XCTAssertEqual(try WalletKeyID("A \0 é").value, "A \0 é")
        XCTAssertEqual(try WalletKeyID(String(repeating: "a", count: 800)).value.utf8.count, 800)
        XCTAssertThrowsError(try WalletKeyID(String(repeating: "a", count: 801)))
        XCTAssertEqual(try WalletKeyID(String(repeating: "é", count: 400)).value.utf8.count, 800)
        XCTAssertThrowsError(try WalletKeyID(String(repeating: "é", count: 401)))
        let composed = try WalletKeyID("é")
        let decomposed = try WalletKeyID("e\u{301}")
        XCTAssertNotEqual(composed, decomposed)
    }

    func testCryptoLimitsValidation() throws {
        XCTAssertEqual(WalletCryptoLimits.standard.maximumCiphertextByteCount, 1_048_624)
        XCTAssertEqual(try WalletCryptoLimits(maximumPayloadByteCount: 0).maximumCiphertextByteCount, 48)
        XCTAssertThrowsError(try WalletCryptoLimits(maximumPayloadByteCount: -1))
        XCTAssertThrowsError(try WalletCryptoLimits(maximumJSONByteCount: -1))
        XCTAssertThrowsError(try WalletCryptoLimits(maximumPayloadByteCount: Int.max))
    }

    func testCounterpartyStrictJSON() throws {
        let key = try walletTestPrivateKey(42).publicKey
        let values: [WalletCounterparty] = [.self, .anyone, .publicKey(key)]
        for value in values {
            let encoded = try WalletJSON.encode(value)
            XCTAssertEqual(try WalletJSON.decode(WalletCounterparty.self, from: encoded), value)
        }
        let uncompressed = Hex.encode(key.uncompressedBytes)
        for json in ["\"\"", "\"other\"", "null", "true", "123", "\"\(uncompressed)\"", "\"02\""] {
            XCTAssertThrowsError(try WalletJSON.decode(WalletCounterparty.self, from: Array(json.utf8)))
        }
    }
}
