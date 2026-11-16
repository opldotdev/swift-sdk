import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVStorage
import Foundation
import XCTest

/// Vectors follow the TypeScript layout in
/// `packages/sdk/src/storage/UHRPAdvertisementValidation.ts` (`@bsv/sdk` 4.1.1):
/// six canonical lock-before PushDrop fields (line 40), host key at index 0
/// (line 46), hash at index 1 (line 54), HTTPS URL at index 2 (line 69),
/// expiry and size as CompactSize at 3 and 4 (lines 78-79), and a signature
/// over fields 0-4 by the key linked to the host under
/// `[2, "uhrp advertisement"]`, key ID "1", counterparty anyone (lines 89-98).
final class UHRPAdvertisementTests: XCTestCase {
    private let hostScalar: [UInt8] = Array(repeating: 0, count: 31) + [0x2a]
    private let hash = [UInt8](repeating: 0xab, count: 32)
    private let url = "https://cdn.example/abc"

    func testDecodesHandBuiltTypeScriptAdvertisement() throws {
        let host = try PrivateKey(hostScalar)
        let expiry = CompactSize.encode(1_700_000_000)
        let size = CompactSize.encode(1_024)
        let fields = [host.publicKey.compressedBytes, hash, Array(url.utf8), expiry, size]
        let lockingKey = try linkedPrivateKey(host)
        let signature = try lockingKey.sign(digest: BSVHashing.sha256(Array(fields.joined())))

        // <33 lock key> OP_CHECKSIG <33 host key> <32 hash> <url> <expiry> <size> <sig>
        // OP_2DROP OP_2DROP OP_2DROP
        var bytes: [UInt8] = [0x21] + lockingKey.publicKey.compressedBytes + [0xac]
        bytes += [0x21] + fields[0]
        bytes += [0x20] + fields[1]
        bytes += [UInt8(fields[2].count)] + fields[2]
        bytes += [0x05] + expiry
        bytes += [0x03] + size
        bytes += [UInt8(signature.derBytes.count)] + signature.derBytes
        bytes += [0x6d, 0x6d, 0x6d]
        let script = try Script(bytes: bytes, maximumByteCount: 10_000)

        let advertisement = try UHRPAdvertisement.decode(script)
        XCTAssertEqual(advertisement.hostIdentityKey, host.publicKey)
        XCTAssertEqual(advertisement.hash.bytes, hash)
        XCTAssertEqual(advertisement.hostedFileLocation.absoluteString, url)
        XCTAssertEqual(advertisement.expiryTime, 1_700_000_000)
        XCTAssertEqual(advertisement.fileSize, 1_024)
        XCTAssertEqual(advertisement.lockingPublicKey, lockingKey.publicKey)
        XCTAssertEqual(advertisement.signature, signature)
        XCTAssertEqual(
            try UHRPAdvertisement.linkedLockingKey(for: host.publicKey),
            lockingKey.publicKey
        )
    }

    func testSmallCompactSizeValuesUseMinimalOpcodes() throws {
        // TypeScript PushDrop writes a one-byte field 1...16 as OP_1...OP_16.
        let host = try PrivateKey(hostScalar)
        let script = try advertisementScript(host: host, expiry: [5], size: [16])
        let bytes = script.bytes
        XCTAssertTrue(bytes.contains(0x55))
        XCTAssertTrue(bytes.contains(0x60))
        let advertisement = try UHRPAdvertisement.decode(script)
        XCTAssertEqual(advertisement.expiryTime, 5)
        XCTAssertEqual(advertisement.fileSize, 16)
    }

    func testRejectsPreviousFourFieldSwiftShape() throws {
        // Swift used [hash, uhrp URL, host URL, expiry], unsigned. TypeScript
        // requires six fields, so this shape is refused.
        let host = try PrivateKey(hostScalar)
        let fields = [
            hash,
            Array("XUT6PqWb3GP3LR7dmBMCJwZ3oo5g1iGCF3CrpzyuJCemkGu1WGoq".utf8),
            Array(url.utf8),
            CompactSize.encode(1_700_000_000),
        ]
        let script = try PushDrop.lockingScript(
            fields: fields,
            publicKey: host.publicKey,
            lockPosition: .beforeCompatibility
        )
        XCTAssertThrowsError(try UHRPAdvertisement.decode(script)) { error in
            XCTAssertEqual(error as? UHRPAdvertisementError, .unexpectedFieldCount(actual: 4))
        }
    }

    func testRejectsLockingKeyNotLinkedToHost() throws {
        let host = try PrivateKey(hostScalar)
        let script = try advertisementScript(host: host, lockingKey: host)
        XCTAssertThrowsError(try UHRPAdvertisement.decode(script)) { error in
            XCTAssertEqual(error as? UHRPAdvertisementError, .lockingKeyNotLinkedToHost)
        }
    }

    func testRejectsSignatureOverOtherData() throws {
        let host = try PrivateKey(hostScalar)
        let script = try advertisementScript(host: host, signedSuffix: [0])
        XCTAssertThrowsError(try UHRPAdvertisement.decode(script)) { error in
            XCTAssertEqual(error as? UHRPAdvertisementError, .invalidSignature)
        }
    }

    func testRejectsFieldsTypeScriptRejects() throws {
        let host = try PrivateKey(hostScalar)
        let cases: [(UHRPAdvertisementError, () throws -> Script)] = [
            (.invalidURL, { try self.advertisementScript(host: host, url: "http://cdn.example/a") }),
            (.invalidURL, { try self.advertisementScript(host: host, url: "https://u:p@cdn.example/a") }),
            (.invalidURL, { try self.advertisementScript(host: host, url: "https://cdn.example/a#f") }),
            (.invalidURL, { try self.advertisementScript(host: host, url: "https://cdn.example/\u{85}") }),
            (.invalidExpiryTime, { try self.advertisementScript(host: host, expiry: [0xfd, 0x10, 0x00]) }),
            (.invalidExpiryTime, { try self.advertisementScript(host: host, expiry: CompactSize.encode(1 << 53)) }),
            (.invalidFileSize, { try self.advertisementScript(host: host, size: CompactSize.encode(9) + [0]) }),
            (.invalidHash, { try self.advertisementScript(host: host, hash: [1, 2, 3]) }),
            (.invalidHostIdentityKey, { try self.advertisementScript(host: host, hostKeyField: [UInt8](repeating: 4, count: 33)) }),
        ]
        for (expected, build) in cases {
            XCTAssertThrowsError(try UHRPAdvertisement.decode(try build())) { error in
                XCTAssertEqual(error as? UHRPAdvertisementError, expected)
            }
        }

        // A non-minimal push of a small value is not a canonical PushDrop.
        let valid = try advertisementScript(host: host, size: [9])
        var bytes = valid.bytes
        // lock (35) + host key (34) + hash (33) + URL push + expiry push (6)
        let index = 35 + 34 + 33 + 1 + url.utf8.count + 6
        XCTAssertEqual(bytes[index], 0x59)
        bytes.replaceSubrange(index...index, with: [0x01, 0x09])
        XCTAssertThrowsError(
            try UHRPAdvertisement.decode(Script(bytes: bytes, maximumByteCount: 10_000))
        ) { error in
            guard case .invalidPushDrop = error as? UHRPAdvertisementError else {
                return XCTFail("unexpected error \(error)")
            }
        }
    }

    func testAcceptsMaximumTypeScriptURLLength() throws {
        let host = try PrivateKey(hostScalar)
        let prefix = "https://cdn.example/"
        let longURL = prefix + String(repeating: "a", count: 2_048 - prefix.utf8.count)
        let advertisement = try UHRPAdvertisement.decode(
            try advertisementScript(host: host, url: longURL)
        )
        XCTAssertEqual(advertisement.hostedFileLocation.absoluteString, longURL)
        XCTAssertThrowsError(
            try UHRPAdvertisement.decode(try advertisementScript(host: host, url: longURL + "a"))
        )
    }

    private func linkedPrivateKey(_ host: PrivateKey) throws -> PrivateKey {
        let anyone = try PrivateKey(Array(repeating: 0, count: 31) + [1])
        return try host.derivedChild(
            with: anyone.publicKey,
            invoiceNumber: "2-uhrp advertisement-1"
        )
    }

    private func advertisementScript(
        host: PrivateKey,
        lockingKey: PrivateKey? = nil,
        hostKeyField: [UInt8]? = nil,
        hash: [UInt8]? = nil,
        url: String? = nil,
        expiry: [UInt8] = CompactSize.encode(1_700_000_000),
        size: [UInt8] = CompactSize.encode(1_024),
        signedSuffix: [UInt8] = []
    ) throws -> Script {
        let fields = [
            hostKeyField ?? host.publicKey.compressedBytes,
            hash ?? self.hash,
            Array((url ?? self.url).utf8),
            expiry,
            size,
        ]
        let signer = try lockingKey ?? linkedPrivateKey(host)
        let signature = try signer.sign(
            digest: BSVHashing.sha256(Array(fields.joined()) + signedSuffix)
        )
        return try PushDrop.lockingScript(
            fields: fields + [signature.derBytes],
            publicKey: signer.publicKey,
            lockPosition: .beforeCompatibility
        )
    }
}
