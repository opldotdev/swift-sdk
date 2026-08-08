import Foundation
import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
import BSVTransaction
@testable import BSVWallet

final class BRC52CertificateBinaryTests: XCTestCase {
    func testExactIDsDisplayTxidCompactVoutAndRawUTF8FieldOrder() throws {
        let type = try CertificateTypeID(Array(0..<32).map(UInt8.init))
        let serial = try CertificateSerialNumber(Array(32..<64).map(UInt8.init))
        let subject = try key(7).publicKey
        let certifier = try key(9).publicKey
        let displayBytes = Array(64..<96).map(UInt8.init)
        let outpoint = Outpoint(
            transactionID: try TransactionID(displayHex: Hex.encode(displayBytes)),
            outputIndex: 253
        )
        let z = try CertificateFieldName("z")
        let nonASCII = try CertificateFieldName("\u{80}")
        let certificate = try Certificate(
            type: type,
            serialNumber: serial,
            subject: subject,
            certifier: certifier,
            revocationOutpoint: outpoint,
            fields: [
                nonASCII: try CertificateCiphertext([2]),
                z: try CertificateCiphertext([1]),
            ]
        )

        let binary = try certificate.binary(includingSignature: false)
        XCTAssertEqual(Array(binary[0..<32]), type.bytes)
        XCTAssertEqual(Array(binary[32..<64]), serial.bytes)
        XCTAssertEqual(Array(binary[64..<97]), subject.compressedBytes)
        XCTAssertEqual(Array(binary[97..<130]), certifier.compressedBytes)
        XCTAssertEqual(Array(binary[130..<162]), displayBytes)
        XCTAssertEqual(Array(binary[162..<165]), [0xfd, 0xfd, 0x00])
        XCTAssertEqual(binary[165], 2)
        XCTAssertEqual(binary[166], 1)
        XCTAssertEqual(binary[167], Character("z").asciiValue)
        XCTAssertEqual(try Certificate(binary: binary), certificate)
    }

    func testStrictCanonicalBase64JSONAndExactIdentifierWidths() throws {
        XCTAssertThrowsError(try CertificateTypeID([UInt8](repeating: 1, count: 31)))
        XCTAssertThrowsError(try CertificateSerialNumber([UInt8](repeating: 1, count: 33)))
        let canonical = Base64Encoding.encode([UInt8](repeating: 1, count: 32))
        XCTAssertEqual(try CertificateTypeID(base64: canonical).base64, canonical)
        XCTAssertThrowsError(try CertificateTypeID(base64: String(canonical.dropLast())))
        XCTAssertThrowsError(try CertificateTypeID(base64: canonical + "="))

        let certificate = try unsignedCertificate(vout: 1)
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(certificate)) as? [String: Any]
        )
        object["type"] = String(certificate.type.base64.dropLast())
        let malformed = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try Certificate(json: malformed))

        object["type"] = certificate.type.base64
        object["unexpected"] = "unsigned extension"
        let unknown = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(try Certificate(json: unknown))

        XCTAssertThrowsError(try CertificateLimits(
            maximumFieldCiphertextByteCount: Int.max
        )) { error in
            XCTAssertEqual(error as? CertificateError, .invalidLimits)
        }
        let tinyBinary = try CertificateLimits(maximumBinaryByteCount: 1)
        XCTAssertThrowsError(try certificate.binary(
            includingSignature: false,
            limits: tinyBinary
        ))
    }

    func testSignatureBindsEveryCoreMemberAndHighSIsRejected() async throws {
        let original = try await unsignedCertificate(vout: 1).signed(
            using: ProtoWallet(rootKey: try key(9))
        )
        let signature = try XCTUnwrap(original.signature)
        let alternateType = try CertificateTypeID([UInt8](repeating: 8, count: 32))
        let alternateSerial = try CertificateSerialNumber([UInt8](repeating: 7, count: 32))
        let alternateOutpoint = Outpoint(
            transactionID: try TransactionID(wireBytes: [UInt8](repeating: 6, count: 32)),
            outputIndex: 2
        )
        let field = try CertificateFieldName("field")
        let mutations = [
            try Certificate(type: alternateType, serialNumber: original.serialNumber, subject: original.subject, certifier: original.certifier, revocationOutpoint: original.revocationOutpoint, fields: original.fields, signature: signature),
            try Certificate(type: original.type, serialNumber: alternateSerial, subject: original.subject, certifier: original.certifier, revocationOutpoint: original.revocationOutpoint, fields: original.fields, signature: signature),
            try Certificate(type: original.type, serialNumber: original.serialNumber, subject: key(8).publicKey, certifier: original.certifier, revocationOutpoint: original.revocationOutpoint, fields: original.fields, signature: signature),
            try Certificate(type: original.type, serialNumber: original.serialNumber, subject: original.subject, certifier: key(10).publicKey, revocationOutpoint: original.revocationOutpoint, fields: original.fields, signature: signature),
            try Certificate(type: original.type, serialNumber: original.serialNumber, subject: original.subject, certifier: original.certifier, revocationOutpoint: alternateOutpoint, fields: original.fields, signature: signature),
            try Certificate(type: original.type, serialNumber: original.serialNumber, subject: original.subject, certifier: original.certifier, revocationOutpoint: original.revocationOutpoint, fields: [field: try CertificateCiphertext([9])], signature: signature),
        ]
        for mutation in mutations {
            let valid = try await mutation.verifySignature()
            XCTAssertFalse(valid)
        }

        let compact = signature.compactBytes
        let highS = subtract(Array(compact[32...]), from: curveOrder)
        let highSignature = try ECDSASignature(
            compactBytes: Array(compact[..<32]) + highS
        )
        let highCertificate = try Certificate(
            type: original.type,
            serialNumber: original.serialNumber,
            subject: original.subject,
            certifier: original.certifier,
            revocationOutpoint: original.revocationOutpoint,
            fields: original.fields,
            signature: highSignature
        )
        let highValid = try await highCertificate.verifySignature()
        XCTAssertFalse(highValid)
        XCTAssertEqual(
            try Certificate(binary: highCertificate.binary(includingSignature: true)),
            highCertificate
        )
    }

    func testRejectsNoncanonicalCompactSizeNarrowVoutAndDERTrailingBytes() async throws {
        let certificate = try unsignedCertificate(vout: 1)
        let unsigned = try certificate.binary(includingSignature: false)
        var noncanonical = unsigned
        noncanonical.replaceSubrange(162..<163, with: [0xfd, 1, 0])
        XCTAssertThrowsError(try Certificate(binary: noncanonical)) { error in
            XCTAssertEqual(error as? CertificateError, .nonCanonicalCompactSize)
        }

        var wide = unsigned
        wide.replaceSubrange(162..<163, with: [0xff, 0, 0, 0, 0, 1, 0, 0, 0])
        XCTAssertThrowsError(try Certificate(binary: wide)) { error in
            XCTAssertEqual(error as? CertificateError, .invalidOutputIndex)
        }

        let wallet = ProtoWallet(rootKey: try key(9))
        let signed = try await certificate.signed(using: wallet)
        var trailing = try signed.binary(includingSignature: true)
        trailing.append(0)
        XCTAssertThrowsError(try Certificate(binary: trailing)) { error in
            XCTAssertEqual(error as? CertificateError, .invalidSignature)
        }
        let valid = try await signed.verifySignature()
        XCTAssertTrue(valid)
    }

    func testKeyringAndCertificateEnvelopeRoundTripAndBounds() async throws {
        let signed = try await unsignedCertificate(vout: 1).signed(
            using: ProtoWallet(rootKey: try key(9))
        )
        let field = try CertificateFieldName("field")
        let keyring = try CertificateKeyring([
            field: try CertificateCiphertext([UInt8](repeating: 4, count: 80))
        ])
        let mapBinary = try keyring.binary()
        XCTAssertEqual(try CertificateKeyring(binary: mapBinary), keyring)
        let envelope = try CertificateWithKeyringBinary(certificate: signed, keyring: keyring)
        XCTAssertEqual(try CertificateWithKeyringBinary(binary: envelope.binary()), envelope)

        var noncanonical = mapBinary
        noncanonical.replaceSubrange(0..<1, with: [0xfd, 1, 0])
        XCTAssertThrowsError(try CertificateKeyring(binary: noncanonical))
        XCTAssertThrowsError(try CertificateKeyring([
            field: try CertificateCiphertext([UInt8](repeating: 1, count: 4_097))
        ]))
    }

    func testEveryProperBinaryTruncationIsRejected() async throws {
        let signed = try await unsignedCertificate(vout: 1).signed(
            using: ProtoWallet(rootKey: try key(9))
        )
        // The signature is optional in the core format, so the signed form has a
        // valid unsigned prefix. Exercise every proper truncation of that complete
        // unsigned value, and separately use the signed value in the envelope.
        let certificateBytes = try signed.binary(includingSignature: false)
        for end in 0..<certificateBytes.count {
            XCTAssertThrowsError(
                try Certificate(binary: Array(certificateBytes[..<end])),
                "certificate prefix ending at \(end) unexpectedly decoded"
            )
        }

        let field = try CertificateFieldName("field")
        let keyring = try CertificateKeyring([
            field: try CertificateCiphertext([UInt8](repeating: 4, count: 80))
        ])
        let keyringBytes = try keyring.binary()
        for end in 0..<keyringBytes.count {
            XCTAssertThrowsError(
                try CertificateKeyring(binary: Array(keyringBytes[..<end])),
                "keyring prefix ending at \(end) unexpectedly decoded"
            )
        }

        let envelopeBytes = try CertificateWithKeyringBinary(
            certificate: signed,
            keyring: keyring
        ).binary()
        for end in 0..<envelopeBytes.count {
            XCTAssertThrowsError(
                try CertificateWithKeyringBinary(binary: Array(envelopeBytes[..<end])),
                "envelope prefix ending at \(end) unexpectedly decoded"
            )
        }
    }

    func testNonminimalCompactSizeIsRejectedAtEveryCertificateAndKeyringField() async throws {
        let a = try CertificateFieldName("a")
        let b = try CertificateFieldName("b")
        let certificate = try Certificate(
            type: CertificateTypeID([UInt8](repeating: 1, count: 32)),
            serialNumber: CertificateSerialNumber([UInt8](repeating: 2, count: 32)),
            subject: key(7).publicKey,
            certifier: key(9).publicKey,
            revocationOutpoint: Outpoint(
                transactionID: try TransactionID(wireBytes: [UInt8](repeating: 3, count: 32)),
                outputIndex: 1
            ),
            fields: [
                a: try CertificateCiphertext([1]),
                b: try CertificateCiphertext([2]),
            ]
        )
        let certificateBytes = try certificate.binary(includingSignature: false)
        // vout, field count, and each field's name and Base64 value lengths.
        for (offset, value) in [(162, 1), (163, 2), (164, 1), (166, 4), (171, 1), (173, 4)] {
            var malformed = certificateBytes
            malformed.replaceSubrange(offset..<(offset + 1), with: nonminimalCompactSize(value))
            assertCertificateError(.nonCanonicalCompactSize) {
                _ = try Certificate(binary: malformed)
            }
        }

        let keyring = try CertificateKeyring([
            a: try CertificateCiphertext([1]),
            b: try CertificateCiphertext([2]),
        ])
        let keyringBytes = try keyring.binary()
        // entry count, then each name and value length.
        for (offset, value) in [(0, 2), (1, 1), (3, 1), (5, 1), (7, 1)] {
            var malformed = keyringBytes
            malformed.replaceSubrange(offset..<(offset + 1), with: nonminimalCompactSize(value))
            assertCertificateError(.nonCanonicalCompactSize) {
                _ = try CertificateKeyring(binary: malformed)
            }
        }

        let envelope = try CertificateWithKeyringBinary(
            certificate: try await certificate.signed(using: ProtoWallet(rootKey: try key(9))),
            keyring: keyring
        )
        let envelopeBytes = try envelope.binary()
        let decodedCertificateLength = try certificateLengthPrefix(envelopeBytes)
        var nonminimalEnvelope = envelopeBytes
        nonminimalEnvelope.replaceSubrange(
            0..<decodedCertificateLength.prefixLength,
            with: nonminimalCompactSize(decodedCertificateLength.value)
        )
        assertCertificateError(.nonCanonicalCompactSize) {
            _ = try CertificateWithKeyringBinary(binary: nonminimalEnvelope)
        }
    }

    func testDuplicateDescendingInvalidUTF8AndTrailingBytesAreRejected() throws {
        let a = try CertificateFieldName("a")
        let b = try CertificateFieldName("b")
        let certificate = try Certificate(
            type: CertificateTypeID([UInt8](repeating: 1, count: 32)),
            serialNumber: CertificateSerialNumber([UInt8](repeating: 2, count: 32)),
            subject: key(7).publicKey,
            certifier: key(9).publicKey,
            revocationOutpoint: disabledRevocationOutpoint(),
            fields: [a: try CertificateCiphertext([1]), b: try CertificateCiphertext([2])]
        )
        let bytes = try certificate.binary(includingSignature: false)

        var duplicate = bytes
        duplicate[172] = Character("a").asciiValue!
        assertCertificateError(.duplicateFieldName) { _ = try Certificate(binary: duplicate) }

        var descending = bytes
        descending[165] = Character("b").asciiValue!
        descending[172] = Character("a").asciiValue!
        assertCertificateError(.fieldsNotInCanonicalOrder) { _ = try Certificate(binary: descending) }

        var invalidName = bytes
        invalidName[165] = 0xff
        assertCertificateError(.invalidUTF8) { _ = try Certificate(binary: invalidName) }

        var invalidValue = bytes
        invalidValue[167] = 0xff
        assertCertificateError(.invalidUTF8) { _ = try Certificate(binary: invalidValue) }

        var trailing = try CertificateKeyring([a: try CertificateCiphertext([1])]).binary()
        trailing.append(0)
        assertCertificateError(.truncatedCertificate) {
            _ = try CertificateKeyring(binary: trailing)
        }

        var signedEnvelope = try awaitEnvelopeBytes(for: certificate, keyring: try CertificateKeyring([
            a: try CertificateCiphertext([1])
        ]))
        signedEnvelope.append(0)
        assertCertificateError(.truncatedCertificate) {
            _ = try CertificateWithKeyringBinary(binary: signedEnvelope)
        }
    }

    func testOutputIndexUInt32MaximumAndOverflow() throws {
        let maximum = try unsignedCertificate(vout: UInt32.max)
        let maximumBytes = try maximum.binary(includingSignature: false)
        XCTAssertEqual(
            Array(maximumBytes[162..<167]),
            [0xfe, 0xff, 0xff, 0xff, 0xff]
        )
        XCTAssertEqual(try Certificate(binary: maximumBytes).revocationOutpoint.outputIndex, UInt32.max)

        var overflow = maximumBytes
        overflow.replaceSubrange(162..<167, with: [0xff, 0, 0, 0, 0, 1, 0, 0, 0])
        assertCertificateError(.invalidOutputIndex) { _ = try Certificate(binary: overflow) }
    }

    func testExactAndMaximumPlusOneResourceLimits() async throws {
        XCTAssertThrowsError(try CertificateLimits(maximumFieldNameUTF8ByteCount: 51)) {
            XCTAssertEqual($0 as? CertificateError, .invalidLimits)
        }
        let custom = try CertificateLimits(
            maximumFieldNameUTF8ByteCount: 50,
            maximumFieldCiphertextByteCount: 3,
            maximumKeyringCiphertextByteCount: 4_096
        )
        let longName = try CertificateFieldName(String(repeating: "n", count: 50), limits: custom)
        XCTAssertThrowsError(try CertificateFieldName(String(repeating: "n", count: 51)))
        let customCertificate = try Certificate(
            type: CertificateTypeID([UInt8](repeating: 1, count: 32)),
            serialNumber: CertificateSerialNumber([UInt8](repeating: 2, count: 32)),
            subject: key(9).publicKey,
            certifier: key(9).publicKey,
            revocationOutpoint: disabledRevocationOutpoint(),
            fields: [longName: try CertificateCiphertext([1, 2, 3], maximumByteCount: 3)],
            limits: custom
        )
        let signed = try await customCertificate.signed(
            using: ProtoWallet(rootKey: try key(9)),
            limits: custom
        )
        XCTAssertNotNil(signed.signature)
        XCTAssertEqual(
            try Certificate(binary: signed.binary(includingSignature: true, limits: custom), limits: custom),
            signed
        )

        XCTAssertNoThrow(try CertificateCiphertext(
            [UInt8](repeating: 1, count: 3),
            maximumByteCount: 3
        ))
        assertCertificateError(.fieldValueTooLarge(actual: 4, maximum: 3)) {
            _ = try CertificateCiphertext([UInt8](repeating: 1, count: 4), maximumByteCount: 3)
        }
        let keyringField = try CertificateFieldName("k")
        XCTAssertNoThrow(try CertificateKeyring([
            keyringField: try CertificateCiphertext([UInt8](repeating: 1, count: 4_096))
        ]))
        XCTAssertThrowsError(try CertificateKeyring([
            keyringField: try CertificateCiphertext([UInt8](repeating: 1, count: 4_097))
        ]))

        let unsignedBytes = try unsignedCertificate(vout: 1).binary(includingSignature: false)
        let exactBinary = try CertificateLimits(maximumBinaryByteCount: unsignedBytes.count)
        XCTAssertNoThrow(try Certificate(binary: unsignedBytes, limits: exactBinary))
        let oneShort = try CertificateLimits(maximumBinaryByteCount: unsignedBytes.count - 1)
        assertCertificateError(.certificateTooLarge(actual: unsignedBytes.count, maximum: unsignedBytes.count - 1)) {
            _ = try Certificate(binary: unsignedBytes, limits: oneShort)
        }
    }

    func testSigningSupportsPreimageBeyondWalletPayloadLimitAndValidatesFinalSize() async throws {
        let field = try CertificateFieldName("large")
        let expandedCiphertextLimit =
            CertificateLimits.standard.maximumFieldCiphertextByteCount + 1
        let custom = try CertificateLimits(
            maximumFieldCiphertextByteCount: expandedCiphertextLimit
        )
        let certificate = try Certificate(
            type: CertificateTypeID([UInt8](repeating: 1, count: 32)),
            serialNumber: CertificateSerialNumber([UInt8](repeating: 2, count: 32)),
            subject: key(9).publicKey,
            certifier: key(9).publicKey,
            revocationOutpoint: disabledRevocationOutpoint(),
            fields: [
                field: try CertificateCiphertext(
                    [UInt8](repeating: 7, count: expandedCiphertextLimit),
                    maximumByteCount: expandedCiphertextLimit
                )
            ],
            limits: custom
        )
        let unsigned = try certificate.binary(includingSignature: false, limits: custom)
        XCTAssertGreaterThan(unsigned.count, WalletCryptoLimits.standard.maximumPayloadByteCount)
        let signed = try await certificate.signed(
            using: ProtoWallet(rootKey: try key(9)),
            limits: custom
        )
        let signatureValid = try await signed.verifySignature(limits: custom)
        XCTAssertTrue(signatureValid)

        let exactUnsignedOnly = try CertificateLimits(
            maximumFieldCiphertextByteCount: expandedCiphertextLimit,
            maximumBinaryByteCount: unsigned.count
        )
        await XCTAssertThrowsErrorAsync {
            _ = try await certificate.signed(
                using: ProtoWallet(rootKey: try self.key(9)),
                limits: exactUnsignedOnly
            )
        }
    }

    private func unsignedCertificate(vout: UInt32) throws -> Certificate {
        let field = try CertificateFieldName("field")
        return try Certificate(
            type: CertificateTypeID([UInt8](repeating: 1, count: 32)),
            serialNumber: CertificateSerialNumber([UInt8](repeating: 2, count: 32)),
            subject: key(7).publicKey,
            certifier: key(9).publicKey,
            revocationOutpoint: Outpoint(
                transactionID: try TransactionID(wireBytes: [UInt8](repeating: 3, count: 32)),
                outputIndex: vout
            ),
            fields: [field: try CertificateCiphertext([1, 2, 3])]
        )
    }

    private func key(_ scalar: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [scalar])
    }

    private func disabledRevocationOutpoint() -> Outpoint {
        Outpoint(
            transactionID: TransactionID(
                exactDigestBytesGuaranteed: [UInt8](repeating: 0, count: 32)
            ),
            outputIndex: 0
        )
    }

    private func awaitEnvelopeBytes(
        for certificate: Certificate,
        keyring: CertificateKeyring
    ) throws -> [UInt8] {
        // This helper is synchronous, so use a deterministic strict-DER signature
        // only to exercise the envelope's complete-input parser.
        let digest = BSVHashing.sha256(
            try certificate.binary(includingSignature: false)
        )
        let signature = try key(9).sign(digest: digest)
        return try CertificateWithKeyringBinary(
            certificate: certificate.replacingSignature(signature),
            keyring: keyring
        ).binary()
    }

    private func nonminimalCompactSize(_ value: Int) -> [UInt8] {
        [0xfd, UInt8(value & 0xff), UInt8((value >> 8) & 0xff)]
    }

    private func certificateLengthPrefix(_ bytes: [UInt8]) throws -> (value: Int, prefixLength: Int) {
        switch bytes[0] {
        case 0...0xfc:
            return (Int(bytes[0]), 1)
        case 0xfd:
            return (Int(bytes[1]) | (Int(bytes[2]) << 8), 3)
        default:
            throw CertificateError.invalidLimits
        }
    }

    private func assertCertificateError<T>(
        _ expected: CertificateError,
        _ expression: () throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            XCTAssertEqual(error as? CertificateError, expected, file: file, line: line)
        }
    }

    private func XCTAssertThrowsErrorAsync<T>(
        _ expression: () async throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await expression()
            XCTFail("expected error", file: file, line: line)
        } catch {
            guard case CertificateError.certificateTooLarge = error else {
                XCTFail("expected certificateTooLarge, got \(error)", file: file, line: line)
                return
            }
        }
    }

    private let curveOrder: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]

    private func subtract(_ subtrahend: [UInt8], from minuend: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: minuend.count)
        var borrow = 0
        for index in minuend.indices.reversed() {
            var difference = Int(minuend[index]) - Int(subtrahend[index]) - borrow
            if difference < 0 { difference += 256; borrow = 1 } else { borrow = 0 }
            result[index] = UInt8(difference)
        }
        return result
    }
}
