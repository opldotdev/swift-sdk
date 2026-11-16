import BSVAuth
import BSVCore
import BSVCrypto
import BSVKeys
import BSVWallet
import Foundation
import Testing

/// `LocaleCompareOrder` against JavaScript `localeCompare`, and BRC-52
/// certificate signatures over fields in that order.
///
/// The expected values were produced by Bun 1.4.4 and Node 22.23.4 (both ICU,
/// locale `en-US`) running `collate-vec.ts` in
/// Documentation/Compatibility/TypeScriptAuthVectors.md; both printed the same
/// results.
@Suite("localeCompare order")
struct LocaleCompareOrderTests {
    @Test("printable ASCII sorts as localeCompare does")
    func printableASCII() {
        let printable = (0x20...0x7E).map { String(UnicodeScalar(UInt8($0))) }
        let sorted = printable.sorted(by: LocaleCompareOrder.areInIncreasingOrder)
        #expect(
            sorted.joined()
                == " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789"
                + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ")
        #expect(LocaleCompareOrder.asciiOrder.hasSuffix(sorted.joined()))
    }

    @Test("every pair of printable ASCII characters sorts as localeCompare does")
    func printableASCIIPairs() {
        let printable = (0x20...0x7E).map { String(UnicodeScalar(UInt8($0))) }
        var pairs: [String] = []
        for first in printable { for second in printable { pairs.append(first + second) } }
        #expect(pairs.count == 9_025)
        // localeCompare reports no ties among these 9025 strings, so the order is total.
        #expect(
            sortedDigest(pairs)
                == "486638e314651e755e158382de74daec1be1e94d392ff87e70f48006b14bc4f8")
    }

    @Test("three-character strings over spaces, punctuation, digits and both cases")
    func triples() {
        let alphabet = Array(" !-._09aAzZ").map(String.init)
        var triples: [String] = []
        for a in alphabet { for b in alphabet { for c in alphabet { triples.append(a + b + c) } } }
        #expect(triples.count == 1_331)
        #expect(
            sortedDigest(triples)
                == "a7264e62b832c8d1682eb3222b5dadff4d39138b5c05a7fd517bbc32941eb25f")
    }

    @Test("random printable ASCII strings of one to eight characters")
    func randomStrings() {
        // x = (1103515245 x + 12345) mod 2^31 from x = 1, as in `collate-vec.ts`.
        var state: UInt32 = 1
        func next() -> Int {
            state = (state &* 1_103_515_245 &+ 12_345) & 0x7FFF_FFFF
            return Int(state)
        }
        var strings: [String] = []
        for _ in 0..<4_000 {
            let length = 1 + next() % 8
            var value = ""
            for _ in 0..<length { value.unicodeScalars.append(UnicodeScalar(UInt8(0x20 + next() % 95))) }
            strings.append(value)
        }
        #expect(Array(strings.prefix(3)) == ["/[0QeO/", "1(]D+70", "G^[m>^0"])
        #expect(Set(strings).count == 4_000)
        #expect(
            sortedDigest(strings)
                == "1c2fb4ded5031dfa2cf5cf764b119dcb5477b331e17dd8ce43dc71234585957a")
    }

    @Test("field and header names sort as localeCompare does")
    func names() {
        let names = [
            "Zip", "age", "a_b", "a-b", "ab", "a b", "A", "a", "aB", "Ab", "a1", "a10", "a2",
            "x-bsv-a_b", "x-bsv-ab", "x-bsv-a-b", "x-bsv-Z", "x-bsv-z", "email", "Email",
            "first_name", "firstName", "first-name",
        ]
        #expect(
            names.sorted(by: LocaleCompareOrder.areInIncreasingOrder) == [
                "a", "A", "a b", "a_b", "a-b", "a1", "a10", "a2", "ab", "aB", "Ab", "age", "email",
                "Email", "first_name", "first-name", "firstName", "x-bsv-a_b", "x-bsv-a-b",
                "x-bsv-ab", "x-bsv-z", "x-bsv-Z", "Zip",
            ])
        #expect(LocaleCompareOrder.compare("age", "Zip") < 0)
        #expect(Array("age".utf8).lexicographicallyPrecedes(Array("Zip".utf8)) == false)
    }

    @Test("non-ASCII and ignorable characters have a documented total order")
    func nonASCII() {
        // ICU ignores most C0 controls: `'a\u0001b'.localeCompare('ab') === 0`.
        // Such ties fall back to UTF-8 byte order, so the order stays total.
        #expect(LocaleCompareOrder.compare("a\u{01}b", "ab") < 0)
        #expect(LocaleCompareOrder.compare("ab", "a\u{01}b") > 0)
        #expect(LocaleCompareOrder.compare("a\u{AD}b", "abc") < 0)
        // Other non-ASCII sorts after ASCII in code point order. ICU puts
        // `é` between `e` and `f`; this order does not.
        #expect(LocaleCompareOrder.compare("é", "z") > 0)
        #expect(LocaleCompareOrder.compare("日本", "é") > 0)
        #expect(LocaleCompareOrder.compare("same", "same") == 0)
    }

    private func sortedDigest(_ strings: [String]) -> String {
        let sorted = strings.sorted(by: LocaleCompareOrder.areInIncreasingOrder)
        return Hex.encode(BSVHashing.sha256(Array(sorted.joined(separator: "\n").utf8)).bytes)
    }
}

@Suite("BRC-52 certificate field order")
struct CertificateFieldOrderTests {
    @Test("a TS-signed certificate with mixed-case fields verifies")
    func typeScriptMixedCaseCertificate() async throws {
        let certificate = try Certificate(json: Array(TypeScriptAuthVectors.mixedCaseCertificate.utf8))
        #expect(
            Hex.encode(try certificate.localeOrderSigningPreimage(limits: .standard))
                == TypeScriptAuthVectors.mixedCaseCertificatePreimage)
        #expect(try await certificate.verifySignatureInEitherFieldOrder(limits: .standard))
        #expect(try await verifies(certificate, over: certificate.localeOrderSigningPreimage(limits: .standard)))

        // Signing the same unsigned certificate gives TypeScript's RFC 6979 signature.
        let unsigned = try unsignedCopy(of: certificate)
        let resigned = try await unsigned.signedInLocaleOrder(
            using: ProtoWallet(rootKey: try key(11)), limits: .standard)
        #expect(resigned.signature == certificate.signature)
    }

    @Test("issued certificates are signed in localeCompare order")
    func issuedMixedCaseCertificate() async throws {
        let master = try await CertificateEngine.issue(
            type: try CertificateTypeID([UInt8](repeating: 0x21, count: 32)),
            subject: .publicKey(try key(7).publicKey),
            plaintextFields: [
                try CertificateFieldName("Zip"): "90210", try CertificateFieldName("age"): "30",
                try CertificateFieldName("a_b"): "1", try CertificateFieldName("a-b"): "2",
            ],
            using: ProtoWallet(rootKey: try key(11)))
        let certificate = master.certificate
        let localeOrder = try certificate.localeOrderSigningPreimage(limits: .standard)
        #expect(localeOrder != (try certificate.binary(includingSignature: false)))
        #expect(try await verifies(certificate, over: localeOrder))
        #expect(try await certificate.verifySignatureInEitherFieldOrder(limits: .standard))
    }

    @Test("non-ASCII field names are refused at issue and still verify in byte order")
    func nonASCIIFieldNames() async throws {
        // ICU root collation is not emulated past ASCII (COMP-041), so a
        // certificate whose TS signature order could not be predicted is not issued.
        let fields = [
            try CertificateFieldName("été"): "summer", try CertificateFieldName("age"): "30",
        ]
        let log = AuthLogLines()
        let error = await log.record {
            await #expect(throws: (any Error).self) {
                try await CertificateEngine.issue(
                    type: try CertificateTypeID([UInt8](repeating: 0x24, count: 32)),
                    subject: .publicKey(try key(7).publicKey),
                    plaintextFields: fields,
                    using: ProtoWallet(rootKey: try key(11)))
            }
        }
        #expect(
            error?.localizedDescription
                == "Certificate field names must use only plain ASCII letters, digits, spaces and symbols.")
        #expect(log.lines.contains { $0.contains("field name") })

        let unsigned = try Certificate(
            type: try CertificateTypeID([UInt8](repeating: 0x25, count: 32)),
            serialNumber: try CertificateSerialNumber([UInt8](repeating: 0x26, count: 32)),
            subject: try key(7).publicKey,
            certifier: try key(11).publicKey,
            revocationOutpoint: CertificateEngine.disabledRevocationOutpoint,
            fields: [
                try CertificateFieldName("été"): try CertificateCiphertext([1]),
                try CertificateFieldName("age"): try CertificateCiphertext([2]),
            ])
        await #expect(throws: (any Error).self) {
            try await unsigned.signedInLocaleOrder(
                using: ProtoWallet(rootKey: try key(11)), limits: .standard)
        }
        // A Go-style byte-order signature over such names is still accepted.
        let byteOrder = try await unsigned.signed(using: ProtoWallet(rootKey: try key(11)))
        #expect(try await byteOrder.verifySignatureInEitherFieldOrder(limits: .standard))
    }

    @Test("certificates signed in byte order still verify")
    func byteOrderSignatureStillVerifies() async throws {
        let unsigned = try Certificate(
            type: try CertificateTypeID([UInt8](repeating: 0x22, count: 32)),
            serialNumber: try CertificateSerialNumber([UInt8](repeating: 0x23, count: 32)),
            subject: try key(7).publicKey,
            certifier: try key(11).publicKey,
            revocationOutpoint: CertificateEngine.disabledRevocationOutpoint,
            fields: [
                try CertificateFieldName("Zip"): try CertificateCiphertext([1]),
                try CertificateFieldName("age"): try CertificateCiphertext([2]),
            ])
        // `Certificate.signed` signs the UTF-8 byte order, as the Go SDK does.
        let byteOrder = try await unsigned.signed(using: ProtoWallet(rootKey: try key(11)))
        #expect(try await byteOrder.verifySignatureInEitherFieldOrder(limits: .standard))
        let localeOrder = try await unsigned.signedInLocaleOrder(
            using: ProtoWallet(rootKey: try key(11)), limits: .standard)
        #expect(byteOrder.signature != localeOrder.signature)
        #expect(try await localeOrder.verifySignatureInEitherFieldOrder(limits: .standard))

        let tampered = try Certificate(
            type: unsigned.type, serialNumber: unsigned.serialNumber, subject: unsigned.subject,
            certifier: unsigned.certifier, revocationOutpoint: unsigned.revocationOutpoint,
            fields: [
                try CertificateFieldName("Zip"): try CertificateCiphertext([9]),
                try CertificateFieldName("age"): try CertificateCiphertext([2]),
            ],
            signature: byteOrder.signature)
        #expect(try await tampered.verifySignatureInEitherFieldOrder(limits: .standard) == false)
    }

    private func verifies(_ certificate: Certificate, over preimage: [UInt8]) async throws -> Bool {
        try await ProtoWallet.anyone().verifySignature(
            .init(
                protocolID: try CertificateProtocols.signature,
                keyID: try WalletKeyID(certificate.signatureKeyID),
                counterparty: .publicKey(certificate.certifier),
                payload: .digest(BSVHashing.sha256(preimage)),
                signature: try #require(certificate.signature))
        ).valid
    }

    private func unsignedCopy(of certificate: Certificate) throws -> Certificate {
        try Certificate(
            type: certificate.type, serialNumber: certificate.serialNumber,
            subject: certificate.subject, certifier: certificate.certifier,
            revocationOutpoint: certificate.revocationOutpoint, fields: certificate.fields)
    }

    private func key(_ scalar: UInt8) throws -> PrivateKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[31] = scalar
        return try PrivateKey(bytes)
    }
}
