import BSVAuth
import BSVCore
import BSVCrypto
import BSVKeys
import BSVWallet
import Foundation
import Testing

@Suite("BRC-52 certificate field order")
struct CertificateFieldOrderTests {
    @Test("a TS-signed certificate with mixed-case fields verifies")
    func typeScriptMixedCaseCertificate() async throws {
        let certificate = try Certificate(json: Array(TypeScriptAuthVectors.mixedCaseCertificate.utf8))
        #expect(
            Hex.encode(try certificate.binary(includingSignature: false))
                == TypeScriptAuthVectors.mixedCaseCertificatePreimage)
        #expect(try await certificate.verifySignature())
        #expect(try await verifies(certificate, over: certificate.binary(includingSignature: false)))

        // Signing the same unsigned certificate gives TypeScript's RFC 6979 signature.
        let unsigned = try unsignedCopy(of: certificate)
        let resigned = try await unsigned.signed(using: ProtoWallet(rootKey: try key(11)))
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
                try CertificateFieldName("été"): "summer", try CertificateFieldName("Ete"): "x",
            ],
            using: ProtoWallet(rootKey: try key(11)))
        let certificate = master.certificate
        let localeOrder = try certificate.binary(includingSignature: false)
        let byteOrder = try certificate.binary(
            includingSignature: false, limits: .standard, fieldOrder: .utf8Bytes)
        #expect(localeOrder != byteOrder)
        #expect(try await verifies(certificate, over: localeOrder))
        #expect(try await verifies(certificate, over: byteOrder) == false)
        #expect(try await certificate.verifySignature())
    }

    @Test("names whose localeCompare order is not reproduced are refused at issue")
    func unreproducibleFieldNames() async throws {
        // ICU root collation is emulated for ASCII and accented Latin letters
        // only (COMP-041), so a certificate whose TS signature order could not
        // be predicted is not issued.
        let fields = [
            try CertificateFieldName("øre"): "krone", try CertificateFieldName("age"): "30",
        ]
        let log = AuthLogLines()
        let error = await log.record {
            await #expect(throws: CertificateFieldNameError.unsupportedCharacter) {
                try await CertificateEngine.issue(
                    type: try CertificateTypeID([UInt8](repeating: 0x24, count: 32)),
                    subject: .publicKey(try key(7).publicKey),
                    plaintextFields: fields,
                    using: ProtoWallet(rootKey: try key(11)))
            }
        }
        #expect(
            error?.localizedDescription
                == "Certificate field names must use only plain ASCII letters, digits, spaces and "
                + "symbols, and accented Latin letters.")
        #expect(log.lines.contains { $0.contains("Certificate issue: a field name of 4 bytes") })
    }

    @Test("a single field is issued whatever its name")
    func singleFieldIssue() async throws {
        let master = try await CertificateEngine.issue(
            type: try CertificateTypeID([UInt8](repeating: 0x25, count: 32)),
            subject: .publicKey(try key(7).publicKey),
            plaintextFields: [try CertificateFieldName("øre"): "krone"],
            using: ProtoWallet(rootKey: try key(11)))
        #expect(master.certificate.fields.keys.map(\.value) == ["øre"])
        #expect(try await master.certificate.verifySignature())
    }

    @Test("certificates signed in byte order still verify through the engine")
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
        // The Go SDK and earlier releases of this SDK sign UTF-8 byte order.
        let byteOrder = try unsigned.binary(
            includingSignature: false, limits: .standard, fieldOrder: .utf8Bytes)
        let signature = try await ProtoWallet(rootKey: try key(11)).createSignature(
            .init(
                protocolID: try CertificateProtocols.signature,
                keyID: try WalletKeyID(unsigned.signatureKeyID),
                counterparty: .anyone,
                payload: .digest(BSVHashing.sha256(byteOrder))
            )
        ).signature
        let goSigned = try unsigned.replacingSignature(signature)
        #expect(try await goSigned.verifySignature())
        let localeOrder = try await unsigned.signed(using: ProtoWallet(rootKey: try key(11)))
        #expect(goSigned.signature != localeOrder.signature)
        #expect(try await localeOrder.verifySignature())
        #expect(try await verifies(localeOrder, over: byteOrder) == false)

        let tampered = try Certificate(
            type: unsigned.type, serialNumber: unsigned.serialNumber, subject: unsigned.subject,
            certifier: unsigned.certifier, revocationOutpoint: unsigned.revocationOutpoint,
            fields: [
                try CertificateFieldName("Zip"): try CertificateCiphertext([9]),
                try CertificateFieldName("age"): try CertificateCiphertext([2]),
            ],
            signature: signature)
        #expect(try await tampered.verifySignature() == false)
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
