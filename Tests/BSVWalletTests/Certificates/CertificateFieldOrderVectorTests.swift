import BSVCore
import BSVCrypto
import BSVKeys
import BSVTransaction
import BSVWallet
import Foundation
import Testing

/// BRC-52 certificates written and signed by `@bsv/sdk` 4.1.1
/// `Certificate.sign` and `Certificate.toBinary`, whose fields are in
/// `localeCompare` order (`auth/certificates/Certificate.ts:290`, `:473`).
/// The field names differ from UTF-8 byte order in case, accents, underscores
/// and digits. Produced by `certorder-vec.ts` in
/// Documentation/Compatibility/TypeScriptAuthVectors.md (certifier key 11,
/// subject key 7).
@Suite("BRC-52 certificates in TypeScript field order")
struct CertificateFieldOrderVectorTests {
    static let accentedCertificateJSON =
        #"{"type":"MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=","serialNumber":"MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjI=","subject":"025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc","certifier":"03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb","revocationOutpoint":"0000000000000000000000000000000000000000000000000000000000000000.0","fields":{"Zip":"AQ==","zip_code":"Ag==","zip-code":"Aw==","zip2":"BA==","zip10":"BQ==","Zeta":"Bg==","email":"Bw==","eMail":"CA==","Email":"CQ==","_id":"Cg==","id":"Cw==","ID":"DA==","a1":"DQ==","a_1":"Dg==","a-1":"Dw==","aB":"EA==","ab":"EQ==","cafe":"Eg==","café":"Ew==","Café":"FA==","cafés":"FQ==","émile":"Fg==","Émile":"Fw==","naïve":"GA==","nausea":"GQ==","résumé":"Gg==","resume":"Gw==","zoë":"HA==","Ångström":"HQ==","angle":"Hg=="},"signature":"30440220414ba43586646efbbb901e48680c419bb5de91ec1730ef99f7602bda95c1711b02204aa129d5d7bb3d1d2c5865243d48a9f84a34dbeab5b58f8ce06c6d9d0e607969"}"#

    static let accentedCertificateBinary =
        "313131313131313131313131313131313131313131313131313131313131313132323232323232323232323232323232"
        + "32323232323232323232323232323232025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9"
        + "bc03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb0000000000000000000000000000"
        + "000000000000000000000000000000000000001e035f69640443673d3d03615f310444673d3d03612d310444773d3d02"
        + "61310444513d3d0261620445513d3d0261420445413d3d05616e676c650448673d3d0ac3856e67737472c3b66d044851"
        + "3d3d04636166650445673d3d05636166c3a90445773d3d05436166c3a90446413d3d06636166c3a9730446513d3d0565"
        + "6d61696c0442773d3d05654d61696c0443413d3d05456d61696c0443513d3d06c3a96d696c650446673d3d06c3896d69"
        + "6c650446773d3d0269640443773d3d0249440444413d3d066e61c3af76650447413d3d066e61757365610447513d3d06"
        + "726573756d650447773d3d0872c3a973756dc3a90447673d3d045a6574610442673d3d035a69700441513d3d087a6970"
        + "5f636f64650441673d3d087a69702d636f64650441773d3d057a697031300442513d3d047a6970320442413d3d047a6f"
        + "c3ab0448413d3d30440220414ba43586646efbbb901e48680c419bb5de91ec1730ef99f7602bda95c1711b02204aa129"
        + "d5d7bb3d1d2c5865243d48a9f84a34dbeab5b58f8ce06c6d9d0e607969"

    static let accentedCertificatePreimageByteCount = 487

    static let asciiCertificateBinary =
        "333333333333333333333333333333333333333333333333333333333333333334343434343434343434343434343434"
        + "34343434343434343434343434343434025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9"
        + "bc03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb0000000000000000000000000000"
        + "000000000000000000000000000000000000000c035f69640452773d3d03615f310453673d3d0261310453773d3d0565"
        + "6d61696c0452513d3d05456d61696c0452673d3d0269640453513d3d0249440453413d3d035a69700451413d3d087a69"
        + "705f636f64650451513d3d087a69702d636f64650451673d3d057a697031300452413d3d047a6970320451773d3d3044"
        + "022011b40e97ca13fac44274ed40d543546a40ff1be101ae6f0e8b3d29d15150b69d022037020a2aea15e7e11e54a51f"
        + "838dc029010b6e42e620425fe93a66cc8edaf8fc"

    static let asciiCertificatePreimageByteCount = 286

    /// Signed by `Certificate.sign` with names whose `localeCompare` order
    /// this SDK does not reproduce: `ß`, which ICU sorts as `ss`, Cyrillic
    /// with `ё` and case pairs, and CJK. TypeScript order:
    /// `name Name strasse straße strat stress ёлка ель имя Имя 名前 日本`.
    /// Produced by `certwire-vec.ts` (TypeScriptAuthVectors.md).
    static let exoticCertificateJSON =
        #"{"type":"NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU=","serialNumber":"NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY=","subject":"025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc","certifier":"03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb","revocationOutpoint":"0000000000000000000000000000000000000000000000000000000000000000.0","fields":{"straße":"AQ==","strasse":"Ag==","strat":"Aw==","stress":"BA==","имя":"BQ==","Имя":"Bg==","ёлка":"Bw==","ель":"CA==","日本":"CQ==","名前":"Cg==","name":"Cw==","Name":"DA=="},"signature":"30440220334e585ca445bbfef97538a8a2a8c7b7ef7618e6cc248df7473704cd54b26b820220196f71271a0830f0762ec7385fb2cabde5127b1592d14af46149e3460223a6fc"}"#

    static let exoticCertificateBinary =
        "353535353535353535353535353535353535353535353535353535353535353536363636363636363636363636363636"
        + "36363636363636363636363636363636025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9"
        + "bc03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb0000000000000000000000000000"
        + "000000000000000000000000000000000000000c046e616d650443773d3d044e616d650444413d3d0773747261737365"
        + "0441673d3d0773747261c39f650441513d3d0573747261740441773d3d067374726573730442413d3d08d191d0bbd0ba"
        + "d0b00442773d3d06d0b5d0bbd18c0443413d3d06d0b8d0bcd18f0442513d3d06d098d0bcd18f0442673d3d06e5908de5"
        + "898d0443673d3d06e697a5e69cac0443513d3d30440220334e585ca445bbfef97538a8a2a8c7b7ef7618e6cc248df747"
        + "3704cd54b26b820220196f71271a0830f0762ec7385fb2cabde5127b1592d14af46149e3460223a6fc"

    /// Signed by `Certificate.sign` with the host collation Node 22 resolves
    /// under `LC_ALL=da_DK.UTF-8` (`da-DK`, capitals first), which sorts
    /// `email Email id ID aa z` as `Email email ID id z aa`. Produced by
    /// `certwire-vec.ts`.
    static let danishCertificateJSON =
        #"{"type":"Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=","serialNumber":"ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg=","subject":"025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc","certifier":"03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb","revocationOutpoint":"0000000000000000000000000000000000000000000000000000000000000000.0","fields":{"email":"AQ==","Email":"Ag==","id":"Aw==","ID":"BA==","aa":"BQ==","z":"Bg=="},"signature":"3045022100e2642ed325b09615e6a8a0839625d21ba1a2fafaeff16391478e0c2b70c2824902201ad32b894373467af183e6000955e1eadd6ef7fb38a5f04117292054a8e8e03c"}"#

    static let danishCertificateBinary =
        "373737373737373737373737373737373737373737373737373737373737373738383838383838383838383838383838"
        + "38383838383838383838383838383838025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9"
        + "bc03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb0000000000000000000000000000"
        + "000000000000000000000000000000000000000605456d61696c0441673d3d05656d61696c0441513d3d024944044241"
        + "3d3d0269640441773d3d017a0442673d3d0261610442513d3d3045022100e2642ed325b09615e6a8a0839625d21ba1a2"
        + "fafaeff16391478e0c2b70c2824902201ad32b894373467af183e6000955e1eadd6ef7fb38a5f04117292054a8e8e03c"

    @Test("a TS certificate with names outside the reproduced order verifies from binary by received order")
    func exoticTypeScriptCertificate() async throws {
        let decoded = try Certificate(binary: try hex(Self.exoticCertificateBinary))
        #expect(decoded.receivedFieldOrder?.map(\.value) == [
            "name", "Name", "strasse", "straße", "strat", "stress", "ёлка", "ель", "имя", "Имя",
            "名前", "日本",
        ])
        // Neither order this SDK computes is the one TypeScript signed.
        let unsigned = try decoded.binary(includingSignature: false, limits: .standard, fieldOrder: .received)
        #expect(unsigned != (try decoded.binary(includingSignature: false)))
        #expect(unsigned != (try decoded.binary(
            includingSignature: false, limits: .standard, fieldOrder: .utf8Bytes)))
        #expect(Hex.encode(unsigned + decoded.signature!.derBytes) == Self.exoticCertificateBinary)
        #expect(try await decoded.verifySignature())

        // Read from JSON, the certificate is equal but has no received order.
        let fromJSON = try Certificate(json: Array(Self.exoticCertificateJSON.utf8))
        #expect(fromJSON == decoded)
        #expect(fromJSON.receivedFieldOrder == nil)
        #expect(try await fromJSON.verifySignature() == false)

        // The received order carries through a signature replacement, and
        // binds the values: a changed value fails in every order.
        let resignable = try decoded.withoutSignature()
        #expect(try await resignable.replacingSignature(decoded.signature!).verifySignature())
        var fields = decoded.fields
        fields[try CertificateFieldName("straße")] = try CertificateCiphertext([0xFF])
        var tampered = try Certificate(
            type: decoded.type, serialNumber: decoded.serialNumber, subject: decoded.subject,
            certifier: decoded.certifier, revocationOutpoint: decoded.revocationOutpoint,
            fields: fields, signature: decoded.signature)
        tampered.receivedFieldOrder = decoded.receivedFieldOrder
        #expect(try await tampered.verifySignature() == false)
    }

    @Test("a TS certificate signed under a Danish host collation verifies from binary")
    func danishTypeScriptCertificate() async throws {
        let decoded = try Certificate(binary: try hex(Self.danishCertificateBinary))
        #expect(decoded.receivedFieldOrder?.map(\.value) == ["Email", "email", "ID", "id", "z", "aa"])
        #expect(try await decoded.verifySignature())
        let fromJSON = try Certificate(json: Array(Self.danishCertificateJSON.utf8))
        #expect(fromJSON == decoded)
        #expect(try await fromJSON.verifySignature() == false)
    }

    @Test("a certificate with no field or one is signed whatever the name")
    func singleFieldAnyName() async throws {
        for fields in [
            [:],
            [try CertificateFieldName("日本"): try CertificateCiphertext([1])],
            [try CertificateFieldName("tab\tname"): try CertificateCiphertext([2])],
        ] as [[CertificateFieldName: CertificateCiphertext]] {
            let unsigned = try Certificate(
                type: try CertificateTypeID([UInt8](repeating: 0x39, count: 32)),
                serialNumber: try CertificateSerialNumber([UInt8](repeating: 0x3A, count: 32)),
                subject: try key(7).publicKey,
                certifier: try key(11).publicKey,
                revocationOutpoint: Outpoint(
                    transactionID: TransactionID(
                        exactDigestBytesGuaranteed: [UInt8](repeating: 0, count: 32)),
                    outputIndex: 0),
                fields: fields)
            let signed = try await unsigned.signed(using: ProtoWallet(rootKey: key(11)))
            #expect(try await signed.verifySignature())
            let decoded = try Certificate(binary: try signed.binary(includingSignature: true))
            #expect(decoded == signed)
            #expect(try await decoded.verifySignature())
        }
    }

    @Test("a TS certificate with accented and mixed-case names round-trips byte for byte and verifies")
    func accentedTypeScriptCertificate() async throws {
        let certificate = try Certificate(json: Array(Self.accentedCertificateJSON.utf8))
        let binary = try certificate.binary(includingSignature: true)
        #expect(Hex.encode(binary) == Self.accentedCertificateBinary)
        #expect(
            try certificate.binary(includingSignature: false)
                == Array(binary.prefix(Self.accentedCertificatePreimageByteCount)))
        #expect(try await certificate.verifySignature())

        let decoded = try Certificate(binary: try hex(Self.accentedCertificateBinary))
        #expect(decoded == certificate)
        #expect(try await decoded.verifySignature())

        // Signing the same fields gives TypeScript's RFC 6979 signature.
        let resigned = try await unsignedCopy(of: certificate).signed(using: ProtoWallet(rootKey: key(11)))
        #expect(resigned.signature == certificate.signature)
        #expect(try resigned.binary(includingSignature: true) == binary)
    }

    @Test("Swift signs an ASCII certificate exactly as TypeScript does")
    func asciiTypeScriptCertificate() async throws {
        let certificate = try Certificate(binary: try hex(Self.asciiCertificateBinary))
        #expect(Hex.encode(try certificate.binary(includingSignature: true)) == Self.asciiCertificateBinary)
        #expect(try await certificate.verifySignature())
        #expect(
            try certificate.binary(includingSignature: false).count
                == Self.asciiCertificatePreimageByteCount)
        let resigned = try await unsignedCopy(of: certificate).signed(using: ProtoWallet(rootKey: key(11)))
        #expect(Hex.encode(try resigned.binary(includingSignature: true)) == Self.asciiCertificateBinary)
    }

    @Test("a signature over UTF-8 byte order, as the Go SDK signs, still verifies")
    func byteOrderSignature() async throws {
        let typeScript = try Certificate(binary: try hex(Self.asciiCertificateBinary))
        let unsigned = try unsignedCopy(of: typeScript)
        let byteOrder = try unsigned.binary(
            includingSignature: false, limits: .standard, fieldOrder: .utf8Bytes)
        #expect(byteOrder != (try unsigned.binary(includingSignature: false)))
        let signature = try await ProtoWallet(rootKey: key(11)).createSignature(
            .init(
                protocolID: try CertificateProtocols.signature,
                keyID: try WalletKeyID(unsigned.signatureKeyID),
                counterparty: .anyone,
                payload: .digest(BSVHashing.sha256(byteOrder))
            )
        ).signature
        let goSigned = try unsigned.replacingSignature(signature)
        #expect(goSigned.signature != typeScript.signature)
        #expect(try await goSigned.verifySignature())

        var fields = unsigned.fields
        fields[try CertificateFieldName("zip2")] = try CertificateCiphertext([0xFF])
        let tampered = try Certificate(
            type: unsigned.type, serialNumber: unsigned.serialNumber, subject: unsigned.subject,
            certifier: unsigned.certifier, revocationOutpoint: unsigned.revocationOutpoint,
            fields: fields, signature: signature)
        #expect(try await tampered.verifySignature() == false)
        let tamperedTypeScript = try Certificate(
            type: unsigned.type, serialNumber: unsigned.serialNumber, subject: unsigned.subject,
            certifier: unsigned.certifier, revocationOutpoint: unsigned.revocationOutpoint,
            fields: fields, signature: typeScript.signature)
        #expect(try await tamperedTypeScript.verifySignature() == false)
    }

    @Test("names whose localeCompare order is not reproduced are not signed")
    func refusesUnreproducibleNames() async throws {
        for name in ["øre", "e\u{301}t\u{E9}", "\u{80}", "日本", "tab\tname"] {
            let unsigned = try Certificate(
                type: try CertificateTypeID([UInt8](repeating: 0x35, count: 32)),
                serialNumber: try CertificateSerialNumber([UInt8](repeating: 0x36, count: 32)),
                subject: try key(7).publicKey,
                certifier: try key(11).publicKey,
                revocationOutpoint: Outpoint(
                    transactionID: TransactionID(
                        exactDigestBytesGuaranteed: [UInt8](repeating: 0, count: 32)),
                    outputIndex: 0),
                fields: [
                    try CertificateFieldName(name): try CertificateCiphertext([1]),
                    try CertificateFieldName("age"): try CertificateCiphertext([2]),
                ])
            await #expect(throws: CertificateFieldNameError.unsupportedCharacter) {
                try await unsigned.signed(using: ProtoWallet(rootKey: key(11)))
            }
        }
        #expect(
            CertificateFieldNameError.unsupportedCharacter.localizedDescription
                == "Certificate field names must use only plain ASCII letters, digits, spaces and "
                + "symbols, and accented Latin letters.")
    }

    private func unsignedCopy(of certificate: Certificate) throws -> Certificate {
        try certificate.withoutSignature(keepingReceivedOrder: false)
    }

    private func hex(_ text: String) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: text.utf8.count / 2)
    }

    private func key(_ scalar: UInt8) throws -> PrivateKey {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[31] = scalar
        return try PrivateKey(bytes)
    }
}

extension Certificate {
    /// The same certificate with no signature, with or without the order
    /// its fields arrived in.
    fileprivate func withoutSignature(keepingReceivedOrder: Bool = true) throws -> Certificate {
        var copy = try Certificate(
            type: type, serialNumber: serialNumber, subject: subject, certifier: certifier,
            revocationOutpoint: revocationOutpoint, fields: fields)
        if keepingReceivedOrder { copy.receivedFieldOrder = receivedFieldOrder }
        return copy
    }
}
