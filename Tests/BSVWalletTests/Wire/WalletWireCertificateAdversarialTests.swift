import BSVCore
import BSVKeys
@testable import BSVWallet
import Testing

@Suite("Wallet-wire certificate hostile input")
struct WalletWireCertificateAdversarialTests {
    @Test func rejectsPresentEmptyKeyringAtABIAndWireBoundaries() throws {
        let fixture = try WalletWireCertificateFixture()
        #expect(throws: WalletABIError.invalidFieldRelation(
            "a present certificate keyring must not be empty"
        )) {
            _ = try WalletCertificateResult(
                certificate: fixture.certificate,
                keyring: [:],
                verifier: []
            )
        }

        var payload = WalletWireWriter()
        payload.writeCompactSize(1)
        try payload.writeVarBytes(fixture.certificate.binary(includingSignature: true))
        payload.writeByte(1)
        payload.writeCompactSize(0)
        payload.writeCompactSize(0)
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "empty present certificate keyring"
        )) {
            try WalletWireCodec.decodeCertificateResult(
                [0] + payload.bytes,
                expectedCall: .listCertificates
            )
        }
    }

    @Test func rejectsNoncanonicalCountsHostileCountsAndUnsortedMaps() throws {
        #expect(throws: WalletWireError.noncanonicalCompactSize) {
            try WalletWireCodec.decodeCertificateRequest(
                [WalletCall.discoverByAttributes.rawValue, 0, 0xfd, 0, 0]
            )
        }

        #expect(throws: WalletWireError.countLimitExceeded(
            kind: "certifiers", actual: 10_001, maximum: 10_000
        )) {
            try WalletWireCodec.decodeCertificateRequest(
                [WalletCall.listCertificates.rawValue, 0, 0xfd, 0x11, 0x27]
            )
        }

        var unsorted = WalletWireWriter()
        unsorted.writeCompactSize(2)
        try unsorted.writeString("zeta")
        try unsorted.writeString("last")
        try unsorted.writeString("alpha")
        try unsorted.writeString("first")
        unsorted.writeOptionalUInt32(nil)
        unsorted.writeOptionalUInt32(nil)
        unsorted.writeOptionalBoolean(nil)
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "unsorted or duplicate certificate attributes"
        )) {
            try WalletWireCodec.decodeCertificateRequest(
                [WalletCall.discoverByAttributes.rawValue, 0] + unsorted.bytes
            )
        }
    }

    @Test func rejectsInvalidSentinelsTruncationAndTrailingBytes() throws {
        let fixture = try WalletWireCertificateFixture()
        var payload = WalletWireWriter()
        payload.writeCompactSize(1)
        try payload.writeVarBytes(fixture.certificate.binary(includingSignature: true))
        payload.writeByte(2)
        payload.writeCompactSize(0)
        #expect(throws: WalletWireError.invalidDiscriminator(
            kind: "certificate keyring presence", value: 2
        )) {
            try WalletWireCodec.decodeCertificateResult(
                [0] + payload.bytes,
                expectedCall: .listCertificates
            )
        }

        #expect(throws: WalletWireError.truncated) {
            try WalletWireCodec.decodeCertificateRequest(
                [WalletCall.relinquishCertificate.rawValue, 0, 1, 2]
            )
        }
        #expect(throws: WalletWireError.trailingBytes) {
            try WalletWireCodec.decodeCertificateResult(
                [0, 1],
                expectedCall: .relinquishCertificate
            )
        }
    }

    @Test func rejectsHighSSignatures() throws {
        let fixture = try WalletWireCertificateFixture()
        let highS: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
        ]
        let signature = try ECDSASignature(
            compactBytes: Array(fixture.signature.compactBytes[..<32]) + highS
        )
        let direct = try WalletDirectCertificateAcquisition(
            serialNumber: fixture.serial,
            revocationOutpoint: fixture.outpoint,
            signature: signature,
            keyringRevealer: .certifier,
            keyringForSubject: fixture.keyring
        )
        let request = try WalletAcquireCertificateRequest(
            type: fixture.type,
            certifier: fixture.certifier,
            fields: fixture.textFields,
            acquisition: .direct(direct)
        )
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "high-S signature"
        )) {
            try WalletWireCodec.encodeCertificateRequest(
                .acquireCertificate(request),
                originator: ""
            )
        }
    }

    @Test func decodesMultipleDiscoveryCertificatesWithoutThePinnedGoReaderDefect() throws {
        let fixture = try WalletWireCertificateFixture()
        let identity = try WalletIdentityCertificate(
            certificate: fixture.certificate,
            certifierInfo: WalletIdentityCertifier(
                name: "Issuer",
                iconURL: "",
                description: "",
                trust: 1
            ),
            publiclyRevealedKeyring: [:],
            decryptedFields: [:]
        )
        let result = try WalletDiscoverCertificatesResult(
            totalCertificates: 2,
            certificates: [identity, identity]
        )
        let encoded = try WalletWireCodec.encodeCertificateResult(
            .discoverByIdentityKey(result)
        )
        let decoded = try WalletWireCodec.decodeCertificateResult(
            encoded,
            expectedCall: .discoverByIdentityKey
        )
        #expect(try WalletWireCodec.encodeCertificateResult(decoded) == encoded)
    }

    @Test func boundedWriterStopsAggregateBeforeAppend() throws {
        let fixture = try WalletWireCertificateFixture()
        let result = try WalletRevealCounterpartyKeyLinkageResult(
            prover: fixture.certifier,
            counterparty: fixture.subject,
            verifier: fixture.verifier,
            revelationTime: "time",
            encryptedLinkage: WalletLinkageCiphertext([UInt8](repeating: 1, count: 64)),
            encryptedLinkageProof: WalletLinkageCiphertext([2])
        )
        let limits = try WalletWireLimits(maximumPayloadByteCount: 32)
        #expect(throws: WalletWireError.self) {
            try WalletWireCodec.encodeCertificateResult(
                .revealCounterpartyKeyLinkage(result),
                limits: limits
            )
        }

        let certificateByteCount = try fixture.certificate.binary(
            includingSignature: true
        ).count
        #expect(throws: WalletWireError.byteLimitExceeded(
            kind: "certificate value",
            actual: certificateByteCount,
            maximum: 32
        )) {
            try WalletWireCodec.encodeCertificateResult(
                .acquireCertificate(fixture.certificate),
                limits: limits
            )
        }
    }

    @Test func rejectsZeroTypesAndRelinquishSerialsOnDecode() throws {
        let fixture = try WalletWireCertificateFixture()
        let prove = try WalletProveCertificateRequest(
            certificate: fixture.certificate,
            fieldsToReveal: [fixture.alpha],
            verifier: fixture.verifier
        )
        var proveFrame = try WalletWireCodec.encodeCertificateRequest(
            .proveCertificate(prove),
            originator: ""
        )
        proveFrame.replaceSubrange(2..<34, with: repeatElement(0, count: 32))
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "zero prove-certificate type"
        )) {
            try WalletWireCodec.decodeCertificateRequest(proveFrame)
        }

        let relinquish = WalletRelinquishCertificateRequest(
            type: fixture.type,
            serialNumber: fixture.serial,
            certifier: fixture.certifier
        )
        var relinquishFrame = try WalletWireCodec.encodeCertificateRequest(
            .relinquishCertificate(relinquish),
            originator: ""
        )
        relinquishFrame.replaceSubrange(2..<34, with: repeatElement(0, count: 32))
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "zero relinquish-certificate type"
        )) {
            try WalletWireCodec.decodeCertificateRequest(relinquishFrame)
        }

        relinquishFrame = try WalletWireCodec.encodeCertificateRequest(
            .relinquishCertificate(relinquish),
            originator: ""
        )
        relinquishFrame.replaceSubrange(34..<66, with: repeatElement(0, count: 32))
        #expect(throws: WalletWireError.nonRoundTrippableValue(
            kind: "zero relinquish-certificate serial number"
        )) {
            try WalletWireCodec.decodeCertificateRequest(relinquishFrame)
        }
    }
}
