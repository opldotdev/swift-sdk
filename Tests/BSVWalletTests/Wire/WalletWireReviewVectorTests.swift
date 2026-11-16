import Foundation
import BSVCore
import BSVKeys
import BSVTransaction
@testable import BSVWallet
import Testing

/// Frames from the live `@bsv/sdk` 4.1.1 oracle (Tools/Conformance/TSOracle/gen.ts,
/// the X- review cases), fixed here so they run without the TypeScript toolchain.
/// TS paths are in `packages/sdk/src`.
@Suite("Wallet wire review vectors from @bsv/sdk 4.1.1")
struct WalletWireReviewVectorTests {
    // MARK: M1 certificate field order

    /// One certificate whose fields TS sorted with `localeCompare`
    /// (auth/certificates/Certificate.ts:290): `cardholder` before `cardNumber`,
    /// the reverse of byte order.
    private static let mixedCaseCertificate =
        "0707070707070707070707070707070707070707070707070707070707070707"
        + "0909090909090909090909090909090909090909090909090909090909090909"
        + "035818cd7cc614fea816c8b39eebe6e43cafc635451ec5a873f8757b418aaae91a"
        + "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
        + "abababababababababababababababababababababababababababababababab00"
        + "02" + "0a63617264686f6c646572085a5731686157773d"
        + "0a636172644e756d62657208626d46745a513d3d"
        + "3045022100c07e93b06a4d095e3b5a54f99a23d9fb047bf97c281639284639482e0cbd3cbb"
        + "0220182d292dfa53425744adcbfab1f95fb607aeef4248162f2cf0902dad87369865"

    /// X-acquireCertificate-, X-listCertificates- and X-discover-mixed-case-fields:
    /// the TS processor's answers. WalletWireTransceiver.ts:1532 reads them with
    /// `Certificate.fromBinary`, which takes any order.
    @Test func readsTypeScriptCertificatesWithLocaleCompareFieldOrder() throws {
        let certificate = try Certificate(binary: try hex(Self.mixedCaseCertificate))
        #expect(Set(certificate.fields.keys.map(\.value)) == ["cardholder", "cardNumber"])

        let acquired = try WalletWireCodec.decodeCertificateResult(
            [0x00] + hex(Self.mixedCaseCertificate),
            expectedCall: .acquireCertificate
        )
        guard case .acquireCertificate(let value) = acquired else {
            Issue.record("expected acquireCertificate")
            return
        }
        #expect(value.fields.count == 2)

        let listed = try WalletWireCodec.decodeCertificateResult(
            [0x00, 0x01] + listRecord(),
            expectedCall: .listCertificates
        )
        guard case .listCertificates(let page) = listed else {
            Issue.record("expected listCertificates")
            return
        }
        #expect(page.certificates.first?.certificate.fields.count == 2)

        let discovered = try WalletWireCodec.decodeCertificateResult(
            [0x00, 0x01] + discoveryRecord(),
            expectedCall: .discoverByIdentityKey
        )
        guard case .discoverByIdentityKey(let found) = discovered else {
            Issue.record("expected discoverByIdentityKey")
            return
        }
        #expect(found.certificates.first?.certificate.fields.count == 2)
    }

    // MARK: S1 noSendChange without noSend

    /// X-createAction-noSendChange-without-noSend. TS reads noSendChange whatever
    /// noSend says (wallet/validationHelpers.ts:680, WalletWireProcessor.ts:539-556).
    @Test func acceptsNoSendChangeWithoutNoSend() async throws {
        let request = try hex(
            "010b6578616d706c652e636f6d0c4f7074696f6e732068657265"
            + "ffffffffffffffffffffffffffffffffffff"
            + "011976a914ca9de335082b64a8030b48d5a6d3432efc5d4aba88ac0107506179206f7574"
            + String(repeating: "ff", count: 54)
            + "01ffffffffffffffffffffffff01ff"
            + "01a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a102"
            + "01b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2ff"
        )
        let response = try await answer(
            request,
            walletResult: #"{"txid":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}"#
        )
        #expect(Hex.encode(response) == "0001" + String(repeating: "a1", count: 32)
            + "00" + "ffffffffffffffffff" + "ffffffffffffffffff" + "00")
    }

    /// The peer reads which value was wrong, not "unsupported wallet action value".
    @Test func abiFailuresKeepTheirReason() {
        let relation = WalletABIError.invalidFieldRelation("fieldsToReveal contains duplicates")
        #expect(walletWireMapABIError(relation) as? WalletABIError == relation)
        #expect(walletWireRequestFailureMessage(relation, call: .proveCertificate)
            == "Invalid Wallet Wire proveCertificate request: fieldsToReveal contains duplicates")
        #expect(walletWireRequestFailureMessage(
            WalletABIError.invalidEnumText(type: "trust self", value: "all"), call: .createAction
        ) == "Invalid Wallet Wire createAction request: all is not a valid trust self")
        #expect(walletWireMapCertificateError(CertificateError.fieldNotFound) as? CertificateError
            == .fieldNotFound)
    }

    // MARK: S2 fixed text to the peer, detail to the log

    @Test func otherErrorsSendFixedTextAndLogTheirDetail() {
        let error = ReviewInternalFailure(secret: "internal-detail")
        let request = walletWireRequestFailureMessage(error, call: .getHeight)
        let result = walletWireResultFailureMessage(error, call: .listOutputs)
        #expect(request == "Invalid Wallet Wire getHeight request")
        #expect(result == "Invalid listOutputs result")
        for message in [request, result] {
            #expect(!message.contains("ReviewInternalFailure"))
            #expect(!message.contains("internal-detail"))
        }
        let line = WalletLog.line("Wallet wire result encode", call: .listOutputs, underlying: error)
        #expect(line.contains("listOutputs"))
        #expect(line.contains("ReviewInternalFailure"))
        #expect(line.contains("internal-detail"))
        #expect(WalletLog.subsystem == "dev.opl.swift-sdk")
        #expect(WalletLog.category == "BSVWallet")
    }

    // MARK: S3 requested page limit

    /// X-listOutputs-over-limit and X-listCertificates-over-limit
    /// (wallet/WalletResultValidation.ts:1945-1949).
    @Test func processorRefusesMoreRecordsThanTheRequestAllows() async throws {
        let outputs = try await answer(
            hex("060b6578616d706c652e636f6d0764656661756c7400ffffffffff01ffffffffffffffffffff"),
            walletResult: #"{"totalOutputs":5,"outputs":[{"outpoint":"\#(Self.txA).1","satoshis":1,"spendable":true},{"outpoint":"\#(Self.txA).2","satoshis":1,"spendable":true}]}"#
        )
        #expect(outputs == errorFrame(
            "Invalid listOutputs result outputs: expected at most the requested limit of 1"
        ))

        let certificate = try Certificate(binary: try hex(Self.mixedCaseCertificate))
        let item = try WalletCertificateResult(certificate: certificate, keyring: nil, verifier: [])
        let result = WalletWireCertificateResult.listCertificates(
            try WalletListCertificatesResult(totalCertificates: 3, certificates: [item, item])
        )
        let request = WalletWireCertificateRequest.listCertificates(try WalletListCertificatesRequest(
            certifiers: [certificate.certifier],
            types: [certificate.type],
            pagination: try WalletPagination(limit: 1)
        ))
        #expect(throws: WalletWireResultRejection(
            message: "Invalid listCertificates result certificates: expected at most the requested limit of 1"
        )) {
            try WalletWireCodec.encodeCertificateResult(result, request: request)
        }
        // Without a request there is nothing to check against.
        #expect(try WalletWireCodec.encodeCertificateResult(result).first == 0)
    }

    /// WalletWireTransceiver.ts:1617, :1837 and :2097-2102: a reader stops at the
    /// requested limit (10 when the request gives none).
    @Test func transceiverReadsCertificatePagesUpToTheRequestedLimit() throws {
        let certificate = try Certificate(binary: try hex(Self.mixedCaseCertificate))
        let list = WalletWireCertificateRequest.listCertificates(try WalletListCertificatesRequest(
            certifiers: [certificate.certifier],
            types: [certificate.type],
            pagination: try WalletPagination(limit: 1)
        ))
        let listFrame: [UInt8] = [0x00, 0x02] + (try listRecord()) + (try listRecord())
        #expect(throws: WalletWireResultRejection(
            message: "Wallet Wire listCertificates response exceeds the requested page limit of 1"
        )) {
            try WalletWireCodec.decodeCertificateResult(
                listFrame, expectedCall: .listCertificates, request: list
            )
        }

        let discover = WalletWireCertificateRequest.discoverByIdentityKey(
            WalletDiscoverByIdentityKeyRequest(
                identityKey: certificate.subject,
                pagination: try WalletPagination(limit: 1)
            )
        )
        let record = try discoveryRecord()
        let discoveryFrame: [UInt8] = [0x00, 0x02] + record + record
        #expect(throws: WalletWireResultRejection(
            message: "Wallet Wire discover response exceeds the requested page limit of 1"
        )) {
            try WalletWireCodec.decodeCertificateResult(
                discoveryFrame, expectedCall: .discoverByIdentityKey, request: discover
            )
        }

        let defaultLimit = WalletWireCertificateRequest.discoverByIdentityKey(
            WalletDiscoverByIdentityKeyRequest(identityKey: certificate.subject)
        )
        var eleven: [UInt8] = [0x00, 0x0b]
        for _ in 0..<11 { eleven += record }
        #expect(throws: WalletWireResultRejection(
            message: "Wallet Wire discover response exceeds the requested page limit of 10"
        )) {
            try WalletWireCodec.decodeCertificateResult(
                eleven, expectedCall: .discoverByIdentityKey, request: defaultLimit
            )
        }
    }

    // MARK: N2 error wording

    /// X-relinquishCertificate-false (WalletWireProcessor.ts:2293),
    /// X-waitForAuthentication-false (:1683), X-listOutputs-not-balance (:178-191),
    /// X-listOutputs-more-than-total (WalletResultValidation.ts:1942).
    @Test func refusalsUseTheTypeScriptWording() async throws {
        let relinquish = try await answer(
            hex("140b6578616d706c652e636f6d"
                + String(repeating: "07", count: 32) + String(repeating: "09", count: 32)
                + "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"),
            walletResult: #"{"relinquished":false}"#
        )
        #expect(relinquish == errorFrame("The wallet did not relinquish the certificate"))

        let wait = try await answer(
            hex("180b6578616d706c652e636f6d"), walletResult: #"{"authenticated":false}"#
        )
        #expect(wait == errorFrame("Wallet did not affirmatively authenticate"))

        let notBalance = try await answer(
            hex("060b6578616d706c652e636f6d0d702062746d7320746f6b656e7300"
                + String(repeating: "ff", count: 24)),
            walletResult: #"{"totalOutputs":5000000000,"outputs":[]}"#
        )
        #expect(notBalance == errorFrame(
            "Invalid listOutputs result total: expected an integer from 0 to 4294967295, received 5000000000"
        ))

        let moreThanTotal = try await answer(
            hex("060b6578616d706c652e636f6d0764656661756c7400" + String(repeating: "ff", count: 24)),
            walletResult: #"{"totalOutputs":1,"outputs":[{"outpoint":"\#(Self.txA).1","satoshis":1,"spendable":true},{"outpoint":"\#(Self.txA).2","satoshis":1,"spendable":true}]}"#
        )
        #expect(moreThanTotal == errorFrame("Invalid listOutputs result totalOutputs: expected at least 2"))
    }

    /// X-raw-call-29-probe-trailing (substrates/CertificateWireCompatibility.ts:118-119),
    /// X-raw-originator-bad-utf8 (primitives/utils.ts:237, a fatal TextDecoder),
    /// X-raw-getPublicKey-bad-flag (WalletWireProcessor.ts:49, :1437).
    @Test func malformedFramesUseTheTypeScriptWording() async throws {
        let probe = try await answer(hex("1d00000100"), walletResult: nil)
        #expect(probe == errorFrame(
            "Wallet Wire certificate compatibility probe request contains trailing data"
        ))
        // A well-formed probe still gets the text TS clients downgrade on.
        let plainProbe = try await answer(hex("1d000001"), walletResult: nil)
        #expect(plainProbe == errorFrame("Invalid call code: 29"))

        let originator = try await answer(hex("1902c328"), walletResult: nil)
        #expect(originator == errorFrame("The encoded data was not valid for encoding utf-8"))

        let flag = try await answer(hex("080002"), walletResult: nil)
        #expect(flag == errorFrame("Invalid identityKey flag: expected 0 or 1, received 2"))
    }

    // MARK: helpers

    private static let txA = String(repeating: "a1", count: 32)

    private func hex(_ text: String) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: 1 << 16)
    }

    /// A listCertificates record: certificate, keyring flag 0, empty verifier.
    private func listRecord() throws -> [UInt8] {
        let certificate = try hex(Self.mixedCaseCertificate)
        var writer = WalletWireWriter()
        try writer.writeVarBytes(certificate)
        writer.writeByte(0)
        writer.writeCompactSize(0)
        return writer.bytes
    }

    /// A discovery record as X-discover-mixed-case-fields carries it.
    private func discoveryRecord() throws -> [UInt8] {
        let certificate = try hex(Self.mixedCaseCertificate)
        var writer = WalletWireWriter()
        try writer.writeVarBytes(certificate)
        writer.writeBytes(try hex(
            "09436572746966696572"
            + "1968747470733a2f2f6578616d706c652e636f6d2f692e706e67"
            + "0c54727573746564206365727405" + "00" + "00"
        ))
        return writer.bytes
    }

    private func errorFrame(_ message: String) -> [UInt8] {
        [1, UInt8(message.utf8.count)] + Array(message.utf8) + [0x00]
    }

    private func answer(_ request: [UInt8], walletResult: String?) async throws -> [UInt8] {
        let processor = WalletWireProcessor(
            handler: ReviewJSONHandler(walletResult: walletResult, codec: try reviewCodec()),
            failureMapper: try WalletWireRedactingFailureMapper(limits: .standard),
            beefLimits: try actionBEEFLimits(),
            certificateLimits: .standard,
            wireLimits: .standard
        )
        return try await processor.transmit(request, maximumResponseByteCount: 1 << 16)
    }
}

private struct ReviewInternalFailure: Error {
    let secret: String
}

private struct ReviewNoResult: Error {}

private func reviewCodec() throws -> WalletBRC100JSONCodec {
    try WalletBRC100JSONCodec(beefLimits: actionBEEFLimits())
}

/// Answers with the wallet result the TS oracle's stub wallet returned.
private struct ReviewJSONHandler: WalletRequestHandling {
    let walletResult: String?
    let codec: WalletBRC100JSONCodec

    func handle(_ request: WalletRequest, context: WalletRequestContext) async throws -> WalletResult {
        guard let walletResult else { throw ReviewNoResult() }
        return try codec.decodeResult(
            route: WalletJSONRoute(call: request.call),
            from: Array(walletResult.utf8)
        )
    }
}
