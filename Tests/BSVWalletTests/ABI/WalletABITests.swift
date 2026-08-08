import Foundation
import Testing
import BSVCore
import BSVKeys
import BSVTransaction
@testable import BSVWallet

@Suite("WalletABI")
struct WalletABITests {
    @Test("all 28 call codes are exact and Codable")
    func callCodes() throws {
        let expected: [(WalletCall, UInt8)] = [
            (.createAction, 1), (.signAction, 2), (.abortAction, 3), (.listActions, 4),
            (.internalizeAction, 5), (.listOutputs, 6), (.relinquishOutput, 7),
            (.getPublicKey, 8), (.revealCounterpartyKeyLinkage, 9),
            (.revealSpecificKeyLinkage, 10), (.encrypt, 11), (.decrypt, 12),
            (.createHMAC, 13), (.verifyHMAC, 14), (.createSignature, 15),
            (.verifySignature, 16), (.acquireCertificate, 17), (.listCertificates, 18),
            (.proveCertificate, 19), (.relinquishCertificate, 20),
            (.discoverByIdentityKey, 21), (.discoverByAttributes, 22),
            (.isAuthenticated, 23), (.waitForAuthentication, 24), (.getHeight, 25),
            (.getHeaderForHeight, 26), (.getNetwork, 27), (.getVersion, 28),
        ]
        #expect(WalletCall.allCases.count == 28)
        for (call, raw) in expected {
            #expect(call.rawValue == raw)
            #expect(WalletCall(rawValue: raw) == call)
            let encoded = try JSONEncoder().encode(call)
            #expect(try JSONDecoder().decode(WalletCall.self, from: encoded) == call)
        }
        #expect(WalletCall(rawValue: 0) == nil)
        #expect(WalletCall(rawValue: 29) == nil)
    }

    @Test("closed enums accept only their defined text")
    func enums() throws {
        #expect(try WalletTrustSelf("known") == .known)
        #expect(try WalletActionResultStatus("failed") == .failed)
        #expect(try WalletActionStatus("nonfinal") == .nonfinal)
        #expect(try WalletQueryMode("any") == .any)
        #expect(try WalletOutputInclude("locking scripts") == .lockingScripts)
        #expect(try WalletNetwork("mainnet") == .mainnet)
        #expect(try WalletInternalizeProtocol("wallet payment") == .walletPayment)
        #expect(try WalletCertificateAcquisitionProtocol("issuance") == .issuance)
        #expect(throws: WalletABIError.invalidEnumText(type: "WalletQueryMode", value: "")) {
            try WalletQueryMode("")
        }
        #expect(throws: WalletABIError.invalidEnumText(type: "WalletActionStatus", value: "future")) {
            try WalletActionStatus("future")
        }
        #expect(throws: WalletABIError.invalidEnumText(type: "WalletNetwork", value: "regtest")) {
            try WalletNetwork("regtest")
        }
    }

    @Test("each limit class accepts exact and rejects plus one")
    func limits() throws {
        let limits = try WalletABILimits(
            maximumTextUTF8ByteCount: 3,
            maximumCollectionCount: 3,
            maximumTagCount: 2,
            maximumLabelCount: 2,
            maximumBytePayloadCount: 3,
            maximumAggregatePayloadByteCount: 5
        )
        _ = try WalletGetVersionResult(version: "abc", limits: limits)
        #expect(throws: WalletABIError.self) {
            try WalletGetVersionResult(version: "abcd", limits: limits)
        }

        let key = try testPublicKey()
        _ = try WalletListCertificatesRequest(
            certifiers: [key, key, key], types: [], limits: limits
        )
        #expect(throws: WalletABIError.self) {
            try WalletListCertificatesRequest(
                certifiers: [key, key, key, key], types: [], limits: limits
            )
        }

        _ = try WalletListOutputsRequest(basket: "b", tags: ["a", "b"], limits: limits)
        #expect(throws: WalletABIError.self) {
            try WalletListOutputsRequest(basket: "b", tags: ["a", "b", "c"], limits: limits)
        }
        _ = try WalletListActionsRequest(labels: ["a", "b"], limits: limits)
        #expect(throws: WalletABIError.self) {
            try WalletListActionsRequest(labels: ["a", "b", "c"], limits: limits)
        }

        _ = try WalletBase64Data([1, 2, 3], limits: limits)
        #expect(throws: WalletABIError.self) { try WalletBase64Data([1, 2, 3, 4], limits: limits) }

        let three = try WalletLinkageCiphertext([1, 2, 3], limits: limits)
        let two = try WalletLinkageCiphertext([4, 5], limits: limits)
        _ = try WalletRevealCounterpartyKeyLinkageResult(
            prover: key, counterparty: key, verifier: key, revelationTime: "now",
            encryptedLinkage: three, encryptedLinkageProof: two, limits: limits
        )
        #expect(throws: WalletABIError.self) {
            try WalletRevealCounterpartyKeyLinkageResult(
                prover: key, counterparty: key, verifier: key, revelationTime: "now",
                encryptedLinkage: three, encryptedLinkageProof: three, limits: limits
            )
        }

        #expect(throws: WalletABIError.invalidLimits) {
            try WalletABILimits(maximumTextUTF8ByteCount: -1)
        }
    }

    @Test("pagination and integer boundaries are preserved")
    func integerBoundaries() throws {
        let defaults = try WalletPagination()
        #expect(defaults.limit == nil)
        #expect(defaults.offset == nil)
        #expect(defaults.effectiveLimit == 10)
        #expect(defaults.effectiveOffset == 0)
        #expect(try WalletPagination(limit: 10_000, offset: .max).effectiveLimit == 10_000)
        #expect(throws: WalletABIError.invalidPaginationLimit(0)) { try WalletPagination(limit: 0) }
        #expect(throws: WalletABIError.invalidPaginationLimit(10_001)) {
            try WalletPagination(limit: 10_001)
        }

        let outpoint = testOutpoint(index: .max)
        #expect(outpoint.outputIndex == UInt32.max)
        let createOutput = try WalletCreateActionOutput(
            lockingScript: [], satoshis: .max, outputDescription: "x"
        )
        #expect(createOutput.satoshis == UInt64.max)
        let input = try WalletCreateActionInput(
            outpoint: outpoint,
            inputDescription: "x",
            unlockingScriptLength: .max,
            sequenceNumber: .max
        )
        #expect(input.sequenceNumber == UInt32.max)
        let reference = try WalletBase64Data([1])
        let spend = try WalletSignActionSpend(unlockingScript: [], sequenceNumber: .max)
        let signRequest = try WalletSignActionRequest(
            reference: reference,
            spends: [0: spend, UInt32.max: spend]
        )
        #expect(signRequest.spends[0]?.sequenceNumber == UInt32.max)
        #expect(signRequest.spends[UInt32.max]?.sequenceNumber == UInt32.max)
        let zeroIndex = WalletInternalizeOutput(
            outputIndex: 0,
            remittance: .basketInsertion(try WalletBasketInsertion(basket: "b"))
        )
        let maxIndex = WalletInternalizeOutput(
            outputIndex: .max,
            remittance: .basketInsertion(try WalletBasketInsertion(basket: "b"))
        )
        #expect(zeroIndex.outputIndex == 0)
        #expect(maxIndex.outputIndex == UInt32.max)

        let key = try testPublicKey()
        let linkage = try WalletLinkageCiphertext([])
        let protocolID = try WalletProtocolID(securityLevel: .silent, name: "tests")
        let keyID = try WalletKeyID("k")
        let linkageResult = try WalletRevealSpecificKeyLinkageResult(
            encryptedLinkage: linkage,
            encryptedLinkageProof: linkage,
            prover: key,
            verifier: key,
            counterparty: key,
            protocolID: protocolID,
            keyID: keyID,
            proofType: .max
        )
        #expect(linkageResult.proofType == UInt8.max)

        for satoshis in [Int64.min, Int64.max] {
            let action = try WalletAction(
                transactionID: outpoint.transactionID,
                satoshis: satoshis,
                status: .completed,
                isOutgoing: satoshis < 0,
                description: "x",
                version: .max,
                lockTime: .max
            )
            #expect(action.satoshis == satoshis)
        }
    }

    @Test("tagged unions reject every contradictory representation")
    func unionContradictions() throws {
        let outpoint = testOutpoint(index: 0)
        #expect(throws: WalletABIError.self) {
            try WalletCreateActionInput(
                outpoint: outpoint,
                inputDescription: "x",
                unlockingScript: [1],
                unlockingScriptLength: 1
            )
        }
        #expect(throws: WalletABIError.self) {
            try WalletCreateActionInput(outpoint: outpoint, inputDescription: "x")
        }

        let key = try testPublicKey()
        let payment = try WalletPaymentRemittance(
            derivationPrefix: WalletBase64Data([1]),
            derivationSuffix: WalletBase64Data([2]),
            senderIdentityKey: key
        )
        let insertion = try WalletBasketInsertion(basket: "b")
        #expect(throws: WalletABIError.self) {
            try WalletInternalizeOutput(
                outputIndex: 0, protocol: .walletPayment,
                paymentRemittance: payment, insertionRemittance: insertion
            )
        }
        #expect(throws: WalletABIError.self) {
            try WalletInternalizeOutput(outputIndex: 0, protocol: .walletPayment)
        }
        #expect(throws: WalletABIError.self) {
            try WalletInternalizeOutput(
                outputIndex: 0, protocol: .basketInsertion, paymentRemittance: payment
            )
        }
        #expect(throws: WalletABIError.self) {
            try WalletInternalizeOutput(
                outputIndex: 0, protocol: .walletPayment, insertionRemittance: insertion
            )
        }

        #expect(throws: WalletABIError.self) {
            try WalletKeyringRevealer(certifier: true, publicKey: key)
        }
        #expect(throws: WalletABIError.self) {
            try WalletKeyringRevealer(certifier: false, publicKey: nil)
        }
        #expect(try WalletKeyringRevealer(certifier: true, publicKey: nil) == .certifier)
        #expect(try WalletKeyringRevealer(certifier: false, publicKey: key) == .publicKey(key))

        let issuance = try WalletIssuanceCertificateAcquisition(certifierURL: "x")
        let mode = WalletCertificateAcquisition.issuance(issuance)
        #expect(mode.protocol == .issuance)
    }

    @Test("canonical Base64 is enforced and secret diagnostics are redacted")
    func redaction() throws {
        let value = try WalletBase64Data([1, 2, 3])
        #expect(value.base64 == "AQID")
        #expect(try WalletBase64Data(base64: "AQID") == value)
        #expect(throws: WalletABIError.invalidCanonicalBase64) {
            try WalletBase64Data(base64: "AQID\n")
        }
        let secret = try WalletLinkageCiphertext([111, 112, 113])
        #expect(secret.description == "<redacted linkage ciphertext>")
        #expect(secret.debugDescription == secret.description)
        #expect(Mirror(reflecting: secret).children.isEmpty)
        var output = StringOutput()
        dump(secret, to: &output)
        #expect(!output.value.contains("111"))
        #expect(!String(reflecting: secret).contains("111"))
    }

    @Test("accepted SDK value types are reused directly")
    func acceptedTypeReuse() throws {
        let key = try testPublicKey()
        let type = try CertificateTypeID(Array(repeating: 1, count: 32))
        let serial = try CertificateSerialNumber(Array(repeating: 2, count: 32))
        let field = try CertificateFieldName("name")
        let ciphertext = try CertificateCiphertext([3])
        let signature = try ECDSASignature(derBytes: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
        let outpoint = testOutpoint(index: .max)
        let certificate = try Certificate(
            type: type,
            serialNumber: serial,
            subject: key,
            certifier: key,
            revocationOutpoint: outpoint,
            fields: [field: ciphertext],
            signature: signature
        )
        acceptCertificate(certificate)
        acceptCertificateType(type)
        acceptSerial(serial)
        acceptField(field)
        acceptPublicKey(key)
        acceptSignature(signature)
        acceptTransactionID(outpoint.transactionID)
        acceptOutpoint(outpoint)

        let request = WalletRelinquishCertificateRequest(
            type: type, serialNumber: serial, certifier: key
        )
        #expect(request.type == type)
        #expect(request.serialNumber == serial)
        #expect(request.certifier == key)
    }

    @Test("safe request and result values have equality")
    func equality() throws {
        let pagination = try WalletPagination(limit: 10, offset: UInt32.max)
        #expect(pagination == pagination)
        let request = try WalletListActionsRequest(labels: ["a"], pagination: pagination)
        #expect(request == request)
        let result = WalletAbortActionResult(aborted: true)
        #expect(result == WalletAbortActionResult(aborted: true))
    }

    @Test("Sendable values cross task groups")
    func sendableAcrossTasks() async throws {
        let values = [
            WalletGetHeightResult(height: .max),
            WalletGetHeightResult(height: 0),
        ]
        let total = await withTaskGroup(of: UInt32.self, returning: UInt64.self) { group in
            for value in values { group.addTask { value.height } }
            var sum: UInt64 = 0
            for await value in group { sum += UInt64(value) }
            return sum
        }
        #expect(total == UInt64(UInt32.max))
    }

    @Test("small recording fakes conform to decomposed protocols")
    func protocolFakes() async throws {
        let chain = RecordingChainInformation()
        #expect(try await chain.getHeight(.init()).height == 42)
        #expect(try await chain.getNetwork(.init()).network == .testnet)
        #expect(await chain.calls == ["height", "network"])

        let authentication = RecordingAuthentication()
        #expect(try await authentication.isAuthenticated(.init()).authenticated == false)
        #expect(try await authentication.waitForAuthentication(.init()).authenticated == true)
        #expect(await authentication.calls == 2)
    }
}

private actor RecordingChainInformation: WalletChainInformation {
    var calls: [String] = []
    func getHeight(_ request: WalletGetHeightRequest) async throws -> WalletGetHeightResult {
        calls.append("height")
        return WalletGetHeightResult(height: 42)
    }
    func getHeaderForHeight(_ request: WalletGetHeaderRequest) async throws -> WalletGetHeaderResult {
        calls.append("header")
        return try WalletGetHeaderResult(header: Array(repeating: 0, count: 80))
    }
    func getNetwork(_ request: WalletGetNetworkRequest) async throws -> WalletGetNetworkResult {
        calls.append("network")
        return WalletGetNetworkResult(network: .testnet)
    }
    func getVersion(_ request: WalletGetVersionRequest) async throws -> WalletGetVersionResult {
        calls.append("version")
        return try WalletGetVersionResult(version: "1.0.0")
    }
}

private actor RecordingAuthentication: WalletAuthenticationOperations {
    var calls = 0
    func isAuthenticated(
        _ request: WalletIsAuthenticatedRequest
    ) async throws -> WalletAuthenticatedResult {
        calls += 1
        return WalletAuthenticatedResult(authenticated: false)
    }
    func waitForAuthentication(
        _ request: WalletWaitForAuthenticationRequest
    ) async throws -> WalletAuthenticatedResult {
        calls += 1
        return WalletAuthenticatedResult(authenticated: true)
    }
}

private struct StringOutput: TextOutputStream {
    var value = ""
    mutating func write(_ string: String) { value += string }
}

private func testPublicKey() throws -> PublicKey {
    try PrivateKey(Array(repeating: 0, count: 31) + [1]).publicKey
}

private func testOutpoint(index: UInt32) -> Outpoint {
    Outpoint(
        transactionID: try! TransactionID(wireBytes: Array(repeating: 7, count: 32)),
        outputIndex: index
    )
}

private func acceptCertificate(_: Certificate) {}
private func acceptCertificateType(_: CertificateTypeID) {}
private func acceptSerial(_: CertificateSerialNumber) {}
private func acceptField(_: CertificateFieldName) {}
private func acceptPublicKey(_: PublicKey) {}
private func acceptSignature(_: ECDSASignature) {}
private func acceptTransactionID(_: TransactionID) {}
private func acceptOutpoint(_: Outpoint) {}
