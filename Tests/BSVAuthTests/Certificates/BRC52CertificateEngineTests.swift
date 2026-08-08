import Foundation
import XCTest
import BSVAuth
import BSVCore
import BSVCrypto
import BSVKeys
import BSVTransaction
@testable import BSVWallet

private enum BRC52RandomFailure: Error { case failed }

private final class BRC52ScriptedRandomSource: SecureRandomSource, @unchecked Sendable {
    private let lock = NSLock()
    private var responses: [Result<[UInt8], Error>]
    private(set) var requestedCounts: [Int] = []

    init(_ responses: [Result<[UInt8], Error>]) { self.responses = responses }

    func randomBytes(count: Int) throws -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        requestedCounts.append(count)
        guard !responses.isEmpty else { throw BRC52RandomFailure.failed }
        return try responses.removeFirst().get()
    }
}

final class BRC52CertificateEngineTests: XCTestCase {
    func testDirectIssueAcquireAndVerifierProjectionRoundTrip() async throws {
        let certifierKey = try key(11)
        let subjectKey = try key(22)
        let verifierKey = try key(33)
        let certifierRandom = BRC52ScriptedRandomSource([
            .repeated(0xa1), .repeated(0xa2),
        ])
        let subjectRandom = BRC52ScriptedRandomSource([.repeated(0xb1)])
        let certifier = ProtoWallet(rootKey: certifierKey, randomSource: certifierRandom)
        let subject = ProtoWallet(rootKey: subjectKey, randomSource: subjectRandom)
        let verifier = ProtoWallet(rootKey: verifierKey)
        let engineRandom = BRC52ScriptedRandomSource([
            .repeated(0x11), .repeated(0x21),
            .repeated(0x12), .repeated(0x22),
        ])
        let name = try CertificateFieldName("name")
        let email = try CertificateFieldName("email")
        let type = try CertificateTypeID(repeating: 0x51)
        let serial = try CertificateSerialNumber(repeating: 0x61)

        let issued = try await CertificateEngine.issue(
            type: type,
            serialNumber: serial,
            subject: .publicKey(subjectKey.publicKey),
            plaintextFields: [name: "Ada", email: "ada@example.test"],
            using: certifier,
            randomSource: engineRandom
        )
        XCTAssertEqual(engineRandom.requestedCounts, [32, 32, 32, 32])
        XCTAssertEqual(certifierRandom.requestedCounts, [32, 32])
        XCTAssertEqual(issued.certificate.subject, subjectKey.publicKey)
        XCTAssertEqual(issued.certificate.certifier, certifierKey.publicKey)
        let signatureValid = try await issued.certificate.verifySignature()
        XCTAssertTrue(signatureValid)

        let acquired = try await CertificateEngine.acquire(
            issued,
            requirements: .init(type: type, serialNumber: serial, certifier: certifierKey.publicKey),
            using: subject
        )
        XCTAssertEqual(acquired.plaintextFields, [name: "Ada", email: "ada@example.test"])

        let projected = try await CertificateEngine.project(
            issued,
            fields: [email],
            to: verifierKey.publicKey,
            using: subject
        )
        XCTAssertEqual(Set(projected.keyring.entries.keys), [email])
        XCTAssertNil(projected.keyring.entries[name])
        let verifiedFields = try await CertificateEngine.verify(projected, using: verifier)
        XCTAssertEqual(verifiedFields, [email: "ada@example.test"])
        XCTAssertEqual(subjectRandom.requestedCounts, [32])
    }

    func testSelfSignedCounterpartyRoundTrip() async throws {
        let identity = try key(44)
        let walletRandom = BRC52ScriptedRandomSource([.repeated(0xc1)])
        let wallet = ProtoWallet(rootKey: identity, randomSource: walletRandom)
        let engineRandom = BRC52ScriptedRandomSource([
            .repeated(0xd1), .repeated(0xd2),
        ])
        let field = try CertificateFieldName("self")
        let issued = try await CertificateEngine.issue(
            type: CertificateTypeID(repeating: 7),
            serialNumber: CertificateSerialNumber(repeating: 8),
            subject: .self,
            plaintextFields: [field: "signed by me"],
            using: wallet,
            randomSource: engineRandom
        )
        XCTAssertEqual(issued.certificate.subject, issued.certificate.certifier)
        let acquired = try await CertificateEngine.acquire(issued, using: wallet)
        XCTAssertEqual(acquired.plaintextFields[field], "signed by me")
    }

    func testTamperingWrongIdentitiesExpectationsAndAllOrNothingDecryptionFail() async throws {
        let setup = try await makeIssued()
        let wrongSubject = ProtoWallet(rootKey: try key(99))
        await XCTAssertCertificateErrorAsync(.walletIdentityMismatch) {
            _ = try await CertificateEngine.acquire(setup.master, using: wrongSubject)
        }
        await XCTAssertCertificateErrorAsync(.requirementMismatch) {
            _ = try await CertificateEngine.acquire(
                setup.master,
                requirements: .init(type: try CertificateTypeID(repeating: 0xee)),
                using: setup.subject
            )
        }

        var tamperedEntries = setup.master.masterKeyring.entries
        let first = try XCTUnwrap(tamperedEntries[setup.first])
        var bytes = first.bytes
        bytes[bytes.count - 1] ^= 1
        tamperedEntries[setup.first] = try CertificateCiphertext(bytes)
        let tampered = try MasterCertificate(
            certificate: setup.master.certificate,
            masterKeyring: CertificateKeyring(tamperedEntries)
        )
        await XCTAssertCertificateErrorAsync(.decryptionFailed) {
            _ = try await CertificateEngine.acquire(tampered, using: setup.subject)
        }
    }

    func testEveryAcquisitionRequirementMismatchHasItsOwnExactError() async throws {
        let setup = try await makeIssued()
        let certificate = setup.master.certificate
        let wrongOutpoint = Outpoint(
            transactionID: try TransactionID(wireBytes: [UInt8](repeating: 9, count: 32)),
            outputIndex: 4
        )
        let requirements: [CertificateAcquisitionRequirements] = [
            .init(type: try CertificateTypeID(repeating: 0xee)),
            .init(serialNumber: try CertificateSerialNumber(repeating: 0xee)),
            .init(certifier: try key(99).publicKey),
            .init(revocationOutpoint: wrongOutpoint),
        ]
        for requirement in requirements {
            await XCTAssertCertificateErrorAsync(.requirementMismatch) {
                _ = try await CertificateEngine.acquire(
                    setup.master,
                    requirements: requirement,
                    using: setup.subject
                )
            }
        }
        let matching = CertificateAcquisitionRequirements(
            type: certificate.type,
            serialNumber: certificate.serialNumber,
            certifier: certificate.certifier,
            revocationOutpoint: certificate.revocationOutpoint
        )
        _ = try await CertificateEngine.acquire(
            setup.master,
            requirements: matching,
            using: setup.subject
        )
    }

    func testIdentityMismatchDoesNotSignAndAnyoneIssuanceDoesNoCrypto() async throws {
        let wrongSigner = BRC52RecordingWallet(ProtoWallet(rootKey: try key(99)))
        let unsigned = try Certificate(
            type: CertificateTypeID(repeating: 1),
            serialNumber: CertificateSerialNumber(repeating: 2),
            subject: try key(22).publicKey,
            certifier: try key(11).publicKey,
            revocationOutpoint: CertificateEngine.disabledRevocationOutpoint,
            fields: [:]
        )
        await XCTAssertCertificateErrorAsync(.walletIdentityMismatch) {
            _ = try await unsigned.signed(using: wrongSigner)
        }
        XCTAssertEqual(wrongSigner.createSignatureRequests.count, 0)

        let issuer = BRC52RecordingWallet(ProtoWallet(rootKey: try key(11)))
        await XCTAssertCertificateErrorAsync(.walletIdentityMismatch) {
            _ = try await CertificateEngine.issue(
                type: try CertificateTypeID(repeating: 1),
                serialNumber: try CertificateSerialNumber(repeating: 2),
                subject: .anyone,
                plaintextFields: [try CertificateFieldName("field"): "value"],
                using: issuer
            )
        }
        XCTAssertTrue(issuer.encryptRequests.isEmpty)
        XCTAssertTrue(issuer.createSignatureRequests.isEmpty)
    }

    func testSwappedFieldKeysAndWrongVerifierFailExactly() async throws {
        let setup = try await makeIssued()
        let fields = setup.master.masterKeyring.entries.keys.sorted()
        XCTAssertEqual(fields.count, 2)
        var swappedEntries = setup.master.masterKeyring.entries
        let firstValue = try XCTUnwrap(swappedEntries[fields[0]])
        swappedEntries[fields[0]] = try XCTUnwrap(swappedEntries[fields[1]])
        swappedEntries[fields[1]] = firstValue
        let swapped = try MasterCertificate(
            certificate: setup.master.certificate,
            masterKeyring: CertificateKeyring(swappedEntries)
        )
        await XCTAssertCertificateErrorAsync(.decryptionFailed) {
            _ = try await CertificateEngine.acquire(swapped, using: setup.subject)
        }

        let verifierKey = try key(33)
        let projected = try await CertificateEngine.project(
            setup.master,
            fields: fields,
            to: verifierKey.publicKey,
            using: setup.subject
        )
        await XCTAssertCertificateErrorAsync(.decryptionFailed) {
            _ = try await CertificateEngine.verify(
                projected,
                using: ProtoWallet(rootKey: try key(34))
            )
        }
    }

    func testCorruptFinalRequestedKeyCausesZeroVerifierWrappingCalls() async throws {
        let setup = try await makeIssued()
        let requested = setup.master.masterKeyring.entries.keys.sorted()
        var entries = setup.master.masterKeyring.entries
        var corrupt = try XCTUnwrap(entries[requested.last!]).bytes
        corrupt[corrupt.count - 1] ^= 1
        entries[requested.last!] = try CertificateCiphertext(corrupt)
        let corrupted = try MasterCertificate(
            certificate: setup.master.certificate,
            masterKeyring: CertificateKeyring(entries)
        )
        let subject = BRC52RecordingWallet(ProtoWallet(rootKey: try key(22)))
        await XCTAssertCertificateErrorAsync(.decryptionFailed) {
            _ = try await CertificateEngine.project(
                corrupted,
                fields: requested,
                to: try key(33).publicKey,
                using: subject
            )
        }
        XCTAssertEqual(subject.decryptRequests.count, 2)
        XCTAssertEqual(subject.encryptRequests.count, 0)
    }

    func testExactBRC52CryptoRolesAndKeyIDs() async throws {
        let certifierKey = try key(11)
        let subjectKey = try key(22)
        let verifierKey = try key(33)
        let certifier = BRC52RecordingWallet(ProtoWallet(
            rootKey: certifierKey,
            randomSource: BRC52ScriptedRandomSource([.repeated(0x71), .repeated(0x72)])
        ))
        let field = try CertificateFieldName("field")
        let type = try CertificateTypeID(repeating: 1)
        let serial = try CertificateSerialNumber(repeating: 2)
        let master = try await CertificateEngine.issue(
            type: type,
            serialNumber: serial,
            subject: .publicKey(subjectKey.publicKey),
            plaintextFields: [field: "value"],
            using: certifier,
            randomSource: BRC52ScriptedRandomSource([.repeated(0x31), .repeated(0x41)])
        )
        XCTAssertEqual(certifier.encryptRequests.count, 1)
        XCTAssertEqual(certifier.encryptRequests[0].protocolID, try CertificateProtocols.fieldEncryption)
        XCTAssertEqual(certifier.encryptRequests[0].keyID, try CertificateProtocols.masterFieldKeyID(field))
        XCTAssertEqual(certifier.encryptRequests[0].counterparty, .publicKey(subjectKey.publicKey))
        XCTAssertEqual(certifier.createSignatureRequests.count, 1)
        XCTAssertEqual(certifier.createSignatureRequests[0].protocolID, try CertificateProtocols.signature)
        XCTAssertEqual(certifier.createSignatureRequests[0].keyID, try WalletKeyID(type.base64 + " " + serial.base64))
        XCTAssertEqual(certifier.createSignatureRequests[0].counterparty, .anyone)
        switch certifier.createSignatureRequests[0].payload {
        case .digest(let digest):
            XCTAssertEqual(
                digest,
                BSVHashing.sha256(try master.certificate.binary(includingSignature: false))
            )
        case .data:
            XCTFail("certificate signing must use the equivalent bounded direct digest")
        }

        let subject = BRC52RecordingWallet(ProtoWallet(rootKey: subjectKey))
        _ = try await CertificateEngine.acquire(master, using: subject)
        XCTAssertEqual(subject.decryptRequests.count, 1)
        XCTAssertEqual(subject.decryptRequests[0].protocolID, try CertificateProtocols.fieldEncryption)
        XCTAssertEqual(subject.decryptRequests[0].keyID, try CertificateProtocols.masterFieldKeyID(field))
        XCTAssertEqual(subject.decryptRequests[0].counterparty, .publicKey(certifierKey.publicKey))

        let projected = try await CertificateEngine.project(
            master,
            fields: [field],
            to: verifierKey.publicKey,
            using: subject
        )
        XCTAssertEqual(subject.encryptRequests.count, 1)
        XCTAssertEqual(subject.encryptRequests[0].protocolID, try CertificateProtocols.fieldEncryption)
        XCTAssertEqual(
            subject.encryptRequests[0].keyID,
            try CertificateProtocols.verifierFieldKeyID(serialNumber: serial, field: field)
        )
        XCTAssertEqual(subject.encryptRequests[0].counterparty, .publicKey(verifierKey.publicKey))

        let verifier = BRC52RecordingWallet(ProtoWallet(rootKey: verifierKey))
        _ = try await CertificateEngine.verify(projected, using: verifier)
        XCTAssertEqual(verifier.decryptRequests.count, 1)
        XCTAssertEqual(
            verifier.decryptRequests[0].keyID,
            try CertificateProtocols.verifierFieldKeyID(serialNumber: serial, field: field)
        )
        XCTAssertEqual(verifier.decryptRequests[0].counterparty, .publicKey(subjectKey.publicKey))
    }

    func testLimitsKeyringEqualityAndRandomFailures() async throws {
        let field = try CertificateFieldName("field")
        let certifier = ProtoWallet(rootKey: try key(11))
        let failing = BRC52ScriptedRandomSource([.failure(BRC52RandomFailure.failed)])
        await XCTAssertThrowsErrorAsync {
            _ = try await CertificateEngine.issue(
                type: try CertificateTypeID(repeating: 1),
                serialNumber: try CertificateSerialNumber(repeating: 2),
                subject: .self,
                plaintextFields: [field: "value"],
                using: certifier,
                randomSource: failing
            )
        }
        let wrongLength = BRC52ScriptedRandomSource([.success([1])])
        await XCTAssertThrowsErrorAsync {
            _ = try await CertificateEngine.issue(
                type: try CertificateTypeID(repeating: 1),
                serialNumber: try CertificateSerialNumber(repeating: 2),
                subject: .self,
                plaintextFields: [field: "value"],
                using: certifier,
                randomSource: wrongLength
            )
        }

        let setup = try await makeIssued()
        XCTAssertThrowsError(try MasterCertificate(
            certificate: setup.master.certificate,
            masterKeyring: CertificateKeyring([:])
        ))
        let tiny = try CertificateLimits(maximumFieldCount: 1, maximumFieldPlaintextByteCount: 2)
        let exact = try await CertificateEngine.issue(
            type: CertificateTypeID(repeating: 1),
            serialNumber: CertificateSerialNumber(repeating: 2),
            subject: .self,
            plaintextFields: [field: "ok"],
            using: certifier,
            limits: tiny
        )
        XCTAssertEqual(exact.certificate.fields.count, 1)
        await XCTAssertCertificateErrorAsync(.fieldValueTooLarge(actual: 3, maximum: 2)) {
            _ = try await CertificateEngine.issue(
                type: try CertificateTypeID(repeating: 1),
                serialNumber: try CertificateSerialNumber(repeating: 2),
                subject: .self,
                plaintextFields: [field: "bad"],
                using: certifier,
                limits: tiny
            )
        }
        await XCTAssertCertificateErrorAsync(.tooManyFields(actual: 2, maximum: 1)) {
            _ = try await CertificateEngine.issue(
                type: try CertificateTypeID(repeating: 1),
                serialNumber: try CertificateSerialNumber(repeating: 2),
                subject: .self,
                plaintextFields: [
                    field: "ok",
                    try CertificateFieldName("second"): "ok",
                ],
                using: certifier,
                limits: tiny
            )
        }
    }

    func testCertificateValuesAreSendableAndRedactionDoesNotExposePlaintext() async throws {
        func requireSendable<T: Sendable>(_: T.Type) {}
        requireSendable(Certificate.self)
        requireSendable(MasterCertificate.self)
        requireSendable(VerifiableCertificate.self)
        requireSendable(AcquiredCertificate.self)
        let setup = try await makeIssued()
        let acquired = try await CertificateEngine.acquire(setup.master, using: setup.subject)
        for value in [setup.master as Any, acquired as Any] {
            XCTAssertFalse(String(reflecting: value).contains("first-value"))
            var dumped = ""
            dump(value, to: &dumped)
            XCTAssertFalse(dumped.contains("first-value"))
            XCTAssertTrue(Mirror(reflecting: value).children.isEmpty)
        }

        let result = try await withThrowingTaskGroup(of: Bool.self) { group in
            for _ in 0..<8 {
                group.addTask { try await setup.master.certificate.verifySignature() }
            }
            var valid = true
            for try await item in group { valid = valid && item }
            return valid
        }
        XCTAssertTrue(result)
    }

    private func makeIssued() async throws -> (
        master: MasterCertificate,
        subject: ProtoWallet,
        first: CertificateFieldName
    ) {
        let certifierKey = try key(11)
        let subjectKey = try key(22)
        let certifier = ProtoWallet(
            rootKey: certifierKey,
            randomSource: BRC52ScriptedRandomSource([
                .repeated(0x71), .repeated(0x72),
            ])
        )
        let subject = ProtoWallet(rootKey: subjectKey)
        let first = try CertificateFieldName("first")
        let second = try CertificateFieldName("second")
        let master = try await CertificateEngine.issue(
            type: CertificateTypeID(repeating: 4),
            serialNumber: CertificateSerialNumber(repeating: 5),
            subject: .publicKey(subjectKey.publicKey),
            plaintextFields: [first: "first-value", second: "second-value"],
            using: certifier,
            randomSource: BRC52ScriptedRandomSource([
                .repeated(0x31), .repeated(0x41),
                .repeated(0x32), .repeated(0x42),
            ])
        )
        return (master, subject, first)
    }

    private func key(_ scalar: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [scalar])
    }
}

private extension CertificateTypeID {
    init(repeating byte: UInt8) throws { try self.init([UInt8](repeating: byte, count: 32)) }
}

private extension CertificateSerialNumber {
    init(repeating byte: UInt8) throws { try self.init([UInt8](repeating: byte, count: 32)) }
}

private extension Result where Success == [UInt8], Failure == Error {
    static func repeated(_ byte: UInt8) -> Self {
        .success([UInt8](repeating: byte, count: 32))
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
    } catch {}
}

private func XCTAssertCertificateErrorAsync<T>(
    _ expected: CertificateError,
    _ expression: () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected \(expected)", file: file, line: line)
    } catch {
        XCTAssertEqual(error as? CertificateError, expected, file: file, line: line)
    }
}

private final class BRC52RecordingWallet: CertificateWallet, @unchecked Sendable {
    private let wallet: ProtoWallet
    private let lock = NSLock()
    private var storedEncryptRequests: [WalletEncryptRequest] = []
    private var storedDecryptRequests: [WalletDecryptRequest] = []
    private var storedCreateSignatureRequests: [WalletCreateSignatureRequest] = []

    init(_ wallet: ProtoWallet) {
        self.wallet = wallet
    }

    var encryptRequests: [WalletEncryptRequest] { withLock { storedEncryptRequests } }
    var decryptRequests: [WalletDecryptRequest] { withLock { storedDecryptRequests } }
    var createSignatureRequests: [WalletCreateSignatureRequest] {
        withLock { storedCreateSignatureRequests }
    }

    func getPublicKey(_ request: WalletGetPublicKeyRequest) async throws -> WalletGetPublicKeyResult {
        try await wallet.getPublicKey(request)
    }

    func encrypt(_ request: WalletEncryptRequest) async throws -> WalletEncryptResult {
        recordEncrypt(request)
        return try await wallet.encrypt(request)
    }

    func decrypt(_ request: WalletDecryptRequest) async throws -> WalletDecryptResult {
        recordDecrypt(request)
        return try await wallet.decrypt(request)
    }

    func createSignature(_ request: WalletCreateSignatureRequest) async throws -> WalletCreateSignatureResult {
        recordCreateSignature(request)
        return try await wallet.createSignature(request)
    }

    func verifySignature(_ request: WalletVerifySignatureRequest) async throws -> WalletVerifySignatureResult {
        try await wallet.verifySignature(request)
    }

    private func recordEncrypt(_ request: WalletEncryptRequest) {
        lock.lock()
        storedEncryptRequests.append(request)
        lock.unlock()
    }

    private func recordDecrypt(_ request: WalletDecryptRequest) {
        lock.lock()
        storedDecryptRequests.append(request)
        lock.unlock()
    }

    private func recordCreateSignature(_ request: WalletCreateSignatureRequest) {
        lock.lock()
        storedCreateSignatureRequests.append(request)
        lock.unlock()
    }

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
