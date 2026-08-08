import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVTransaction
import BSVWallet
import Testing

@Suite("Wallet-backed PushDrop")
struct WalletPushDropTests {
    @Test("Alice can create a BRC-42 lock that Bob can spend")
    func crossPartyDirection() async throws {
        let aliceKey = try privateKey(42)
        let bobKey = try privateKey(69)
        let alice = ProtoWallet(rootKey: aliceKey)
        let bob = ProtoWallet(rootKey: bobKey)
        let protocolID = try testProtocol()
        let keyID = try WalletKeyID("cross-party token")

        let script = try await PushDrop.lockingScript(
            fields: [[0xaa], [0xbb]],
            using: alice,
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(bobKey.publicKey),
            forSelf: false
        )
        let decoded = try PushDrop.decode(script)
        let bobSpendingKey = try await bob.getPublicKey(.init(selection: .derived(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(aliceKey.publicKey),
            forSelf: true
        ))).publicKey

        #expect(decoded.publicKey == bobSpendingKey)
        var transaction = try unsignedTransaction(lockingScript: script)
        try await transaction.signPushDropInput(
            at: 0,
            using: bob,
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(aliceKey.publicKey),
            limits: transactionLimits
        )
        #expect(!transaction.inputs[0].unlockingScript.isEmpty)
    }

    @Test("lock requests preserve wallet arguments and use delimiter-free field data")
    func lockingRequestsAndCanonicalFields() async throws {
        let key = try privateKey(1)
        let protocolID = try testProtocol()
        let keyID = try WalletKeyID("signed fields")
        let counterparty = WalletCounterparty.publicKey(try privateKey(2).publicKey)
        let access = try WalletKeyAccess(
            privileged: true,
            privilegedReason: "pushdrop test",
            seekPermission: true
        )
        let fields: [[UInt8]] = [
            [], [0], [1], [16], [0x81],
            [UInt8](repeating: 0x4b, count: 75),
            [UInt8](repeating: 0x4c, count: 76),
            [UInt8](repeating: 0xff, count: 255),
            [UInt8](repeating: 0xee, count: 256),
        ]
        let expectedData = fields.reduce(into: [UInt8]()) {
            $0.append(contentsOf: $1)
        }
        let wallet = RecordingWallet(publicKey: key.publicKey, signingKey: key)

        let script = try await PushDrop.lockingScript(
            fields: fields,
            using: wallet,
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            forSelf: true,
            includeSignature: true,
            lockPosition: .beforeCompatibility,
            access: access
        )
        let decoded = try PushDrop.decode(script, lockPosition: .beforeCompatibility)
        #expect(
            Array(decoded.fields.dropLast())
                == [[0], [0], [1], [16], [0x81]] + Array(fields.dropFirst(5))
        )
        #expect(try ECDSASignature(derBytes: decoded.fields.last ?? []).derBytes == decoded.fields.last)

        let requests = await wallet.requests()
        #expect(requests.publicKeys.count == 1)
        #expect(requests.publicKeys[0].selection == .derived(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            forSelf: true
        ))
        #expect(requests.publicKeys[0].access == access)
        #expect(requests.signatures.count == 1)
        #expect(requests.signatures[0].protocolID == protocolID)
        #expect(requests.signatures[0].keyID == keyID)
        #expect(requests.signatures[0].counterparty == counterparty)
        #expect(requests.signatures[0].payload == .data(expectedData))
        #expect(requests.signatures[0].access == access)
    }

    @Test("unsigned locks support both layouts and skip signing", arguments: [
        PushDropLockPosition.after,
        PushDropLockPosition.beforeCompatibility,
    ])
    func unsignedLayouts(lockPosition: PushDropLockPosition) async throws {
        let key = try privateKey(1)
        let wallet = RecordingWallet(publicKey: key.publicKey, signingKey: key)
        let fields: [[UInt8]] = [[0], [1], [0x81], [UInt8](repeating: 7, count: 76)]
        let script = try await PushDrop.lockingScript(
            fields: fields,
            using: wallet,
            protocolID: try testProtocol(),
            keyID: try WalletKeyID("unsigned fields"),
            counterparty: .self,
            lockPosition: lockPosition
        )

        #expect(try PushDrop.decode(script, lockPosition: lockPosition).fields == fields)
        let requests = await wallet.requests()
        #expect(requests.signatures.isEmpty)
    }

    @Test("unsigned locking needs only public-key capability")
    func leastCapabilityUnsignedLock() async throws {
        let key = try privateKey(1)
        let wallet = PublicKeyOnlyWallet(publicKey: key.publicKey)
        let script = try await PushDrop.lockingScript(
            fields: [[1], [2]],
            using: wallet,
            protocolID: try testProtocol(),
            keyID: try WalletKeyID("public key only"),
            counterparty: .self
        )

        #expect(try PushDrop.decode(script).publicKey == key.publicKey)
    }

    @Test("lock preflight fails before wallet capabilities run")
    func lockPreflight() async throws {
        let key = try privateKey(1)
        let wallet = RecordingWallet(publicKey: key.publicKey, signingKey: key)
        let limits = try PushDropLimits(
            maximumFieldCount: 1,
            maximumFieldByteCount: 1,
            maximumScriptByteCount: 100
        )
        await #expect(throws: PushDropError.fieldCountExceedsLimit(actual: 2, maximum: 1)) {
            try await PushDrop.lockingScript(
                fields: [[1], [2]],
                using: wallet,
                protocolID: testProtocol(),
                keyID: WalletKeyID("preflight"),
                counterparty: .self,
                limits: limits
            )
        }
        let requests = await wallet.requests()
        #expect(requests.publicKeys.isEmpty)
        #expect(requests.signatures.isEmpty)
    }

    @Test("signed lock counts its signature field before wallet calls")
    func signedLockFieldCountPreflight() async throws {
        let key = try privateKey(1)
        let wallet = RecordingWallet(publicKey: key.publicKey, signingKey: key)
        let limits = try PushDropLimits(
            maximumFieldCount: 1,
            maximumFieldByteCount: 100,
            maximumScriptByteCount: 1_000
        )

        await #expect(throws: PushDropError.fieldCountExceedsLimit(
            actual: 2,
            maximum: 1
        )) {
            try await PushDrop.lockingScript(
                fields: [[1]],
                using: wallet,
                protocolID: testProtocol(),
                keyID: WalletKeyID("signed preflight"),
                counterparty: .self,
                includeSignature: true,
                limits: limits
            )
        }
        let requests = await wallet.requests()
        #expect(requests.publicKeys.isEmpty)
        #expect(requests.signatures.isEmpty)
    }

    @Test("all six ForkID flags map to digest requests")
    func allHashTypes() async throws {
        let key = try privateKey(1)
        let protocolID = try testProtocol()
        let keyID = try WalletKeyID("six forkid modes")
        let script = try PushDrop.lockingScript(fields: [[1]], publicKey: key.publicKey)
        let access = try WalletKeyAccess(
            privileged: true,
            privilegedReason: "sign pushdrop input",
            seekPermission: true
        )

        for rawValue in [UInt8(0x41), 0x42, 0x43, 0xc1, 0xc2, 0xc3] {
            let hashType = try ForkIDSignatureHashType(rawValue: rawValue)
            var transaction = try unsignedTransaction(lockingScript: script)
            let digest = try transaction.forkIDSignatureHash(
                inputIndex: 0,
                hashType: hashType,
                limits: transactionLimits
            )
            let wallet = RecordingWallet(publicKey: key.publicKey, signingKey: key)
            try await transaction.signPushDropInput(
                at: 0,
                using: wallet,
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .self,
                hashType: hashType,
                access: access,
                limits: transactionLimits
            )

            let requests = await wallet.requests()
            #expect(requests.signatures.count == 1)
            #expect(requests.signatures[0].payload == .digest(digest))
            #expect(requests.signatures[0].protocolID == protocolID)
            #expect(requests.signatures[0].keyID == keyID)
            #expect(requests.signatures[0].counterparty == .self)
            #expect(requests.signatures[0].access == access)
            let pushed = try #require(transaction.inputs[0].unlockingScript.operations(
                maximumPushDataByteCount: 80
            ).first?.pushedData)
            #expect(pushed.last == rawValue)
        }
    }

    @Test("wrong, high-S, and digest-mismatch signatures are rejected atomically", arguments: [
        SignatureMode.wrongKey,
        SignatureMode.highS,
        SignatureMode.wrongDigest,
    ])
    func signatureMismatch(mode: SignatureMode) async throws {
        let key = try privateKey(1)
        let script = try PushDrop.lockingScript(fields: [[1]], publicKey: key.publicKey)
        var transaction = try unsignedTransaction(lockingScript: script)
        let before = transaction
        let wallet = RecordingWallet(
            publicKey: key.publicKey,
            signingKey: key,
            signatureMode: mode
        )

        await #expect(throws: WalletPushDropError.signatureDoesNotMatchLockingPublicKey(
            inputIndex: 0
        )) {
            try await transaction.signPushDropInput(
                at: 0,
                using: wallet,
                protocolID: testProtocol(),
                keyID: WalletKeyID("mismatch"),
                counterparty: .self,
                limits: transactionLimits
            )
        }
        #expect(transaction == before)
        #expect(transaction.inputs[0].unlockingScript.isEmpty)
    }

    @Test("wallet failures and cancellation do not mutate the transaction", arguments: [
        SignatureMode.failure,
        SignatureMode.cancellation,
    ])
    func walletFailure(mode: SignatureMode) async throws {
        let key = try privateKey(1)
        let script = try PushDrop.lockingScript(fields: [[1]], publicKey: key.publicKey)
        var transaction = try unsignedTransaction(lockingScript: script)
        let before = transaction
        let wallet = RecordingWallet(
            publicKey: key.publicKey,
            signingKey: key,
            signatureMode: mode
        )

        await #expect(throws: Error.self) {
            try await transaction.signPushDropInput(
                at: 0,
                using: wallet,
                protocolID: testProtocol(),
                keyID: WalletKeyID("wallet failure"),
                counterparty: .self,
                limits: transactionLimits
            )
        }
        #expect(transaction == before)
        #expect(transaction.inputs[0].unlockingScript.isEmpty)
    }

    @Test("a non-cooperative wallet cannot mutate after task cancellation")
    func cancellationAfterWalletReturnIsAtomic() async throws {
        let key = try privateKey(1)
        let script = try PushDrop.lockingScript(fields: [[1]], publicKey: key.publicKey)
        let original = try unsignedTransaction(lockingScript: script)
        let box = TransactionBox(transaction: original)
        let wallet = NonCooperativeSigningWallet(signingKey: key)
        let protocolID = try testProtocol()
        let keyID = try WalletKeyID("cancel after return")

        let task = Task {
            try await box.signPushDropInput(
                using: wallet,
                protocolID: protocolID,
                keyID: keyID,
                limits: transactionLimits
            )
        }
        await wallet.waitUntilCreateSignatureCalled()
        task.cancel()
        await wallet.releaseSignature()

        await #expect(throws: CancellationError.self) {
            try await task.value
        }
        #expect(await box.value() == original)
        #expect((await box.value()).inputs[0].unlockingScript.isEmpty)
    }

    @Test("pre-cancelled locking does not call the wallet")
    func preCancelledLockAvoidsWalletCall() async throws {
        let key = try privateKey(1)
        let wallet = RecordingWallet(publicKey: key.publicKey, signingKey: key)
        let gate = AsyncGate()
        let protocolID = try testProtocol()
        let keyID = try WalletKeyID("pre cancelled")
        let task = Task {
            await gate.wait()
            return try await PushDrop.lockingScript(
                fields: [[1]],
                using: wallet,
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .self
            )
        }
        task.cancel()
        await gate.open()

        await #expect(throws: CancellationError.self) {
            try await task.value
        }
        let requests = await wallet.requests()
        #expect(requests.publicKeys.isEmpty)
        #expect(requests.signatures.isEmpty)
    }

    @Test("a maximum accepted DER signature uses the full 73-byte estimate")
    func maximumDERProjection() async throws {
        let key = try privateKey(1)
        let script = try PushDrop.lockingScript(fields: [[1]], publicKey: key.publicKey)
        var transaction = try unsignedTransaction(lockingScript: script)
        var found = false
        for lockTime in UInt32(0)..<512 {
            transaction.lockTime = lockTime
            let digest = try transaction.forkIDSignatureHash(
                inputIndex: 0,
                limits: transactionLimits
            )
            if try key.sign(digest: digest).derBytes.count == 71 {
                found = true
                break
            }
        }
        #expect(found)

        let wallet = RecordingWallet(publicKey: key.publicKey, signingKey: key)
        try await transaction.signPushDropInput(
            at: 0,
            using: wallet,
            protocolID: testProtocol(),
            keyID: WalletKeyID("maximum der"),
            counterparty: .self,
            limits: transactionLimits
        )
        #expect(
            transaction.inputs[0].unlockingScript.byteCount
                == TransactionInput.pushDropUnlockingScriptByteCount
        )
    }

    @Test("local validation and candidate-limit failures are atomic")
    func localFailures() async throws {
        let key = try privateKey(1)
        let script = try PushDrop.lockingScript(fields: [[1]], publicKey: key.publicKey)
        let wallet = RecordingWallet(publicKey: key.publicKey, signingKey: key)
        var transaction = try unsignedTransaction(lockingScript: script)
        let original = transaction

        await #expect(throws: TransactionError.invalidInputIndex(-1)) {
            try await transaction.signPushDropInput(
                at: -1,
                using: wallet,
                protocolID: testProtocol(),
                keyID: WalletKeyID("local failure"),
                counterparty: .self,
                limits: transactionLimits
            )
        }
        #expect(transaction == original)
        #expect(await wallet.requests().signatures.isEmpty)

        let unsignedByteCount = try transaction.serializedByteCount(
            limits: transactionLimits
        )
        let guaranteedTooSmall = try TransactionLimits(
            maximumTransactionByteCount: unsignedByteCount + 9,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )
        await #expect(throws: TransactionError.self) {
            try await transaction.signPushDropInput(
                at: 0,
                using: wallet,
                protocolID: testProtocol(),
                keyID: WalletKeyID("local failure"),
                counterparty: .self,
                limits: guaranteedTooSmall
            )
        }
        #expect(transaction == original)
        #expect(await wallet.requests().signatures.isEmpty)

        let tightLimits = try TransactionLimits(
            maximumTransactionByteCount: 100,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )
        await #expect(throws: TransactionError.self) {
            try await transaction.signPushDropInput(
                at: 0,
                using: wallet,
                protocolID: testProtocol(),
                keyID: WalletKeyID("local failure"),
                counterparty: .self,
                limits: tightLimits
            )
        }
        #expect(transaction == original)
        #expect(transaction.inputs[0].unlockingScript.isEmpty)
    }

    private let transactionLimits = try! TransactionLimits(
        maximumTransactionByteCount: 100_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 100_000
    )

    private func privateKey(_ value: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [value])
    }

    private func testProtocol() throws -> WalletProtocolID {
        try WalletProtocolID(securityLevel: .silent, name: "pushdrop tests")
    }

    private func unsignedTransaction(lockingScript: Script) throws -> Transaction {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        return Transaction(
            inputs: [TransactionInput(
                previousOutput: try Outpoint(
                    transactionID: TransactionID(
                        wireBytes: [UInt8](repeating: 0x11, count: 32)
                    ),
                    outputIndex: 0
                ),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(
                    satoshis: 10_000,
                    lockingScript: lockingScript
                )
            )],
            outputs: [TransactionOutput(satoshis: 9_000, lockingScript: empty)]
        )
    }
}

enum SignatureMode: Equatable, Sendable {
    case correct
    case wrongKey
    case highS
    case wrongDigest
    case failure
    case cancellation
}

private struct PublicKeyOnlyWallet: WalletPublicKeyProviding {
    let publicKey: PublicKey

    func getPublicKey(
        _ request: WalletGetPublicKeyRequest
    ) async throws -> WalletGetPublicKeyResult {
        WalletGetPublicKeyResult(publicKey: publicKey)
    }
}

private actor AsyncGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func open() {
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        for continuation in pending {
            continuation.resume()
        }
    }
}

private actor TransactionBox {
    private var transaction: Transaction

    init(transaction: Transaction) {
        self.transaction = transaction
    }

    func signPushDropInput(
        using wallet: any WalletSignatureOperations,
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        limits: TransactionLimits
    ) async throws {
        var candidate = transaction
        try await candidate.signPushDropInput(
            at: 0,
            using: wallet,
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .self,
            limits: limits
        )
        transaction = candidate
    }

    func value() -> Transaction {
        transaction
    }
}

private actor NonCooperativeSigningWallet: WalletSignatureOperations {
    private let signingKey: PrivateKey
    private var createSignatureCalled = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var pendingResult: WalletCreateSignatureResult?
    private var signatureContinuation:
        CheckedContinuation<WalletCreateSignatureResult, Never>?

    init(signingKey: PrivateKey) {
        self.signingKey = signingKey
    }

    func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        let digest: Hash256
        switch request.payload {
        case .data(let data):
            digest = BSVHashing.sha256(data)
        case .digest(let value):
            digest = value
        }
        pendingResult = WalletCreateSignatureResult(
            signature: try signingKey.sign(digest: digest)
        )
        createSignatureCalled = true
        let waiters = startWaiters
        startWaiters.removeAll()
        for continuation in waiters {
            continuation.resume()
        }
        return await withCheckedContinuation { continuation in
            signatureContinuation = continuation
        }
    }

    func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        WalletVerifySignatureResult(valid: false)
    }

    func waitUntilCreateSignatureCalled() async {
        guard !createSignatureCalled else { return }
        await withCheckedContinuation { continuation in
            startWaiters.append(continuation)
        }
    }

    func releaseSignature() {
        guard let pendingResult, let signatureContinuation else { return }
        self.pendingResult = nil
        self.signatureContinuation = nil
        signatureContinuation.resume(returning: pendingResult)
    }
}

private enum RecordingWalletError: Error {
    case requestedFailure
}

private actor RecordingWallet: WalletPublicKeyProviding, WalletSignatureOperations {
    struct Requests: Sendable {
        var publicKeys: [WalletGetPublicKeyRequest]
        var signatures: [WalletCreateSignatureRequest]
    }

    private let publicKey: PublicKey
    private let signingKey: PrivateKey
    private let signatureMode: SignatureMode
    private var publicKeyRequests: [WalletGetPublicKeyRequest] = []
    private var signatureRequests: [WalletCreateSignatureRequest] = []

    init(
        publicKey: PublicKey,
        signingKey: PrivateKey,
        signatureMode: SignatureMode = .correct
    ) {
        self.publicKey = publicKey
        self.signingKey = signingKey
        self.signatureMode = signatureMode
    }

    func getPublicKey(
        _ request: WalletGetPublicKeyRequest
    ) async throws -> WalletGetPublicKeyResult {
        publicKeyRequests.append(request)
        return WalletGetPublicKeyResult(publicKey: publicKey)
    }

    func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult {
        signatureRequests.append(request)
        switch signatureMode {
        case .failure:
            throw RecordingWalletError.requestedFailure
        case .cancellation:
            throw CancellationError()
        case .correct, .wrongKey, .highS, .wrongDigest:
            break
        }

        var digest = try digest(for: request.payload)
        if signatureMode == .wrongDigest {
            digest = try Hash256([UInt8](repeating: 0xa5, count: 32))
        }
        let key = signatureMode == .wrongKey
            ? try PrivateKey([UInt8](repeating: 0, count: 31) + [2])
            : signingKey
        var signature = try key.sign(digest: digest)
        if signatureMode == .highS {
            signature = try highSSignature(from: signature)
        }
        return WalletCreateSignatureResult(signature: signature)
    }

    func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult {
        WalletVerifySignatureResult(valid: false)
    }

    func requests() -> Requests {
        Requests(publicKeys: publicKeyRequests, signatures: signatureRequests)
    }

    private func digest(for payload: WalletSignaturePayload) throws -> Hash256 {
        switch payload {
        case .data(let data): BSVHashing.sha256(data)
        case .digest(let digest): digest
        }
    }

    private func highSSignature(from signature: ECDSASignature) throws -> ECDSASignature {
        let order: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        ]
        let compact = signature.compactBytes
        let lowS = Array(compact[32...])
        var highS = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            var difference = Int(order[index]) - Int(lowS[index]) - borrow
            if difference < 0 {
                difference += 256
                borrow = 1
            } else {
                borrow = 0
            }
            highS[index] = UInt8(difference)
        }
        return try ECDSASignature(compactBytes: Array(compact[..<32]) + highS)
    }
}
