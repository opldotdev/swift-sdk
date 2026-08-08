import BSVCore
import BSVKeys
import BSVScript
import BSVTransaction
import Testing

@Suite("PushDrop transaction signing")
struct PushDropSigningTests {
    @Test("all six ForkID modes produce strict DER signatures over the selected digest")
    func allHashTypes() throws {
        let key = try privateKey(1)
        let types = try [UInt8(0x41), 0x42, 0x43, 0xc1, 0xc2, 0xc3].map {
            try ForkIDSignatureHashType(rawValue: $0)
        }
        for hashType in types {
            var transaction = try unsignedTransaction(key: key, lockPosition: .after)
            let digest = try transaction.forkIDSignatureHash(
                inputIndex: 0,
                hashType: hashType,
                limits: limits
            )
            try transaction.signPushDropInput(
                at: 0,
                with: key,
                hashType: hashType,
                limits: limits
            )
            let operations = try transaction.inputs[0].unlockingScript.operations(
                maximumPushDataByteCount: 80
            )
            #expect(operations.count == 1)
            let bytes = try #require(operations[0].pushedData)
            #expect(bytes.last == hashType.rawValue)
            let signature = try ECDSASignature(derBytes: Array(bytes.dropLast()))
            #expect(key.publicKey.verify(signature, digest: digest))
        }
    }

    @Test("default lock-after and explicit lock-before compatibility both sign")
    func layouts() throws {
        let key = try privateKey(1)
        var after = try unsignedTransaction(key: key, lockPosition: .after)
        try after.signPushDropInput(at: 0, with: key, limits: limits)
        #expect(!after.inputs[0].unlockingScript.isEmpty)

        var before = try unsignedTransaction(key: key, lockPosition: .beforeCompatibility)
        #expect(throws: PushDropError.self) {
            try before.signPushDropInput(at: 0, with: key, limits: limits)
        }
        try before.signPushDropInput(
            at: 0,
            with: key,
            lockPosition: .beforeCompatibility,
            limits: limits
        )
        #expect(!before.inputs[0].unlockingScript.isEmpty)
    }

    @Test("invalid input, missing source, script mismatch, and key mismatch are atomic")
    func validationFailures() throws {
        let key = try privateKey(1)
        let otherKey = try privateKey(2)
        var transaction = try unsignedTransaction(key: key, lockPosition: .after)
        let original = transaction

        #expect(throws: TransactionError.invalidInputIndex(-1)) {
            try transaction.signPushDropInput(at: -1, with: key, limits: limits)
        }
        #expect(transaction == original)

        transaction.inputs[0].sourceOutput = nil
        let missingSource = transaction
        #expect(throws: TransactionError.missingSourceOutput(inputIndex: 0)) {
            try transaction.signPushDropInput(at: 0, with: key, limits: limits)
        }
        #expect(transaction == missingSource)

        transaction = original
        let nonPushDrop = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        transaction.inputs[0].sourceOutput = TransactionOutput(
            satoshis: 10_000,
            lockingScript: nonPushDrop
        )
        let mismatch = transaction
        #expect(throws: PushDropError.self) {
            try transaction.signPushDropInput(at: 0, with: key, limits: limits)
        }
        #expect(transaction == mismatch)

        transaction = original
        #expect(throws: PushDropError.privateKeyDoesNotMatchPublicKey(inputIndex: 0)) {
            try transaction.signPushDropInput(at: 0, with: otherKey, limits: limits)
        }
        #expect(transaction == original)
    }

    @Test("Script construction and candidate validation failures do not mutate")
    func signingFailuresAreAtomic() throws {
        let key = try privateKey(1)
        var transaction = try unsignedTransaction(key: key, lockPosition: .after)
        let original = transaction
        let sourceScriptByteCount = try #require(
            transaction.inputs[0].sourceOutput?.lockingScript.byteCount
        )
        let unlockingTooSmall = try TransactionLimits(
            maximumTransactionByteCount: 10_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            // The source script fits exactly, while a DER signature push does not.
            maximumScriptByteCount: UInt64(sourceScriptByteCount)
        )
        #expect(throws: Error.self) {
            try transaction.signPushDropInput(at: 0, with: key, limits: unlockingTooSmall)
        }
        #expect(transaction == original)

        let transactionTooSmall = try TransactionLimits(
            maximumTransactionByteCount: 100,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 1_000
        )
        #expect(throws: TransactionError.self) {
            try transaction.signPushDropInput(at: 0, with: key, limits: transactionTooSmall)
        }
        #expect(transaction == original)
    }

    private let limits = try! TransactionLimits(
        maximumTransactionByteCount: 100_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 100_000
    )

    private func privateKey(_ value: UInt8) throws -> PrivateKey {
        try PrivateKey([UInt8](repeating: 0, count: 31) + [value])
    }

    private func unsignedTransaction(
        key: PrivateKey,
        lockPosition: PushDropLockPosition
    ) throws -> Transaction {
        let lockingScript = try PushDrop.lockingScript(
            fields: [[0xaa], [0xbb, 0xcc], [0xdd]],
            publicKey: key.publicKey,
            lockPosition: lockPosition
        )
        let empty = try Script(bytes: [], maximumByteCount: 0)
        return Transaction(
            inputs: [
                TransactionInput(
                    previousOutput: try Outpoint(
                        transactionID: TransactionID(wireBytes: [UInt8](repeating: 0x11, count: 32)),
                        outputIndex: 0
                    ),
                    unlockingScript: empty,
                    sequence: 0xffff_fffe,
                    sourceOutput: TransactionOutput(satoshis: 10_000, lockingScript: lockingScript)
                ),
                TransactionInput(
                    previousOutput: try Outpoint(
                        transactionID: TransactionID(wireBytes: [UInt8](repeating: 0x22, count: 32)),
                        outputIndex: 1
                    ),
                    unlockingScript: empty,
                    sequence: 0xffff_fffd,
                    sourceOutput: TransactionOutput(satoshis: 2_000, lockingScript: lockingScript)
                ),
            ],
            outputs: [
                TransactionOutput(satoshis: 9_000, lockingScript: lockingScript),
                TransactionOutput(satoshis: 2_500, lockingScript: empty),
            ]
        )
    }
}
