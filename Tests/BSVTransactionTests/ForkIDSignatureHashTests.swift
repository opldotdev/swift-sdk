import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVTransaction
import Testing

@Suite("ForkID transaction signatures")
struct ForkIDSignatureHashTests {
    // Public-domain BIP-143 native P2WPKH example, applied to the same
    // replay-protected digest algorithm with BSV's 0x40 ForkID bit. The only
    // transformed preimage field is nHashType: 0x00000001 -> 0x00000041.
    // Source: bitcoin/bips bip-0143.mediawiki, Native P2WPKH example, public
    // domain per its header. Pinned revision ed4ffcb6a48d4dc4fdfc11cdba783c233db8c66e;
    // source SHA-256 62bc71351563e68baeb12643c68355d217953ae9eb6a6e68b2b0323275b6beec.
    // The transformed digest below was independently calculated with OpenSSL
    // from the displayed transformed preimage; it is not Go-oracle output.
    private let unsignedTransaction =
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f" +
        "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57" +
        "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c" +
        "95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2" +
        "f0167faa815988ac11000000"

    private let expectedForkIDPreimage =
        "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37" +
        "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b" +
        "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000" +
        "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac" +
        "0046c32300000000ffffffff" +
        "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5" +
        "1100000041000000"

    @Test("public-domain BIP-143 image maps exactly to BSV ForkID")
    func knownPreimageAndDigest() throws {
        let limits = try signingLimits()
        var transaction = try Transaction(hex: unsignedTransaction, limits: limits)
        transaction.inputs[1].sourceOutput = TransactionOutput(
            satoshis: 600_000_000,
            lockingScript: try Script(
                hex: "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac",
                maximumByteCount: 25
            )
        )

        let preimage = try transaction.forkIDSignaturePreimage(
            inputIndex: 1,
            limits: limits
        )
        #expect(Hex.encode(preimage) == expectedForkIDPreimage)
        #expect(
            Hex.encode(try transaction.forkIDSignatureHash(
                inputIndex: 1,
                limits: limits
            ).bytes) == "467f411d178762db122a6aced76370a1c8324355bf0796502bf82eeaeda86a35"
        )
    }

    @Test("all flag combinations commit to the correct transaction subsets")
    func flagSemantics() throws {
        let limits = try signingLimits()
        let base = try transactionForFlagTests()

        for outputs in SignatureHashOutputs.allCases {
            for anyoneCanPay in [false, true] {
                let type = ForkIDSignatureHashType(
                    outputs: outputs,
                    anyoneCanPay: anyoneCanPay
                )
                var changedOtherInput = base
                changedOtherInput.inputs[0].previousOutput = try outpoint(fill: 0xee, index: 7)
                changedOtherInput.inputs[0].sequence = 9

                let baseHash = try base.forkIDSignatureHash(
                    inputIndex: 1,
                    hashType: type,
                    limits: limits
                )
                let changedHash = try changedOtherInput.forkIDSignatureHash(
                    inputIndex: 1,
                    hashType: type,
                    limits: limits
                )
                #expect((baseHash == changedHash) == anyoneCanPay)
            }
        }

        var outputsChanged = base
        outputsChanged.outputs[0].satoshis += 1
        #expect(try base.forkIDSignatureHash(
            inputIndex: 1,
            hashType: .none,
            limits: limits
        ) == outputsChanged.forkIDSignatureHash(
            inputIndex: 1,
            hashType: .none,
            limits: limits
        ))
        #expect(try base.forkIDSignatureHash(
            inputIndex: 1,
            hashType: .single,
            limits: limits
        ) == outputsChanged.forkIDSignatureHash(
            inputIndex: 1,
            hashType: .single,
            limits: limits
        ))

        outputsChanged.outputs[1].satoshis += 1
        #expect(try base.forkIDSignatureHash(
            inputIndex: 1,
            hashType: .single,
            limits: limits
        ) != outputsChanged.forkIDSignatureHash(
            inputIndex: 1,
            hashType: .single,
            limits: limits
        ))
    }

    @Test("P2PKH signing is deterministic, verifiable, and transactional")
    func p2pkhSigning() throws {
        let limits = try signingLimits()
        let key = try PrivateKey([UInt8](repeating: 0, count: 31) + [1])
        let lockingScript = try Script.payToPublicKeyHash(
            BSVHashing.hash160(key.publicKey.compressedBytes),
            maximumByteCount: 25
        )
        let empty = try Script(bytes: [], maximumByteCount: 0)
        var transaction = Transaction(
            inputs: [TransactionInput(
                previousOutput: try outpoint(fill: 0x11, index: 2),
                unlockingScript: empty,
                sourceOutput: TransactionOutput(satoshis: 12_345, lockingScript: lockingScript)
            )],
            outputs: [TransactionOutput(satoshis: 12_000, lockingScript: lockingScript)]
        )
        let digest = try transaction.forkIDSignatureHash(inputIndex: 0, limits: limits)

        try transaction.signPayToPublicKeyHashInput(
            at: 0,
            with: key,
            limits: limits
        )
        let firstImage = transaction.inputs[0].unlockingScript.bytes
        let operations = try transaction.inputs[0].unlockingScript.operations(
            maximumPushDataByteCount: 80
        )
        #expect(operations.count == 2)
        let signatureBytes = try #require(operations[0].pushedData)
        #expect(signatureBytes.last == ForkIDSignatureHashType.all.rawValue)
        let signature = try ECDSASignature(derBytes: Array(signatureBytes.dropLast()))
        #expect(key.publicKey.verify(signature, digest: digest))
        #expect(operations[1].pushedData == key.publicKey.compressedBytes)

        try transaction.signPayToPublicKeyHashInput(at: 0, with: key, limits: limits)
        #expect(transaction.inputs[0].unlockingScript.bytes == firstImage)

        let tooSmall = try TransactionLimits(
            maximumTransactionByteCount: 60,
            maximumInputCount: 1,
            maximumOutputCount: 1,
            maximumScriptByteCount: 1_000
        )
        #expect(throws: TransactionError.self) {
            try transaction.signPayToPublicKeyHashInput(
                at: 0,
                with: key,
                limits: tooSmall
            )
        }
        #expect(transaction.inputs[0].unlockingScript.bytes == firstImage)

        let otherKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [2])
        #expect(throws: TransactionError.privateKeyDoesNotMatchSourceOutput(inputIndex: 0)) {
            try transaction.signPayToPublicKeyHashInput(
                at: 0,
                with: otherKey,
                limits: limits
            )
        }
        #expect(transaction.inputs[0].unlockingScript.bytes == firstImage)
    }

    @Test("invalid indices, missing metadata, and bounded scripts are typed")
    func failures() throws {
        let limits = try signingLimits()
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let transaction = Transaction(inputs: [TransactionInput(
            previousOutput: try outpoint(fill: 1, index: 0),
            unlockingScript: empty
        )])
        #expect(throws: TransactionError.invalidInputIndex(-1)) {
            try transaction.forkIDSignaturePreimage(inputIndex: -1, limits: limits)
        }
        #expect(throws: TransactionError.invalidInputIndex(1)) {
            try transaction.forkIDSignaturePreimage(inputIndex: 1, limits: limits)
        }
        #expect(throws: TransactionError.missingSourceOutput(inputIndex: 0)) {
            try transaction.forkIDSignaturePreimage(inputIndex: 0, limits: limits)
        }
        for invalid in [UInt8(0), 1, 0x40, 0x44, 0x61, 0xff] {
            #expect(throws: SignatureHashTypeError.invalidForkIDValue(invalid)) {
                try ForkIDSignatureHashType(rawValue: invalid)
            }
        }
        for valid in [UInt8(0x41), 0x42, 0x43, 0xc1, 0xc2, 0xc3] {
            #expect(try ForkIDSignatureHashType(rawValue: valid).rawValue == valid)
        }

        var withSource = transaction
        withSource.inputs[0].sourceOutput = TransactionOutput(
            satoshis: 1,
            lockingScript: empty
        )
        let explicitScriptCode = try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1)
        let defaultPreimage = try withSource.forkIDSignaturePreimage(
            inputIndex: 0,
            limits: limits
        )
        let explicitPreimage = try withSource.forkIDSignaturePreimage(
            inputIndex: 0,
            scriptCode: explicitScriptCode,
            limits: limits
        )
        #expect(defaultPreimage != explicitPreimage)
        #expect(explicitPreimage[104...105] == [1, Opcode.one.rawValue])
    }

    private func transactionForFlagTests() throws -> Transaction {
        let empty = try Script(bytes: [], maximumByteCount: 0)
        let source = TransactionOutput(satoshis: 500, lockingScript: empty)
        return Transaction(
            version: 2,
            inputs: [
                TransactionInput(
                    previousOutput: try outpoint(fill: 1, index: 0),
                    unlockingScript: empty,
                    sequence: 1,
                    sourceOutput: source
                ),
                TransactionInput(
                    previousOutput: try outpoint(fill: 2, index: 1),
                    unlockingScript: empty,
                    sequence: 2,
                    sourceOutput: source
                ),
            ],
            outputs: [
                TransactionOutput(satoshis: 100, lockingScript: empty),
                TransactionOutput(satoshis: 200, lockingScript: empty),
            ],
            lockTime: 3
        )
    }

    private func outpoint(fill: UInt8, index: UInt32) throws -> Outpoint {
        Outpoint(
            transactionID: try TransactionID(wireBytes: [UInt8](repeating: fill, count: 32)),
            outputIndex: index
        )
    }

    private func signingLimits() throws -> TransactionLimits {
        try TransactionLimits(
            maximumTransactionByteCount: 100_000,
            maximumInputCount: 100,
            maximumOutputCount: 100,
            maximumScriptByteCount: 10_000
        )
    }
}
