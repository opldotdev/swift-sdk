import BSVCore
import BSVCrypto
import BSVSPV
import BSVScript
import BSVTransaction
import Testing

@Suite("SPV proof verifier")
struct SPVProofVerifierTests {
    @Test("the public façade verifies a transaction inclusion proof")
    func merklePath() async throws {
        let limits = try TransactionLimits(
            maximumTransactionByteCount: 1_000,
            maximumInputCount: 10,
            maximumOutputCount: 10,
            maximumScriptByteCount: 100
        )
        let transaction = Transaction(
            version: 1,
            inputs: [],
            outputs: [],
            lockTime: 0
        )
        let transactionID = try transaction.transactionID(limits: limits)
        let root = try Hash256(transactionID.wireBytes)
        let path = try MerklePath(
            blockHeight: 100,
            levels: [[.hash(offset: 0, hash: root, isTransactionID: true)]]
        )
        let tracker = FixedChainTracker(root: root, blockHeight: 100)

        #expect(try await SPVProofVerifier.verify(
            path,
            transactionID: transactionID,
            using: tracker
        ))
    }
}

private struct FixedChainTracker: ChainTracker {
    let root: Hash256
    let blockHeight: UInt32

    func isValidRoot(
        _ candidate: Hash256,
        atBlockHeight candidateHeight: UInt32
    ) async throws -> Bool {
        candidate == root && candidateHeight == blockHeight
    }

    func currentHeight() async throws -> UInt32 {
        blockHeight
    }
}
