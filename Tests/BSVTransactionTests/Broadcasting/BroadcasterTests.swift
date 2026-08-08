import BSVCore
@testable import BSVTransaction
import Testing

@Suite("Transaction broadcaster contract")
struct BroadcasterTests {
    @Test("transaction extension dispatches through the broadcaster")
    func extensionDispatch() async throws {
        let transaction = Transaction(version: 2, lockTime: 7)
        let limits = try transactionLimits()
        let expected = BroadcastResult(
            transactionID: try transaction.transactionID(limits: limits),
            message: "accepted"
        )
        let broadcaster = RecordingBroadcaster(result: expected)

        let result = try await transaction.broadcast(using: broadcaster, limits: limits)

        #expect(result == expected)
        #expect(await broadcaster.recordedTransaction() == transaction)
        #expect(await broadcaster.recordedLimits() == limits)
    }

    @Test("public broadcaster values satisfy Sendable and Hashable constraints")
    func compileChecks() throws {
        let transactionID = try TransactionID(wireBytes: Array(repeating: 0, count: 32))
        let result = BroadcastResult(transactionID: transactionID)
        let broadcaster = RecordingBroadcaster(result: result)

        acceptSendable(result)
        acceptHashable(result)
        acceptBroadcaster(broadcaster)
    }
}

private actor RecordingBroadcaster: Broadcaster {
    private let result: BroadcastResult
    private var transaction: Transaction?
    private var limits: TransactionLimits?

    init(result: BroadcastResult) {
        self.result = result
    }

    func broadcast(
        _ transaction: Transaction,
        limits: TransactionLimits
    ) async throws -> BroadcastResult {
        self.transaction = transaction
        self.limits = limits
        return result
    }

    func recordedTransaction() -> Transaction? { transaction }
    func recordedLimits() -> TransactionLimits? { limits }
}

private func transactionLimits() throws -> TransactionLimits {
    try TransactionLimits(
        maximumTransactionByteCount: 1_000,
        maximumInputCount: 10,
        maximumOutputCount: 10,
        maximumScriptByteCount: 100
    )
}

private func acceptSendable<T: Sendable>(_ value: T) {}
private func acceptHashable<T: Hashable>(_ value: T) {}
private func acceptBroadcaster<T: Broadcaster & Sendable>(_ value: T) {}
