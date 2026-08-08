import BSVCore
import BSVNetwork
import Foundation
import Testing

@Suite("WhatsOnChain chain tracker live conformance")
struct WhatsOnChainChainTrackerConformanceTests {
    @Test(
        "mainnet height one and current tip match the live provider",
        .disabled(
            if: ProcessInfo.processInfo.environment["BSV_LIVE_NETWORK_TESTS"] != "1",
            "Set BSV_LIVE_NETWORK_TESTS=1 to enable read-only provider checks"
        )
    )
    func liveReadOnlyChecks() async throws {
        let policy = try NetworkRequestPolicy(
            requestTimeout: .seconds(5),
            resourceTimeout: .seconds(10),
            maximumResponseBodyByteCount: 64 * 1_024,
            maximumAttempts: 1,
            initialBackoff: .zero,
            maximumBackoff: .zero
        )
        let tracker = WhatsOnChainChainTracker(network: .mainnet, policy: policy)
        let root = try Hash256(try bytes(from: displayRoot).reversed())

        try await withHardDeadline(.seconds(15)) { () async throws -> Void in
            #expect(try await tracker.isValidRoot(root, atBlockHeight: 1))
            #expect(try await tracker.currentHeight() >= 961_399)
        }
    }
}

private enum LiveTestDeadlineError: Error {
    case exceeded
}

private func withHardDeadline<T: Sendable>(
    _ duration: Duration,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: duration)
            throw LiveTestDeadlineError.exceeded
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}

private let displayRoot =
    "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"

private func bytes(from hex: String) throws -> [UInt8] {
    guard hex.utf8.count.isMultiple(of: 2) else {
        throw NetworkServiceError.malformedResponse
    }
    var result: [UInt8] = []
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            throw NetworkServiceError.malformedResponse
        }
        result.append(byte)
        index = next
    }
    return result
}
