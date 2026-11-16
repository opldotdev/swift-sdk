import BSVAuth
import Foundation

/// Collects `AuthLog` lines written while a test runs.
final class AuthLogLines: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [String] = []

    var lines: [String] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func record<T>(_ body: () async throws -> T) async rethrows -> T {
        try await AuthLog.$observer.withValue({ [self] line in
            lock.lock()
            stored.append(line)
            lock.unlock()
        }) {
            try await body()
        }
    }
}
