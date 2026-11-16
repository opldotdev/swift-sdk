import Foundation
#if canImport(os)
import os
#endif

/// The wallet log: subsystem `dev.opl.swift-sdk`, category `BSVWallet`.
///
/// A wire processor answers a peer with a short, fixed text. The full reason goes here,
/// so the host app can see that a peer sent a frame it could not read, or that its own
/// wallet returned a result the wire cannot carry. A line names the call and the error's
/// type and value. It never holds frame bytes, because those can carry keys and payloads.
package enum WalletLog {
    package static let subsystem = "dev.opl.swift-sdk"
    package static let category = "BSVWallet"

    package static func error(_ message: String) {
        #if canImport(os)
        Logger(subsystem: subsystem, category: category).error("\(message, privacy: .public)")
        #endif
    }

    /// A failure answered in-band: what was being done, the call, and the underlying error.
    package static func failure(_ operation: String, call: WalletCall?, underlying: any Error) {
        error(line(operation, call: call, underlying: underlying))
    }

    package static func line(_ operation: String, call: WalletCall?, underlying: any Error) -> String {
        let name = call?.wireMethodName ?? "unknown call"
        return "\(operation) (\(name)) failed: \(type(of: underlying)): \(String(reflecting: underlying))"
    }
}
