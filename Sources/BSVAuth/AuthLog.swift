import Foundation
#if canImport(os)
import os
#endif

/// The authentication log: subsystem `dev.opl.swift-sdk`, category `BSVAuth`.
///
/// When a detailed error is reported to the caller as a shorter one, such as
/// a `BRC104Error` reported as `BRC104HTTPFramingError.invalidFrame`, the
/// detailed error is written here with its type and case. The reasons this
/// module writes hold no nonce, signature, payload, header value, certificate
/// field or key. An underlying error is written as it describes itself, so an
/// error thrown by a caller's wallet appears as that wallet wrote it.
package enum AuthLog {
    package static let subsystem = "dev.opl.swift-sdk"
    package static let category = "BSVAuth"

    /// Receives each line as well as the system log, for tests.
    @TaskLocal package static var observer: (@Sendable (String) -> Void)?

    package static func error(_ message: String) {
        observer?(message)
        #if canImport(os)
        Logger(subsystem: subsystem, category: category).error("\(message, privacy: .public)")
        #endif
    }

    /// Records the detailed error behind a shorter one the caller receives.
    package static func reported<Reported: Error>(
        _ operation: String,
        _ underlying: any Error,
        as reported: Reported
    ) {
        error(line(operation, underlying, as: reported))
    }

    /// Records why a check failed when the caller receives only `reported`.
    package static func rejected<Reported: Error>(
        _ operation: String,
        _ reason: String,
        as reported: Reported
    ) {
        error("\(operation): \(reason); reported as \(String(reflecting: reported))")
    }

    package static func line<Reported: Error>(
        _ operation: String,
        _ underlying: any Error,
        as reported: Reported
    ) -> String {
        "\(operation): \(type(of: underlying)): \(String(reflecting: underlying)); "
            + "reported as \(String(reflecting: reported))"
    }
}
