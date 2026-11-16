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
/// field or key, and are public in the system log. An underlying error
/// defined by this SDK carries only counts and sizes and is public too. Any
/// other underlying error, such as one thrown by a caller's wallet, is public
/// only by type; its description is marked private, so it can hold whatever
/// that code put in it without reaching a shared log in clear.
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
        observer?(line(operation, underlying, as: reported))
        #if canImport(os)
        let typeName = String(reflecting: type(of: underlying))
        let detail = String(reflecting: underlying)
        let outcome = String(reflecting: reported)
        let logger = Logger(subsystem: subsystem, category: category)
        if isSDKError(underlying) {
            logger.error(
                "\(operation, privacy: .public): \(typeName, privacy: .public): \(detail, privacy: .public); reported as \(outcome, privacy: .public)"
            )
        } else {
            logger.error(
                "\(operation, privacy: .public): \(typeName, privacy: .public): \(detail, privacy: .private); reported as \(outcome, privacy: .public)"
            )
        }
        #endif
    }

    /// Whether `error` is a type this SDK defines, whose cases carry only
    /// counts, sizes and names chosen here.
    package static func isSDKError(_ error: any Error) -> Bool {
        let module = String(reflecting: type(of: error)).prefix { $0 != "." }
        return sdkModules.contains(String(module))
    }

    private static let sdkModules: Set<String> = [
        "BSVAuth", "BSVCore", "BSVCrypto", "BSVKeys", "BSVMessage", "BSVScript",
        "BSVTransaction", "BSVWallet",
    ]

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
