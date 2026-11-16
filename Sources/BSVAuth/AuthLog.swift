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
/// field or key, and are public in the system log.
///
/// An underlying error whose type this SDK defines is public too. Its cases
/// carry counts, sizes, names this SDK chose, and some carry the input text
/// that failed to parse, such as an unknown enum value or JSON key; none is
/// known to carry a key or a certificate field value. Any other underlying
/// error, such as one thrown by a caller's wallet, is public only by type:
/// its description is marked private, so whatever that code put in it does
/// not reach a shared log in clear.
package enum AuthLog {
    package static let subsystem = "dev.opl.swift-sdk"
    package static let category = "BSVAuth"

    /// One line about an underlying error, split where the privacy marker
    /// changes: `detail` is private when `detailIsPrivate` is set.
    package struct Entry: Sendable, Equatable {
        package let prefix: String
        package let detail: String
        package let suffix: String
        package let detailIsPrivate: Bool

        /// The line as a reader of the system log without private data sees it.
        package var publicText: String {
            prefix + (detailIsPrivate ? "<private>" : detail) + suffix
        }
    }

    /// Receives each line as well as the system log, for tests.
    @TaskLocal package static var observer: (@Sendable (String) -> Void)?

    /// Receives each underlying-error entry as it is passed to `os.Logger`, for tests.
    @TaskLocal package static var entryObserver: (@Sendable (Entry) -> Void)?

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
        let entry = entry(operation, underlying, as: reported)
        entryObserver?(entry)
        #if canImport(os)
        let logger = Logger(subsystem: subsystem, category: category)
        if entry.detailIsPrivate {
            logger.error(
                "\(entry.prefix, privacy: .public)\(entry.detail, privacy: .private)\(entry.suffix, privacy: .public)"
            )
        } else {
            logger.error(
                "\(entry.prefix, privacy: .public)\(entry.detail, privacy: .public)\(entry.suffix, privacy: .public)"
            )
        }
        #endif
    }

    package static func entry<Reported: Error>(
        _ operation: String,
        _ underlying: any Error,
        as reported: Reported
    ) -> Entry {
        Entry(
            prefix: "\(operation): \(type(of: underlying)): ",
            detail: String(reflecting: underlying),
            suffix: "; reported as \(String(reflecting: reported))",
            detailIsPrivate: !isSDKError(underlying))
    }

    /// Whether `error` is a type this SDK defines.
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
        let entry = entry(operation, underlying, as: reported)
        return entry.prefix + entry.detail + entry.suffix
    }
}
