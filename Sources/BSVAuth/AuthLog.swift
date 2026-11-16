import BSVCore
import Foundation

/// The authentication log: `BSVLog` category `BSVAuth`, written to
/// `os.Logger` on Apple platforms and to the caller's `BSVLog` handler on
/// every platform.
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
/// not reach a shared log in clear. A `BSVLog` handler receives it as
/// `<private>` unless it was installed with `revealingPrivateDetails`.
package enum AuthLog {
    package static let subsystem = BSVLog.subsystem
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
            prefix + (detailIsPrivate ? BSVLog.privatePlaceholder : detail) + suffix
        }
    }

    /// Receives each line as well as the system log, for tests.
    @TaskLocal package static var observer: (@Sendable (String) -> Void)?

    /// Receives each underlying-error entry as it is passed to `BSVLog`, for tests.
    @TaskLocal package static var entryObserver: (@Sendable (Entry) -> Void)?

    package static func error(_ message: String) {
        observer?(message)
        BSVLog.error(category: category, message)
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
        BSVLog.error(
            category: category,
            prefix: entry.prefix,
            detail: entry.detail,
            detailIsPrivate: entry.detailIsPrivate,
            suffix: entry.suffix)
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
        BSVLog.isSDKError(error)
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
        let entry = entry(operation, underlying, as: reported)
        return entry.prefix + entry.detail + entry.suffix
    }
}
