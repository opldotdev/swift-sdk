#if canImport(os)
import os
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// The SDK's diagnostic log, shared by every module.
///
/// The SDK writes a line here when it reports a failure to the caller as a
/// shorter error, or leaves something out: a wire peer's unreadable frame, a
/// provider's failed response, an overlay host that failed, a certificate that
/// did not verify. Each line belongs to one category, the module that wrote
/// it: `BSVAuth`, `BSVNetwork`, `BSVOverlay` or `BSVWallet`.
///
/// On Apple platforms every line goes to `os.Logger` with subsystem
/// `dev.opl.swift-sdk` and that category, at error level. On every platform,
/// Linux included, it also goes to the handler installed with
/// `setHandler(_:revealingPrivateDetails:)`, if any; with no handler, nothing
/// is written on platforms without `os`.
///
/// Some lines hold a detail the system log marks private, such as the
/// description of an error thrown by a caller's wallet, which may carry
/// whatever that code put in it. The handler receives such a line with the
/// detail replaced by `<private>`, as the system log shows it without private
/// data, unless the handler was installed with `revealingPrivateDetails`.
///
/// ```swift
/// BSVLog.setHandler { entry in
///     logger.error("\(entry.category): \(entry.message)")
/// }
/// ```
public enum BSVLog {
    /// The `os.Logger` subsystem of every line.
    public static let subsystem = "dev.opl.swift-sdk"

    /// One line of the log.
    public struct Entry: Sendable, Equatable {
        /// The module that wrote the line, such as `BSVWallet`.
        public let category: String
        /// The line. A private detail reads `<private>` unless the handler
        /// was installed with `revealingPrivateDetails`.
        public let message: String
        /// Whether the line holds a detail the system log marks private,
        /// shown or replaced in `message`.
        public let hasPrivateDetail: Bool

        public init(category: String, message: String, hasPrivateDetail: Bool) {
            self.category = category
            self.message = message
            self.hasPrivateDetail = hasPrivateDetail
        }
    }

    /// Receives each line. It is called synchronously on the thread that
    /// writes the line, from any thread, so it must be quick and thread-safe.
    public typealias Handler = @Sendable (Entry) -> Void

    /// Installs `handler` for every line the SDK writes from now on, in place
    /// of any handler installed before; `nil` removes it.
    ///
    /// With `revealingPrivateDetails`, lines carry their private details in
    /// plain text. Set it only when the handler's output is as private as the
    /// data the SDK handles, such as during local debugging.
    public static func setHandler(_ handler: Handler?, revealingPrivateDetails: Bool = false) {
        store.set(handler, revealingPrivateDetails: revealingPrivateDetails)
    }

    /// Writes a line with no private part.
    package static func error(category: String, _ message: String) {
        #if canImport(os)
        Logger(subsystem: subsystem, category: category).error("\(message, privacy: .public)")
        #endif
        let (handler, _) = store.get()
        handler?(Entry(category: category, message: message, hasPrivateDetail: false))
    }

    /// Writes `prefix`, `detail` and `suffix` as one line. When
    /// `detailIsPrivate` is set, the detail is private in the system log and
    /// reaches the handler as `<private>` unless it reveals private details.
    package static func error(
        category: String,
        prefix: String,
        detail: String,
        detailIsPrivate: Bool,
        suffix: String
    ) {
        guard detailIsPrivate else {
            error(category: category, prefix + detail + suffix)
            return
        }
        #if canImport(os)
        Logger(subsystem: subsystem, category: category).error(
            "\(prefix, privacy: .public)\(detail, privacy: .private)\(suffix, privacy: .public)"
        )
        #endif
        let (handler, reveals) = store.get()
        handler?(Entry(
            category: category,
            message: prefix + (reveals ? detail : privatePlaceholder) + suffix,
            hasPrivateDetail: true))
    }

    /// What a private detail reads as, as the system log shows it.
    package static let privatePlaceholder = "<private>"

    private static let store = HandlerStore()

    /// The installed handler, behind a lock so any thread can write lines
    /// while a caller installs or removes one.
    private final class HandlerStore: @unchecked Sendable {
        private let mutex: UnsafeMutablePointer<pthread_mutex_t>
        private var handler: Handler?
        private var revealsPrivateDetails = false

        init() {
            mutex = .allocate(capacity: 1)
            mutex.initialize(to: pthread_mutex_t())
            pthread_mutex_init(mutex, nil)
        }

        func set(_ handler: Handler?, revealingPrivateDetails: Bool) {
            pthread_mutex_lock(mutex)
            self.handler = handler
            revealsPrivateDetails = handler != nil && revealingPrivateDetails
            pthread_mutex_unlock(mutex)
        }

        func get() -> (Handler?, Bool) {
            pthread_mutex_lock(mutex)
            defer { pthread_mutex_unlock(mutex) }
            return (handler, revealsPrivateDetails)
        }
    }
}
