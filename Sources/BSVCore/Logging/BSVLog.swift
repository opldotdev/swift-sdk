#if canImport(os)
import os
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif os(Windows)
import WinSDK
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
    /// writes the line, from any thread and from several threads at once, so
    /// it must be quick and thread-safe.
    ///
    /// The handler is called outside the SDK's lock, so it may call
    /// `setHandler` or make SDK calls. A call that writes a line, such as a
    /// failed signature check, calls the handler again from inside it, and a
    /// handler that does so on every line recurses without end. A line
    /// already being written when `setHandler` returns can still reach the
    /// handler that was replaced or removed, with that handler's own
    /// `revealingPrivateDetails` setting; every line written after it returns
    /// goes to the new handler.
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

    /// Writes `prefix`, the description of `error` and `suffix` as one line.
    /// The description is public when the error's type is defined by this
    /// SDK, whose errors carry counts, sizes, names it chose and redacted
    /// provider text, and private otherwise, since an error thrown by caller
    /// code, such as a custom transport or wallet, may hold whatever that
    /// code put in it.
    package static func error(
        category: String,
        prefix: String,
        describing error: any Error,
        suffix: String = ""
    ) {
        self.error(
            category: category,
            prefix: prefix,
            detail: String(reflecting: error),
            detailIsPrivate: !isSDKError(error),
            suffix: suffix)
    }

    /// Whether `error` is a type one of this SDK's modules defines.
    package static func isSDKError(_ error: any Error) -> Bool {
        let module = String(reflecting: type(of: error)).prefix { $0 != "." }
        return sdkModules.contains(String(module))
    }

    private static let sdkModules: Set<String> = [
        "BSV", "BSVAirGap", "BSVAuth", "BSVBigNum", "BSVCompat", "BSVCore", "BSVCrypto",
        "BSVIdentity", "BSVInterpreter", "BSVKVStore", "BSVKeys", "BSVMessage", "BSVNetwork",
        "BSVOverlay", "BSVRegistry", "BSVSPV", "BSVScript", "BSVStorage", "BSVTransaction",
        "BSVWallet",
    ]

    /// What a private detail reads as, as the system log shows it.
    package static let privatePlaceholder = "<private>"

    private static let store = HandlerStore()

    /// The installed handler, behind a lock so any thread can write lines
    /// while a caller installs or removes one. The lock is held only to read
    /// or replace the handler, never while it runs.
    private final class HandlerStore: @unchecked Sendable {
        private let lock = PlatformLock()
        private var handler: Handler?
        private var revealsPrivateDetails = false

        func set(_ handler: Handler?, revealingPrivateDetails: Bool) {
            lock.withLock {
                self.handler = handler
                revealsPrivateDetails = handler != nil && revealingPrivateDetails
            }
        }

        func get() -> (Handler?, Bool) {
            lock.withLock { (handler, revealsPrivateDetails) }
        }
    }
}

/// A mutual-exclusion lock from the platform's C library, since BSVCore does
/// not import Foundation.
private final class PlatformLock: @unchecked Sendable {
    #if os(Windows)
    private let primitive: UnsafeMutablePointer<SRWLOCK>
    #else
    private let primitive: UnsafeMutablePointer<pthread_mutex_t>
    #endif

    init() {
        primitive = .allocate(capacity: 1)
        #if os(Windows)
        InitializeSRWLock(primitive)
        #else
        primitive.initialize(to: pthread_mutex_t())
        pthread_mutex_init(primitive, nil)
        #endif
    }

    deinit {
        #if !os(Windows)
        pthread_mutex_destroy(primitive)
        #endif
        primitive.deallocate()
    }

    func withLock<Result>(_ body: () throws -> Result) rethrows -> Result {
        #if os(Windows)
        AcquireSRWLockExclusive(primitive)
        defer { ReleaseSRWLockExclusive(primitive) }
        #else
        pthread_mutex_lock(primitive)
        defer { pthread_mutex_unlock(primitive) }
        #endif
        return try body()
    }
}
