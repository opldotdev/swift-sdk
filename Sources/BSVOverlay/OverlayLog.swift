#if canImport(os)
import os
#endif

/// The overlay policy log: subsystem `dev.opl.swift-sdk`, category `BSVOverlay`.
///
/// The HTTPS facilitators log each failed request through `NetworkLog`. This
/// log records what the resolver and broadcaster then leave out: a host that
/// failed, a STEAK that was empty or acknowledged a topic that was not sent,
/// an output whose transaction could not be read, and advertised hosts past
/// the host limit. Hosts are origins and
/// errors are logged in full; no payload bytes are written.
enum OverlayLog {
    static let subsystem = "dev.opl.swift-sdk"
    static let category = "BSVOverlay"

    static func hostFailure(_ operation: String, _ failure: OverlayHostFailure) {
        error(
            "\(operation): host \(failure.host.rawValue) failed: "
                + "\(type(of: failure.error)): \(String(reflecting: failure.error))"
        )
    }

    static func rejectedOutput(_ operation: String, _ rejection: LookupOutputRejection) {
        error(
            "\(operation): output \(rejection.output.outputIndex) from host "
                + "\(rejection.host.rawValue) left out: "
                + "\(type(of: rejection.error)): \(String(reflecting: rejection.error))"
        )
    }

    static func skippedHosts(_ operation: String, count: Int, limit: Int) {
        error("\(operation): \(count) advertised host(s) left out past the limit of \(limit)")
    }

    private static func error(_ message: String) {
        #if canImport(os)
        Logger(subsystem: subsystem, category: category).error("\(message, privacy: .public)")
        #endif
    }
}
