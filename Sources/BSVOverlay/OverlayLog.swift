import Foundation

#if canImport(os)
import os
#endif

/// The overlay policy log: subsystem `dev.opl.swift-sdk`, category `BSVOverlay`.
///
/// The HTTPS facilitators log each failed request through `NetworkLog`. This
/// log records what the resolver and broadcaster then leave out: a host or
/// tracker that failed, a STEAK that was empty or acknowledged a topic that
/// was not sent, an output whose transaction could not be read, an
/// advertisement that could not be used, and advertised hosts past the host
/// limit. Errors are logged in full. Hosts are written as scheme, host and
/// port only, so a caller host carrying a user name, password, path or query
/// does not put it in the log; no payload bytes are written.
///
/// Like `NetworkLog`, it writes through `os.Logger`, so it records nothing on
/// platforms without `os` (Linux).
enum OverlayLog {
    static let subsystem = "dev.opl.swift-sdk"
    static let category = "BSVOverlay"

    static func hostFailure(_ operation: String, _ failure: OverlayHostFailure) {
        error(
            "\(operation): host \(location(failure.host)) failed: "
                + "\(type(of: failure.error)): \(String(reflecting: failure.error))"
        )
    }

    static func rejectedOutput(_ operation: String, _ rejection: LookupOutputRejection) {
        error(
            "\(operation): output \(rejection.output.outputIndex) from host "
                + "\(location(rejection.host)) left out: "
                + "\(type(of: rejection.error)): \(String(reflecting: rejection.error))"
        )
    }

    static func skippedAdvertisement(_ operation: String, output: OutputListItem, reason: String) {
        let transaction = output.transactionID.map { " of \($0.displayHex)" } ?? ""
        error(
            "\(operation): advertisement output \(output.outputIndex)\(transaction) "
                + "left out: \(reason)"
        )
    }

    static func skippedHosts(_ operation: String, count: Int, limit: Int) {
        error("\(operation): \(count) advertised host(s) left out past the limit of \(limit)")
    }

    /// Scheme, host and port of `host`, as `NetworkLog.location` keeps only
    /// what identifies the endpoint.
    static func location(_ host: OverlayHost) -> String {
        guard let components = URLComponents(string: host.rawValue),
            let scheme = components.scheme, let name = components.host, !name.isEmpty
        else { return "(unparsed host)" }
        let port = components.port.map { ":\($0)" } ?? ""
        return "\(scheme)://\(name)\(port)"
    }

    private static func error(_ message: String) {
        #if canImport(os)
        Logger(subsystem: subsystem, category: category).error("\(message, privacy: .public)")
        #endif
    }
}
