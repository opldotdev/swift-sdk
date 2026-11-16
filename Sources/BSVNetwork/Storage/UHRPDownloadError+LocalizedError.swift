import Foundation

/// Plain sentences a wallet can show when a UHRP download fails.
/// `String(reflecting:)` still lists every rejected offer and failed host for a log.
extension UHRPDownloadError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration:
            "The file download is not set up correctly."
        case .unexpectedLookupAnswer:
            "The overlay sent a file lookup answer the wallet could not read."
        case .tooManyAdvertisements:
            "The overlay listed more offers for this file than the wallet accepts."
        case .tooManyHosts:
            "This file is offered by more hosts than the wallet accepts."
        case .noAvailableHosts(let rejected) where rejected.isEmpty:
            "No host is offering this file."
        case .noAvailableHosts(let rejected):
            "No host is offering this file right now. \(Self.count(rejected.count, "offer was", "offers were")) "
                + "found, but none could be used."
        case .allHostsFailed(let failures):
            "The file could not be downloaded from \(failures.count == 1 ? "its host" : "any of its \(failures.count) hosts"). "
                + "Try again later."
        }
    }

    private static func count(_ value: Int, _ one: String, _ many: String) -> String {
        value == 1 ? "1 \(one)" : "\(value) \(many)"
    }
}
