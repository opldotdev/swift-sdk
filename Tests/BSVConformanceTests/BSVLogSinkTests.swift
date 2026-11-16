import BSVAuth
import BSVCore
import BSVKeys
import BSVNetwork
import BSVOverlay
import BSVTransaction
import BSVWallet
import Foundation
import Testing

/// The `BSVLog` handler, which receives every module's lines on every
/// platform. The handler is process-wide, so these tests run one at a time
/// and keep only lines carrying their own marker; other suites may write
/// lines while they run.
@Suite("BSVLog handler", .serialized)
struct BSVLogSinkTests {
    @Test("every module's log reaches the handler with its category")
    func everyModuleReachesHandler() {
        let marker = UUID().uuidString
        let lines = LogLines(marker: marker)
        BSVLog.setHandler(lines.record)
        defer { BSVLog.setHandler(nil) }

        NetworkLog.error("network \(marker)")
        WalletLog.error("wallet \(marker)")
        OverlayLog.error("overlay \(marker)")
        AuthLog.error("auth \(marker)")

        #expect(lines.entries == [
            BSVLog.Entry(category: "BSVNetwork", message: "network \(marker)", hasPrivateDetail: false),
            BSVLog.Entry(category: "BSVWallet", message: "wallet \(marker)", hasPrivateDetail: false),
            BSVLog.Entry(category: "BSVOverlay", message: "overlay \(marker)", hasPrivateDetail: false),
            BSVLog.Entry(category: "BSVAuth", message: "auth \(marker)", hasPrivateDetail: false),
        ])
        #expect(BSVLog.subsystem == "dev.opl.swift-sdk")
    }

    @Test("a private detail is redacted unless the caller opts in")
    func privateDetails() {
        let marker = UUID().uuidString
        let lines = LogLines(marker: marker)
        let callerError = CallerWalletError.failed("secret-\(marker)")

        BSVLog.setHandler(lines.record)
        AuthLog.reported("Redacted \(marker)", callerError, as: AuthError.certificateValidationFailed)
        // An error this SDK defines is public, as in the system log.
        AuthLog.reported("Public \(marker)", CertificateError.invalidJSON, as: AuthError.certificateValidationFailed)
        BSVLog.setHandler(lines.record, revealingPrivateDetails: true)
        AuthLog.reported("Revealed \(marker)", callerError, as: AuthError.certificateValidationFailed)
        BSVLog.setHandler(nil)
        AuthLog.reported("Removed \(marker)", callerError, as: AuthError.certificateValidationFailed)

        let entries = lines.entries
        #expect(entries.count == 3)
        #expect(entries.allSatisfy { $0.category == "BSVAuth" })
        let redacted = entries[0]
        #expect(redacted.hasPrivateDetail)
        #expect(redacted.message.hasPrefix("Redacted \(marker): CallerWalletError: <private>; reported as "))
        #expect(!redacted.message.contains("secret-"))
        #expect(!entries[1].hasPrivateDetail)
        #expect(entries[1].message.contains("CertificateError.invalidJSON"))
        #expect(entries[2].hasPrivateDetail)
        #expect(entries[2].message.contains("secret-\(marker)"))
    }

    @Test("an SDK failure is logged through the handler")
    func sdkFailureReachesHandler() async throws {
        let lines = LogLines(marker: "Certificate signing")
        BSVLog.setHandler(lines.record)
        defer { BSVLog.setHandler(nil) }
        var key = [UInt8](repeating: 0, count: 32)
        key[31] = 11
        let certifier = try PrivateKey(key)
        let unsigned = try Certificate(
            type: try CertificateTypeID([UInt8](repeating: 0x41, count: 32)),
            serialNumber: try CertificateSerialNumber([UInt8](repeating: 0x42, count: 32)),
            subject: certifier.publicKey,
            certifier: certifier.publicKey,
            revocationOutpoint: Outpoint(
                transactionID: TransactionID(exactDigestBytesGuaranteed: [UInt8](repeating: 0, count: 32)),
                outputIndex: 0),
            fields: [try CertificateFieldName("日本"): try CertificateCiphertext([1])])
        await #expect(throws: CertificateFieldNameError.unsupportedCharacter) {
            try await unsigned.signed(using: ProtoWallet(rootKey: certifier))
        }
        #expect(lines.entries.contains {
            $0.category == "BSVWallet"
                && $0.message.hasPrefix("Certificate signing: a field name of 6 bytes")
        })
    }
}

private enum CallerWalletError: Error {
    case failed(String)
}

/// Collects the lines that contain `marker`.
private final class LogLines: @unchecked Sendable {
    private let marker: String
    private let lock = NSLock()
    private var recorded: [BSVLog.Entry] = []

    init(marker: String) { self.marker = marker }

    var record: BSVLog.Handler {
        { [self] entry in
            guard entry.message.contains(marker) else { return }
            lock.lock()
            recorded.append(entry)
            lock.unlock()
        }
    }

    var entries: [BSVLog.Entry] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }
}
