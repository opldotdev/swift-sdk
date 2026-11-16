import BSVAuth
import BSVCore
import BSVCrypto
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
            fields: [
                try CertificateFieldName("日本"): try CertificateCiphertext([1]),
                try CertificateFieldName("a"): try CertificateCiphertext([2]),
            ])
        await #expect(throws: CertificateFieldNameError.unsupportedCharacter) {
            try await unsigned.signed(using: ProtoWallet(rootKey: certifier))
        }
        #expect(lines.entries.contains {
            $0.category == "BSVWallet"
                && $0.message.hasPrefix("Certificate signing: a field name of 6 bytes")
        })
    }

    @Test("a caller's transport or facilitator error text is private; an SDK error is public")
    func callerErrorTextIsPrivate() throws {
        let marker = UUID().uuidString
        let lines = LogLines(marker: marker)
        BSVLog.setHandler(lines.record)
        defer { BSVLog.setHandler(nil) }
        let request = HTTPRequest(
            method: .get, url: try #require(URL(string: "https://api.example/v1/tx?key=k")))
        let callerError = CallerWalletError.failed("https://api.example/v1/tx?key=secret-\(marker)")

        NetworkLog.failure("Caller \(marker)", request: request, underlying: callerError)
        NetworkLog.failure("SDK \(marker)", request: request, underlying: NetworkServiceError.timedOut)
        let host = try OverlayHost(rawValue: "https://overlay.example")
        OverlayLog.hostFailure("Caller \(marker)", OverlayHostFailure(host: host, error: callerError))
        OverlayLog.hostFailure(
            "SDK \(marker)",
            OverlayHostFailure(host: host, error: OverlayHTTPError.rejected(statusCode: 503)))

        let entries = lines.entries
        #expect(entries.map(\.category) == ["BSVNetwork", "BSVNetwork", "BSVOverlay", "BSVOverlay"])
        #expect(entries.map(\.hasPrivateDetail) == [true, false, true, false])
        #expect(entries.allSatisfy { !$0.message.contains("secret-") })
        #expect(entries[0].message == "Caller \(marker): GET api.example/v1/tx failed: CallerWalletError: <private>")
        #expect(entries[1].message.hasSuffix("failed: NetworkServiceError: BSVNetwork.NetworkServiceError.timedOut"))
        #expect(entries[2].message == "Caller \(marker): host https://overlay.example failed: CallerWalletError: <private>")
        #expect(entries[3].message.contains("OverlayHTTPError.rejected(statusCode: 503"))

        BSVLog.setHandler(lines.record, revealingPrivateDetails: true)
        NetworkLog.failure("Revealed \(marker)", request: request, underlying: callerError)
        #expect(lines.entries.last?.message.contains("secret-\(marker)") == true)
        #expect(BSVLog.isSDKError(OverlayPolicyError.invalidSteak))
        #expect(!BSVLog.isSDKError(callerError))
    }

    @Test("certificate verification logs a match by byte or received order and an unexplained failure")
    func certificateVerificationLines() async throws {
        let lines = LogLines(marker: "Certificate verification:")
        BSVLog.setHandler(lines.record)
        defer { BSVLog.setHandler(nil) }
        let wallet = try ProtoWallet(rootKey: certifierKey())

        // Signed over UTF-8 byte order, as the Go SDK signs.
        let goOrder = try unsignedCertificate(names: ["Zip", "age"], serial: 0x50)
        let goSigned = try goOrder.replacingSignature(try await sign(
            goOrder.binary(includingSignature: false, limits: .standard, fieldOrder: .utf8Bytes),
            for: goOrder, with: wallet))
        #expect(try await goSigned.verifySignature())

        // Signed over the order the fields arrived in, which is neither.
        var received = try unsignedCertificate(names: ["Zip", "age", "_x"], serial: 0x51)
        received.receivedFieldOrder = try ["age", "_x", "Zip"].map { try CertificateFieldName($0) }
        let receivedSigned = try received.replacingSignature(try await sign(
            received.binary(includingSignature: false, limits: .standard, fieldOrder: .received),
            for: received, with: wallet))
        #expect(try await receivedSigned.verifySignature())

        // A name outside the reproduced order, and a signature no order matches.
        let exotic = try unsignedCertificate(names: ["日本", "a"], serial: 0x52)
        let wrong = try exotic.replacingSignature(try await sign([1, 2, 3], for: exotic, with: wallet))
        #expect(try await wrong.verifySignature() == false)

        let messages = lines.entries.map(\.message)
        #expect(messages.contains(
            "Certificate verification: the signature covers its 2 fields in UTF-8 byte order, "
                + "as the Go SDK signs, not in localeCompare order"))
        #expect(messages.contains(
            "Certificate verification: the signature covers its 3 fields in the order they were "
                + "received, which is neither localeCompare order on an en-US host nor UTF-8 byte order"))
        #expect(messages.contains { $0.hasPrefix(
            "Certificate verification: the signature did not verify; a field name of 6 bytes") })
        #expect(lines.entries.allSatisfy { $0.category == "BSVWallet" && !$0.hasPrivateDetail })
    }

    @Test("a handler may log and replace the handler from inside itself")
    func reentrantHandler() {
        let marker = UUID().uuidString
        let outer = LogLines(marker: marker)
        let replacement = LogLines(marker: marker)
        let reentrant: BSVLog.Handler = { entry in
            outer.record(entry)
            guard entry.message == "first \(marker)" else { return }
            // Writing a line from inside the handler calls it again.
            WalletLog.error("nested \(marker)")
            BSVLog.setHandler(replacement.record)
        }
        BSVLog.setHandler(reentrant)
        defer { BSVLog.setHandler(nil) }

        WalletLog.error("first \(marker)")
        WalletLog.error("after \(marker)")

        #expect(outer.entries.map(\.message) == ["first \(marker)", "nested \(marker)"])
        #expect(replacement.entries.map(\.message) == ["after \(marker)"])
    }

    @Test("lines written from many tasks while the handler is swapped each reach one handler")
    func concurrentLinesAndSwaps() async {
        let marker = UUID().uuidString
        let first = LogLines(marker: marker)
        let second = LogLines(marker: marker)
        BSVLog.setHandler(first.record)
        defer { BSVLog.setHandler(nil) }
        let writers = 16
        let linesPerWriter = 200

        await withTaskGroup(of: Void.self) { group in
            for writer in 0..<writers {
                group.addTask {
                    for line in 0..<linesPerWriter {
                        AuthLog.reported(
                            "\(marker) \(writer) \(line)",
                            CallerWalletError.failed("secret"),
                            as: AuthError.certificateValidationFailed)
                    }
                }
            }
            group.addTask {
                for swap in 0..<500 {
                    if swap.isMultiple(of: 2) {
                        BSVLog.setHandler(second.record, revealingPrivateDetails: true)
                    } else {
                        BSVLog.setHandler(first.record)
                    }
                }
            }
        }

        let all = first.entries + second.entries
        #expect(all.count == writers * linesPerWriter)
        #expect(Set(all.map(\.message)).count == writers * linesPerWriter)
        // Each handler sees details only as it was installed to.
        #expect(first.entries.allSatisfy { $0.message.contains("<private>") })
        #expect(second.entries.allSatisfy { $0.message.contains("CallerWalletError.failed(\"secret\")") })
    }

    private func certifierKey() throws -> PrivateKey {
        var key = [UInt8](repeating: 0, count: 32)
        key[31] = 11
        return try PrivateKey(key)
    }

    private func unsignedCertificate(names: [String], serial: UInt8) throws -> Certificate {
        let certifier = try certifierKey().publicKey
        var fields: [CertificateFieldName: CertificateCiphertext] = [:]
        for (index, name) in names.enumerated() {
            fields[try CertificateFieldName(name)] = try CertificateCiphertext([UInt8(index + 1)])
        }
        return try Certificate(
            type: try CertificateTypeID([UInt8](repeating: 0x4F, count: 32)),
            serialNumber: try CertificateSerialNumber([UInt8](repeating: serial, count: 32)),
            subject: certifier,
            certifier: certifier,
            revocationOutpoint: Outpoint(
                transactionID: TransactionID(exactDigestBytesGuaranteed: [UInt8](repeating: 0, count: 32)),
                outputIndex: 0),
            fields: fields)
    }

    private func sign(
        _ preimage: [UInt8], for certificate: Certificate, with wallet: ProtoWallet
    ) async throws -> ECDSASignature {
        try await wallet.createSignature(.init(
            protocolID: try CertificateProtocols.signature,
            keyID: try WalletKeyID(certificate.signatureKeyID),
            counterparty: .anyone,
            payload: .digest(BSVHashing.sha256(preimage))
        )).signature
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
