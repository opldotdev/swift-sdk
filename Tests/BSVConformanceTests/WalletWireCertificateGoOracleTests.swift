import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
import BSVTransaction
import BSVWallet

final class WalletWireCertificateGoOracleTests: XCTestCase {
    func testOnePersistentPinnedGoClientChecksAllCertificateCalls() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let value): client = value
        case .unavailable(let reason):
            XCTAssertFalse(configuration.required)
            print("Wallet-wire certificate Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        let fixture = try CertificateOracleFixture()
        let privilege = try WalletPrivilege(
            privileged: true,
            privilegedReason: "oracle review"
        )
        let direct = try WalletDirectCertificateAcquisition(
            serialNumber: fixture.serial,
            revocationOutpoint: fixture.outpoint,
            signature: fixture.signature,
            keyringRevealer: .certifier,
            keyringForSubject: fixture.keyring
        )
        let requests: [WalletWireCertificateRequest] = [
            .revealCounterpartyKeyLinkage(.init(
                counterparty: fixture.subject,
                verifier: fixture.verifier,
                privilege: privilege
            )),
            .revealSpecificKeyLinkage(try .init(
                counterparty: .publicKey(fixture.subject),
                verifier: fixture.verifier,
                protocolID: fixture.protocolID,
                keyID: fixture.keyID,
                privilege: privilege
            )),
            .acquireCertificate(try .init(
                type: fixture.type,
                certifier: fixture.certifier,
                fields: fixture.textFields,
                acquisition: .direct(direct),
                privilege: privilege
            )),
            .listCertificates(try .init(
                certifiers: [fixture.certifier],
                types: [fixture.type],
                pagination: WalletPagination(limit: 2, offset: 1),
                privilege: privilege
            )),
            .proveCertificate(try .init(
                certificate: fixture.certificate,
                fieldsToReveal: [fixture.alpha],
                verifier: fixture.verifier,
                privilege: privilege
            )),
            .relinquishCertificate(.init(
                type: fixture.type,
                serialNumber: fixture.serial,
                certifier: fixture.certifier
            )),
            .discoverByIdentityKey(.init(
                identityKey: fixture.subject,
                pagination: try WalletPagination(limit: 1, offset: 0),
                seekPermission: true
            )),
            .discoverByAttributes(try .init(
                attributes: fixture.textFields,
                pagination: WalletPagination(limit: 1, offset: 0),
                seekPermission: false
            )),
        ]

        var sequence = 60_000
        for request in requests {
            let encoded = try WalletWireCodec.encodeCertificateRequest(
                request,
                originator: "oracle"
            )
            XCTAssertEqual(
                try certificateOracleBytes(
                    client,
                    operation: "wallet.wire.request.reencode",
                    call: request.call,
                    bytes: encoded,
                    sequence: &sequence
                ),
                encoded,
                "request call \(request.call.rawValue)"
            )
        }

        let identity = try WalletIdentityCertificate(
            certificate: fixture.certificate,
            certifierInfo: WalletIdentityCertifier(
                name: "Issuer",
                iconURL: "https://issuer.example/icon",
                description: "Oracle issuer",
                trust: 8
            ),
            publiclyRevealedKeyring: fixture.keyring,
            decryptedFields: fixture.textFields
        )
        let results: [WalletWireCertificateResult] = [
            .revealCounterpartyKeyLinkage(try .init(
                prover: fixture.certifier,
                counterparty: fixture.subject,
                verifier: fixture.verifier,
                revelationTime: "2026-08-08T12:00:00Z",
                encryptedLinkage: WalletLinkageCiphertext([1, 2]),
                encryptedLinkageProof: WalletLinkageCiphertext([3, 4])
            )),
            .revealSpecificKeyLinkage(try .init(
                encryptedLinkage: WalletLinkageCiphertext([5]),
                encryptedLinkageProof: WalletLinkageCiphertext([6]),
                prover: fixture.certifier,
                verifier: fixture.verifier,
                counterparty: fixture.subject,
                protocolID: fixture.protocolID,
                keyID: fixture.keyID,
                proofType: 1
            )),
            .acquireCertificate(fixture.certificate),
            .listCertificates(try .init(
                totalCertificates: 2,
                certificates: [
                    WalletCertificateResult(
                        certificate: fixture.certificate,
                        keyring: nil,
                        verifier: []
                    ),
                    WalletCertificateResult(
                        certificate: fixture.certificate,
                        keyring: fixture.keyring,
                        verifier: [7]
                    ),
                ]
            )),
            .proveCertificate(try .init(keyringForVerifier: fixture.keyring)),
            .relinquishCertificate(.init(relinquished: true)),
            .discoverByIdentityKey(try .init(
                totalCertificates: 1,
                certificates: [identity]
            )),
            .discoverByAttributes(try .init(
                totalCertificates: 1,
                certificates: [identity]
            )),
        ]

        for result in results {
            let encoded = try WalletWireCodec.encodeCertificateResult(result)
            XCTAssertEqual(
                try certificateOracleBytes(
                    client,
                    operation: "wallet.wire.result.reencode",
                    call: result.call,
                    bytes: encoded,
                    sequence: &sequence
                ),
                encoded,
                "result call \(result.call.rawValue)"
            )
        }
    }

    func testSafeAdapterRejectsPinnedCertificateLeniencies() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let value): client = value
        case .unavailable:
            XCTAssertFalse(configuration.required)
            return
        }
        defer { client.close() }
        let fixture = try CertificateOracleFixture()
        var sequence = 61_000

        var presentEmpty = WalletWireOracleWriter()
        presentEmpty.writeCompactSize(1)
        presentEmpty.writeVarBytes(try fixture.certificate.binary(includingSignature: true))
        presentEmpty.writeByte(1)
        presentEmpty.writeCompactSize(0)
        presentEmpty.writeCompactSize(0)
        let emptyResponse = try certificateOracleRequest(
            client,
            operation: "wallet.wire.result.reencode",
            call: .listCertificates,
            bytes: [0] + presentEmpty.bytes,
            sequence: &sequence
        )
        XCTAssertFalse(emptyResponse.ok)
        XCTAssertEqual(emptyResponse.error?.category, "invalidArgument")

        let hostileCount = [UInt8](arrayLiteral:
            WalletCall.listCertificates.rawValue, 0, 0xfd, 0x11, 0x27
        )
        let hostileResponse = try certificateOracleRequest(
            client,
            operation: "wallet.wire.request.reencode",
            call: .listCertificates,
            bytes: hostileCount,
            sequence: &sequence
        )
        XCTAssertFalse(hostileResponse.ok)
        XCTAssertEqual(hostileResponse.error?.category, "resourceLimit")

        let trailingResponse = try certificateOracleRequest(
            client,
            operation: "wallet.wire.result.reencode",
            call: .relinquishCertificate,
            bytes: [0, 1],
            sequence: &sequence
        )
        XCTAssertFalse(trailingResponse.ok)
        XCTAssertEqual(trailingResponse.error?.category, "trailingData")

        let multiDiscovery = [UInt8](arrayLiteral: 0, 2)
        let discoveryResponse = try certificateOracleRequest(
            client,
            operation: "wallet.wire.result.reencode",
            call: .discoverByIdentityKey,
            bytes: multiDiscovery,
            sequence: &sequence
        )
        XCTAssertFalse(discoveryResponse.ok)
        XCTAssertEqual(discoveryResponse.error?.category, "invalidArgument")
    }
}

private struct CertificateOracleFixture {
    let type = try! CertificateTypeID([UInt8](repeating: 0x11, count: 32))
    let serial = try! CertificateSerialNumber([UInt8](repeating: 0x22, count: 32))
    let alpha = try! CertificateFieldName("alpha")
    let zeta = try! CertificateFieldName("zeta")
    let subject: PublicKey
    let certifier: PublicKey
    let verifier: PublicKey
    let outpoint: Outpoint
    let signature: ECDSASignature
    let certificate: Certificate
    let keyring: [CertificateFieldName: CertificateCiphertext]
    let textFields: [CertificateFieldName: String]
    let protocolID: WalletProtocolID
    let keyID: WalletKeyID

    init() throws {
        subject = try certificateOraclePrivateKey(2).publicKey
        certifier = try certificateOraclePrivateKey(3).publicKey
        verifier = try certificateOraclePrivateKey(4).publicKey
        outpoint = Outpoint(
            transactionID: try TransactionID(wireBytes: Array(0..<32)),
            outputIndex: 253
        )
        signature = try certificateOraclePrivateKey(3).sign(
            digest: BSVHashing.sha256([1, 2, 3])
        )
        keyring = [
            alpha: try CertificateCiphertext([1, 2]),
            zeta: try CertificateCiphertext([3, 4]),
        ]
        textFields = [alpha: "first", zeta: "last"]
        certificate = try Certificate(
            type: type,
            serialNumber: serial,
            subject: subject,
            certifier: certifier,
            revocationOutpoint: outpoint,
            fields: [
                alpha: try CertificateCiphertext([9, 8]),
                zeta: try CertificateCiphertext([7, 6]),
            ],
            signature: signature
        )
        protocolID = try WalletProtocolID(
            securityLevel: .everyAppAndCounterparty,
            name: "linkage test"
        )
        keyID = try WalletKeyID("linkage-key")
    }
}

private struct WalletWireOracleWriter {
    private(set) var bytes: [UInt8] = []

    mutating func writeByte(_ value: UInt8) { bytes.append(value) }
    mutating func writeCompactSize(_ value: UInt64) {
        if value < 0xfd {
            writeByte(UInt8(value))
        } else {
            writeByte(0xfd)
            writeByte(UInt8(truncatingIfNeeded: value))
            writeByte(UInt8(truncatingIfNeeded: value >> 8))
        }
    }
    mutating func writeVarBytes(_ value: [UInt8]) {
        writeCompactSize(UInt64(value.count))
        bytes.append(contentsOf: value)
    }
}

private func certificateOraclePrivateKey(_ scalar: UInt8) throws -> PrivateKey {
    var bytes = [UInt8](repeating: 0, count: 32)
    bytes[31] = scalar
    return try PrivateKey(bytes)
}

private func certificateOracleBytes(
    _ client: GoOracleClient,
    operation: String,
    call: WalletCall,
    bytes: [UInt8],
    sequence: inout Int
) throws -> [UInt8] {
    let response = try certificateOracleRequest(
        client,
        operation: operation,
        call: call,
        bytes: bytes,
        sequence: &sequence
    )
    XCTAssertTrue(response.ok, response.error?.category ?? "missing oracle error")
    guard case .object(let object)? = response.result,
          case .string(let hex)? = object["bytes"] else {
        throw CertificateOracleError.missingBytes
    }
    return try Hex.decode(hex, maximumDecodedByteCount: 300_000)
}

private func certificateOracleRequest(
    _ client: GoOracleClient,
    operation: String,
    call: WalletCall,
    bytes: [UInt8],
    sequence: inout Int
) throws -> GoOracleResponse {
    defer { sequence += 1 }
    return try client.request(
        id: "wallet-wire-certificate-\(sequence)",
        operation: operation,
        arguments: [
            "call": .string(String(call.rawValue)),
            "bytes": .string(Hex.encode(bytes)),
        ]
    )
}

private enum CertificateOracleError: Error { case missingBytes }
