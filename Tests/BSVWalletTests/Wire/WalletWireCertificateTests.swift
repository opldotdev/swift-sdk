import XCTest
import BSVCore
import BSVCrypto
import BSVKeys
import BSVTransaction
@testable import BSVWallet

final class WalletWireCertificateTests: XCTestCase {
    func testAllCertificateAndLinkageRequestsRoundTrip() throws {
        let fixture = try WalletWireCertificateFixture()
        let privilege = try WalletPrivilege(
            privileged: true,
            privilegedReason: "certificate review"
        )
        let direct = try WalletDirectCertificateAcquisition(
            serialNumber: fixture.serial,
            revocationOutpoint: fixture.outpoint,
            signature: fixture.signature,
            keyringRevealer: .publicKey(fixture.verifier),
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
            .acquireCertificate(try .init(
                type: fixture.type,
                certifier: fixture.certifier,
                fields: fixture.textFields,
                acquisition: .issuance(try .init(certifierURL: "https://issuer.example"))
            )),
            .listCertificates(try .init(
                certifiers: [fixture.certifier],
                types: [fixture.type],
                pagination: WalletPagination(limit: 10, offset: 2),
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
                pagination: try WalletPagination(limit: 4, offset: 1),
                seekPermission: true
            )),
            .discoverByAttributes(try .init(
                attributes: fixture.textFields,
                pagination: WalletPagination(limit: 4, offset: 1),
                seekPermission: false
            )),
        ]

        for (index, request) in requests.enumerated() {
            let originator = index.isMultiple(of: 2) ? "wallet.example" : "世"
            let encoded = try WalletWireCodec.encodeCertificateRequest(
                request,
                originator: originator
            )
            let decoded = try WalletWireCodec.decodeCertificateRequest(encoded)
            XCTAssertEqual(decoded.originator, originator)
            XCTAssertEqual(decoded.request.call, request.call)
            XCTAssertEqual(
                try WalletWireCodec.encodeCertificateRequest(
                    decoded.request,
                    originator: decoded.originator
                ),
                encoded,
                "request call \(request.call.rawValue)"
            )
        }
    }

    func testAllCertificateAndLinkageResultsRoundTrip() throws {
        let fixture = try WalletWireCertificateFixture()
        let identity = try WalletIdentityCertificate(
            certificate: fixture.certificate,
            certifierInfo: WalletIdentityCertifier(
                name: "Issuer",
                iconURL: "https://issuer.example/icon",
                description: "Trusted issuer",
                trust: 7
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
                        verifier: [7, 8]
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
            let decoded = try WalletWireCodec.decodeCertificateResult(
                encoded,
                expectedCall: result.call
            )
            XCTAssertEqual(decoded.call, result.call)
            XCTAssertEqual(
                try WalletWireCodec.encodeCertificateResult(decoded),
                encoded,
                "result call \(result.call.rawValue)"
            )
        }
    }

    func testMapsUseUTF8ByteOrder() throws {
        let fixture = try WalletWireCertificateFixture()
        let request = WalletWireCertificateRequest.discoverByAttributes(try .init(
            attributes: [fixture.zeta: "last", fixture.alpha: "first"]
        ))
        let encoded = try WalletWireCodec.encodeCertificateRequest(request, originator: "")
        let frame = try WalletWireCodec.decodeRequestFrame(encoded)
        XCTAssertEqual(frame.parameters[0], 2)
        XCTAssertEqual(frame.parameters[1], UInt8(fixture.alpha.value.utf8.count))
        XCTAssertEqual(
            Array(frame.parameters[2..<(2 + fixture.alpha.value.utf8.count)]),
            Array(fixture.alpha.value.utf8)
        )
    }

    func testBothDiscoveryCallsSupportMultipleCertificates() throws {
        let fixture = try WalletWireCertificateFixture()
        let identity = try WalletIdentityCertificate(
            certificate: fixture.certificate,
            certifierInfo: WalletIdentityCertifier(
                name: "Issuer",
                iconURL: "",
                description: "",
                trust: 1
            ),
            publiclyRevealedKeyring: fixture.keyring,
            decryptedFields: fixture.textFields
        )
        let discovered = try WalletDiscoverCertificatesResult(
            totalCertificates: 2,
            certificates: [identity, identity]
        )
        let results: [WalletWireCertificateResult] = [
            .discoverByIdentityKey(discovered),
            .discoverByAttributes(discovered),
        ]
        for result in results {
            let encoded = try WalletWireCodec.encodeCertificateResult(result)
            let decoded = try WalletWireCodec.decodeCertificateResult(
                encoded,
                expectedCall: result.call
            )
            XCTAssertEqual(try WalletWireCodec.encodeCertificateResult(decoded), encoded)
        }
    }
}

struct WalletWireCertificateFixture {
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
        subject = try walletTestPrivateKey(2).publicKey
        certifier = try walletTestPrivateKey(3).publicKey
        verifier = try walletTestPrivateKey(4).publicKey
        outpoint = Outpoint(
            transactionID: try TransactionID(wireBytes: Array(0..<32)),
            outputIndex: 253
        )
        signature = try walletTestPrivateKey(3).sign(
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
