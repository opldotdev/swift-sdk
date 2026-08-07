import BSVCore
import BSVKeys
import Foundation
import Testing

@Suite("ECDSAP2DConformance", .serialized)
struct ECDSAP2DConformanceTests {
    @Test("Decred ECDSA fixture provenance and hashes verify")
    func permissiveFixtureProvenance() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "decred-ecdsa-p2d-cc5e1d63" }
        )

        #expect(group.source.url == "https://github.com/decred/dcrd")
        #expect(group.source.revision == "cc5e1d635561c2cfb825530c1808f9f2b3cbdf36")
        #expect(group.license.identifier == "ISC")
        #expect(group.license.file == "Licenses/decred-ecdsa-isc-p2d.txt")
        #expect(
            group.license.sha256
                == "480be5fb1be03ff19fd71d863f453f16262e98d4e568f5bccfcb7aa3ccf8cf0d"
        )
        #expect(group.files.count == 1)
    }

    @Test("Sage-verified RFC 6979 vectors match exact compact and DER bytes")
    func exactSigningVectors() throws {
        let fixture: ECDSAP2DFixture = try loadFixture()

        for vector in fixture.signingVectors {
            let privateKey = try PrivateKey(decode(vector.privateKey))
            let digest = try Hash256(decode(vector.digest))
            let expectedCompact = try decode(vector.compact)
            let expectedDER = try decode(vector.der)
            let signature = try privateKey.sign(digest: digest)

            #expect(signature.compactBytes == expectedCompact)
            #expect(signature.derBytes == expectedDER)
            #expect(privateKey.publicKey.verify(signature, digest: digest))
            #expect(try ECDSASignature(compactBytes: expectedCompact) == signature)
            #expect(try ECDSASignature(derBytes: expectedDER) == signature)
        }
    }

    @Test("direct Decred malformed DER vectors are all rejected")
    func strictDERRejectVectors() throws {
        let fixture: ECDSAP2DFixture = try loadFixture()

        for encoded in fixture.strictDERReject {
            let der = try decode(encoded)
            #expect(throws: ECDSASignatureError.invalidDEREncoding) {
                try ECDSASignature(derBytes: der)
            }
        }
    }

    private func loadFixture() throws -> ECDSAP2DFixture {
        let fixtureRoot = try #require(
            Bundle.module.url(forResource: "Fixtures", withExtension: nil)
        )
        return try JSONDecoder().decode(
            ECDSAP2DFixture.self,
            from: Data(
                contentsOf: fixtureRoot.appendingPathComponent(
                    "Permissive/Decred/ECDSAP2D/signature-vectors.json"
                )
            )
        )
    }

    private func decode(_ text: String) throws -> [UInt8] {
        try Hex.decode(text, maximumDecodedByteCount: 256)
    }
}

private struct ECDSAP2DFixture: Decodable {
    let signingVectors: [ECDSAP2DSigningVector]
    let strictDERReject: [String]
}

private struct ECDSAP2DSigningVector: Decodable {
    let privateKey: String
    let digest: String
    let compact: String
    let der: String
}
