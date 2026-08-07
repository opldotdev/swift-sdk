import BSVCore
import BSVKeys
import Foundation
import Testing

@Suite("BIP32Conformance")
struct BIP32ConformanceTests {
    @Test("all official bitcoin/bips vectors derive, serialize, parse, and neuter")
    func officialValidVectors() throws {
        let fixture = try loadOfficialFixture()
        #expect(fixture.validVectors.count == 4)
        #expect(fixture.validVectors.flatMap(\.nodes).count == 17)

        for vector in fixture.validVectors {
            let seed = try Hex.decode(
                vector.seed,
                maximumDecodedByteCount: vector.seed.utf8.count / 2
            )
            let master = try ExtendedPrivateKey(seed: seed, network: .mainnet)

            for node in vector.nodes {
                let derived = try master.derived(path: node.path)
                #expect(derived.serialized == node.xprv)
                #expect(derived.description == "<redacted extended private key>")
                #expect(derived.neutered.serialized == node.xpub)
                #expect(try ExtendedPrivateKey(node.xprv) == derived)
                #expect(try ExtendedPublicKey(node.xpub) == derived.neutered)
            }

            for (parent, child) in zip(vector.nodes, vector.nodes.dropFirst()) {
                let childNumber = try #require(HDKeyPath(child.path).components.last)
                if !childNumber.isHardened {
                    let parentPublic = try ExtendedPublicKey(parent.xpub)
                    #expect(try parentPublic.derived(childNumber).serialized == child.xpub)
                }
            }
        }
    }

    @Test("every official invalid extended key is rejected")
    func officialInvalidVectors() throws {
        let fixture = try loadOfficialFixture()
        #expect(fixture.invalidExtendedKeys.count == 16)
        for text in fixture.invalidExtendedKeys {
            #expect(throws: (any Error).self) {
                try ExtendedPrivateKey(text)
            }
            #expect(throws: (any Error).self) {
                try ExtendedPublicKey(text)
            }
        }
    }

    @Test("official vectors are covered by strict pinned provenance")
    func fixtureProvenance() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "bitcoin-bips-bip32-ed4ffcb6a48d" }
        )
        #expect(group.source.url == "https://github.com/bitcoin/bips")
        #expect(group.source.revision == "ed4ffcb6a48d4dc4fdfc11cdba783c233db8c66e")
        #expect(group.license.identifier == "BSD-2-Clause")
        #expect(group.license.file == "Licenses/bitcoin-bips-bip32-bsd-2-clause.txt")
        #expect(group.files.count == 1)
        #expect(
            group.files[0].localPath
                == "Permissive/BitcoinBIPs/BIP32/bip-0032-vectors.json"
        )
    }
}

private struct BIP32Fixture: Decodable {
    let validVectors: [BIP32ValidVector]
    let invalidExtendedKeys: [String]
}

private struct BIP32ValidVector: Decodable {
    let seed: String
    let nodes: [BIP32Node]
}

private struct BIP32Node: Decodable {
    let path: String
    let xpub: String
    let xprv: String
}

private func loadOfficialFixture() throws -> BIP32Fixture {
    let fixtureRoot = try #require(
        Bundle.module.url(forResource: "Fixtures", withExtension: nil)
    )
    return try JSONDecoder().decode(
        BIP32Fixture.self,
        from: Data(
            contentsOf: fixtureRoot.appendingPathComponent(
                "Permissive/BitcoinBIPs/BIP32/bip-0032-vectors.json"
            )
        )
    )
}
