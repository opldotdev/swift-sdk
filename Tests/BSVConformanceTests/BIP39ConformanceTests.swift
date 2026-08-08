import BSVCore
import BSVCrypto
import BSVCompat
import BSVKeys
import Foundation
import Testing

@Suite("BIP-39 conformance")
struct BIP39ConformanceTests {
    @Test("strict python-mnemonic manifest and MIT provenance verify")
    func manifestVerification() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let group = try #require(
            manifest.groups.first { $0.id == "bip39-python-mnemonic-v0.21" }
        )

        #expect(group.schema == FixtureManifestLoader.schema)
        #expect(group.source.url == "https://github.com/trezor/python-mnemonic")
        #expect(group.source.revision == "d4b106cdec196202d44628026fcb8fedc8ea50c1")
        #expect(group.license.identifier == "MIT")
        #expect(
            group.license.sha256
                == "d5e3c7c62a84e80073201e2f6e5130e9e6804fa05f8ac4f8b26a13c7d3969697"
        )
        #expect(
            Set(group.files.map(\.localPath)) == [
                "Permissive/PythonMnemonic/BIP39/english-vectors.json",
                "Permissive/PythonMnemonic/BIP39/english.txt",
            ]
        )
    }

    @Test("all 24 official English vectors match entropy, words, checksum, and TREZOR seed")
    func officialEnglishVectors() throws {
        let corpus = try loadFixture(
            PythonMnemonicCorpus.self,
            path: "Permissive/PythonMnemonic/BIP39/english-vectors.json"
        )
        #expect(corpus.english.count == 24)
        #expect(Set(corpus.english.map { $0.mnemonic.split(separator: " ").count }) == [12, 18, 24])

        for vector in corpus.english {
            let entropy = try Hex.decode(vector.entropy, maximumDecodedByteCount: 32)
            let encoded = try Mnemonic(entropy: entropy)
            #expect(encoded.phrase == vector.mnemonic)
            #expect(encoded.entropy == entropy)

            let decoded = try Mnemonic(vector.mnemonic)
            #expect(decoded == encoded)
            #expect(decoded.words == vector.mnemonic.split(separator: " ").map(String.init))
            #expect(Hex.encode(try decoded.seed(passphrase: "TREZOR").bytes) == vector.seed)
            #expect(try decoded.seed(passphrase: "TREZOR") == decoded.seed(passphrase: "TREZOR"))
        }
    }

    @Test("official English wordlist bytes have exact count, uniqueness, endpoints, and digest")
    func officialEnglishWordList() throws {
        let data = try fixtureData(path: "Permissive/PythonMnemonic/BIP39/english.txt")
        #expect(
            Hex.encode(BSVHashing.sha256(Array(data)).bytes)
                == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        )
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.hasSuffix("\n"))
        let words = text.split(separator: "\n").map(String.init)
        #expect(words.count == 2_048)
        #expect(Set(words).count == 2_048)
        #expect(words.first == "abandon")
        #expect(words.last == "zoo")
    }
}

private struct PythonMnemonicCorpus: Decodable {
    let english: [PythonMnemonicVector]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawVectors = try container.decode([[String]].self, forKey: .english)
        english = try rawVectors.map { values in
            guard values.count == 4 else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: decoder.codingPath, debugDescription: "Expected four fields")
                )
            }
            return PythonMnemonicVector(
                entropy: values[0],
                mnemonic: values[1],
                seed: values[2],
                extendedPrivateKey: values[3]
            )
        }
    }

    private enum CodingKeys: String, CodingKey {
        case english
    }
}

private struct PythonMnemonicVector {
    let entropy: String
    let mnemonic: String
    let seed: String
    let extendedPrivateKey: String
}

private func loadFixture<T: Decodable>(_ type: T.Type, path: String) throws -> T {
    try JSONDecoder().decode(T.self, from: fixtureData(path: path))
}

private func fixtureData(path: String) throws -> Data {
    guard let root = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
        throw BIP39FixtureError.missingFixtureRoot
    }
    return try Data(contentsOf: root.appendingPathComponent(path), options: [.mappedIfSafe])
}

private enum BIP39FixtureError: Error {
    case missingFixtureRoot
}
