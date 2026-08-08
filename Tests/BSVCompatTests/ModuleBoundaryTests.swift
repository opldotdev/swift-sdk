import BSVCompat
import BSVKeys
import Foundation
import Testing

@Suite("BSVCompat module boundary")
struct BSVCompatModuleBoundaryTests {
    @Test("compatibility families compile from the opt-in module")
    func compatibilitySymbolsCompile() {
        func requireType<T>(_: T.Type) {}

        requireType(BitcoinSignedMessage.self)
        requireType(BitcoinMessageSignature.self)
        requireType(ElectrumECIES.self)
        requireType(BitcoreECIES.self)
        requireType(ExtendedPrivateKey.self)
        requireType(ExtendedPublicKey.self)
        requireType(HDKeyPath.self)
        requireType(Mnemonic.self)
    }

    @Test("non-compatibility key formats remain available through BSVKeys")
    func nonCompatibilityKeySymbolsCompile() {
        func requireType<T>(_: T.Type) {}

        requireType(Address.self)
        requireType(WIF.self)
        requireType(PrivateKey.self)
        requireType(SharedSecretProof.self)
        requireType(KeyShare.self)
        requireType(KeySharing.self)
        requireType(BRC42DerivationError.self)
    }

    @Test("compatibility source does not re-export dependency modules")
    func compatibilitySourceHasNoExportedImports() throws {
        let compatSource = try swiftSource(
            below: repositoryRoot.appendingPathComponent("Sources/BSVCompat")
        )

        #expect(!compatSource.contains("@_exported import"))
    }

    @Test("the umbrella has no BSVCompat dependency or re-export")
    func umbrellaExcludesCompatibilityModule() throws {
        let root = repositoryRoot
        let manifest = try String(
            contentsOf: root.appendingPathComponent("Package.swift"),
            encoding: .utf8
        )
        let exports = try String(
            contentsOf: root.appendingPathComponent("Sources/BSV/Exports.swift"),
            encoding: .utf8
        )

        #expect(manifest.contains("let modernPublicModules"))
        #expect(manifest.contains(".library(name: \"BSVCompat\", targets: [\"BSVCompat\"])"))
        #expect(manifest.contains("name: \"BSVCompat\""))
        #expect(!exports.contains("BSVCompat"))
        let modernList = try #require(
            manifest.range(of: "let modernPublicModules")
        )
        let dependencyMap = try #require(
            manifest.range(of: "let modernPublicModuleDependencies")
        )
        #expect(!manifest[modernList.lowerBound..<dependencyMap.lowerBound].contains("BSVCompat"))
    }

    @Test("moved implementations have one source owner")
    func sourceOwnership() throws {
        let root = repositoryRoot
        let oldDirectories = ["Message", "ECIES", "HD", "Mnemonic"].map {
            root.appendingPathComponent("Sources/BSVKeys/\($0)").path
        }
        for path in oldDirectories {
            #expect(!FileManager.default.fileExists(atPath: path))
        }

        let compatRoot = root.appendingPathComponent("Sources/BSVCompat")
        let compatSource = try swiftSource(below: compatRoot)
        let keysSource = try swiftSource(
            below: root.appendingPathComponent("Sources/BSVKeys")
        )
        for declaration in [
            "public enum BitcoinSignedMessage",
            "public enum ElectrumECIES",
            "public enum BitcoreECIES",
            "public struct ExtendedPrivateKey",
            "public struct ExtendedPublicKey",
            "public struct Mnemonic",
        ] {
            #expect(compatSource.contains(declaration))
            #expect(!keysSource.contains(declaration))
        }
        #expect(keysSource.contains("public struct Address"))
        #expect(keysSource.contains("public struct WIF"))
    }

    @Test("inscription argument names match the Go public API")
    func inscriptionArgumentNames() throws {
        let inscriptionDirectory = repositoryRoot.appendingPathComponent(
            "Sources/BSVScript/Templates/Inscription"
        )
        let scriptSource = try swiftSource(below: inscriptionDirectory)
        let sourceFileNames = try FileManager.default.contentsOfDirectory(
            atPath: inscriptionDirectory.path
        )

        #expect(sourceFileNames == ["InscriptionArgs.swift"])
        #expect(scriptSource.contains("public struct InscriptionArgs"))
        #expect(scriptSource.contains("public struct EnrichedInscriptionArgs"))
        #expect(!scriptSource.contains("InscriptionArguments"))
        #expect(!scriptSource.contains("EnrichedInscriptionArguments"))
    }

    @Test("README compatibility language is explicit and uses no emoji")
    func readmePolicy() throws {
        let readme = try String(
            contentsOf: repositoryRoot.appendingPathComponent("README.md"),
            encoding: .utf8
        )
        let lowercase = readme.lowercased()
        #expect(readme.contains("## BSVCompat"))
        #expect(readme.contains("import BSVCompat"))
        #expect(!lowercase.contains("legacy address"))
        #expect(!lowercase.contains("legacy-address"))
        #expect(!readme.unicodeScalars.contains(where: isEmoji))
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func swiftSource(below directory: URL) throws -> String {
        let enumerator = try #require(
            FileManager.default.enumerator(
                at: directory,
                includingPropertiesForKeys: nil
            )
        )
        var source = ""
        for case let file as URL in enumerator where file.pathExtension == "swift" {
            source += try String(contentsOf: file, encoding: .utf8)
        }
        return source
    }

    private func isEmoji(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x1f000...0x1faff, 0x2600...0x27bf:
            true
        default:
            false
        }
    }
}
