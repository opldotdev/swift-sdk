import BSV
import BSVKVStore
import BSVMessage
import BSVRegistry
import BSVStorage
import Foundation
import Testing

@Suite("Package boundaries")
struct PackageStructureTests {
    @Test("feature cores are public umbrella modules")
    func publicProductsAndUmbrella() throws {
        func requireType<T>(_: T.Type) {}
        requireType(SignedMessage.self)
        requireType(EncryptedMessage.self)
        requireType(KVStoreToken.self)
        requireType(UHRPURL.self)
        requireType(RegistryDefinition.self)
        requireType(DisplayableIdentity.self)
        requireType(OverlayAdminToken.self)

        let manifest = try text(at: "Package.swift")
        let exports = try text(at: "Sources/BSV/Exports.swift")
        let modernModules = try #require(
            manifest.range(of: "let modernPublicModules")
        )
        let dependencyMap = try #require(
            manifest.range(of: "let modernPublicModuleDependencies")
        )
        let list = manifest[modernModules.lowerBound..<dependencyMap.lowerBound]

        #expect(list.contains("\"BSVMessage\""))
        #expect(list.contains("\"BSVKVStore\""))
        #expect(list.contains("\"BSVStorage\""))
        #expect(list.contains("\"BSVOverlay\""))
        #expect(list.contains("\"BSVRegistry\""))
        #expect(list.contains("\"BSVIdentity\""))
        #expect(!list.contains("\"BSVServices\""))
        #expect(manifest.contains("modernPublicModules.map { module in"))
        #expect(exports.contains("@_exported import BSVMessage"))
        #expect(exports.contains("@_exported import BSVKVStore"))
        #expect(exports.contains("@_exported import BSVStorage"))
        #expect(exports.contains("@_exported import BSVOverlay"))
        #expect(exports.contains("@_exported import BSVRegistry"))
        #expect(exports.contains("@_exported import BSVIdentity"))
    }

    @Test("portable messages have one source owner")
    func portableMessageSourceOwnership() throws {
        let messageSource = try swiftSource(below: "Sources/BSVMessage")
        let oldMessageSource = try swiftSource(below: "Sources/BSVAuth/Message")
        let authSource = try swiftSource(below: "Sources/BSVAuth")
        #expect(oldMessageSource.isEmpty)
        for declaration in [
            "public enum PortableMessageError",
            "public struct PortableMessageLimits",
            "public struct SignedMessage",
            "public struct EncryptedMessage",
        ] {
            #expect(messageSource.contains(declaration))
            #expect(!authSource.contains(declaration))
        }
        #expect(!authSource.contains("typealias SignedMessage"))
        #expect(!authSource.contains("typealias EncryptedMessage"))
    }

    @Test("BSVOverlay owns overlay source while BSVServices remains absent")
    func overlaySourceOwnership() throws {
        let manifest = try text(at: "Package.swift")
        let exports = try text(at: "Sources/BSV/Exports.swift")
        let overlaySource = try swiftSource(below: "Sources/BSVOverlay")

        #expect(manifest.contains("BSVOverlay"))
        #expect(exports.contains("BSVOverlay"))
        #expect(overlaySource.contains("public struct TaggedBEEF"))
        #expect(overlaySource.contains("public protocol LookupFacilitator"))
        #expect(overlaySource.contains("public enum OverlayAdminTokenCodec"))
        #expect(!manifest.contains("BSVServices"))
        #expect(!exports.contains("BSVServices"))
        #expect(try swiftSource(below: "Sources/BSVServices").isEmpty)
        #expect(try swiftSource(below: "Tests/BSVServicesTests").isEmpty)
        let retiredReadme = try text(at: "Tests/BSVServicesTests/README.md")
        #expect(retiredReadme.contains("Repository safety policy protects this README"))
        #expect(retiredReadme.contains("no\n`BSVServices` product, target, test target, or Swift source"))
    }

    @Test("upper target dependencies match source imports")
    func prunedTargetDependencies() throws {
        let manifest = try text(at: "Package.swift")

        try expectTarget(
            "BSVMessage",
            in: manifest,
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys"]
        )
        try expectTarget(
            "BSVNetwork",
            in: manifest,
            dependencies: ["BSVCore", "BSVTransaction", "BSVSPV"]
        )
        try expectTarget(
            "BSVOverlay",
            in: manifest,
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys", "BSVScript", "BSVTransaction"]
        )
        try expectTarget(
            "BSVKVStore",
            in: manifest,
            dependencies: ["BSVKeys", "BSVScript"]
        )
        try expectTarget(
            "BSVStorage",
            in: manifest,
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys"]
        )
        try expectTarget(
            "BSVRegistry",
            in: manifest,
            dependencies: ["BSVCore", "BSVKeys", "BSVOverlay", "BSVScript", "BSVTransaction", "BSVWallet"]
        )
        try expectTarget(
            "BSVWallet",
            in: manifest,
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys", "BSVScript", "BSVTransaction"]
        )
        try expectTarget(
            "BSVAuth",
            in: manifest,
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys", "BSVTransaction", "BSVWallet"]
        )
        try expectTarget(
            "BSVIdentity",
            in: manifest,
            dependencies: ["BSVCore", "BSVKeys", "BSVScript", "BSVTransaction", "BSVWallet"]
        )
    }

    @Test("README describes public feature modules and omits services")
    func readmeModuleBoundary() throws {
        let readme = try text(at: "README.md")
        #expect(readme.contains("`BSVMessage`"))
        #expect(readme.contains("`BSVKVStore`"))
        #expect(readme.contains("`BSVStorage`"))
        #expect(readme.contains("`SignedMessage` from `BSVMessage`"))
        #expect(readme.contains("`EncryptedMessage` from `BSVMessage`"))
        #expect(readme.contains("`BSVIdentity`"))
        #expect(readme.contains("`BSVRegistry`"))
        #expect(!readme.contains("BSVServices"))
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func text(at relativePath: String) throws -> String {
        try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    private func swiftSource(below relativePath: String) throws -> String {
        let directory = repositoryRoot.appendingPathComponent(relativePath)
        guard FileManager.default.fileExists(atPath: directory.path) else { return "" }
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

    private func expectTarget(
        _ name: String,
        in manifest: String,
        dependencies: [String]
    ) throws {
        let escapedName = NSRegularExpression.escapedPattern(for: name)
        let pattern = #"(?s)\.target\(\s*name: \""#
            + escapedName
            + #"\",.*?\n        \),"#
        let expression = try NSRegularExpression(pattern: pattern)
        let range = NSRange(manifest.startIndex..., in: manifest)
        let match = try #require(expression.firstMatch(in: manifest, range: range))
        let swiftRange = try #require(Range(match.range, in: manifest))
        let block = String(manifest[swiftRange])

        let found = Set(block.matches(of: /"(BSV[A-Za-z0-9]+)"/).map { String($0.1) })
        #expect(found == Set(dependencies + [name]))
    }
}
