import BSV
import BSVMessage
import Foundation
import Testing

@Suite("Package boundaries")
struct PackageStructureTests {
    @Test("BSVMessage is public and part of the modern umbrella")
    func messageProductAndUmbrella() throws {
        func requireType<T>(_: T.Type) {}
        requireType(SignedMessage.self)
        requireType(EncryptedMessage.self)

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
        #expect(!list.contains("\"BSVServices\""))
        #expect(manifest.contains("modernPublicModules.map { module in"))
        #expect(exports.contains("@_exported import BSVMessage"))
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

    @Test("BSVServices is absent")
    func emptyServicesModuleIsAbsent() throws {
        let manifest = try text(at: "Package.swift")
        let exports = try text(at: "Sources/BSV/Exports.swift")

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
            dependencies: ["BSVCore", "BSVTransaction"]
        )
        try expectTarget(
            "BSVWallet",
            in: manifest,
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys", "BSVTransaction"]
        )
        try expectTarget(
            "BSVAuth",
            in: manifest,
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys", "BSVTransaction", "BSVWallet"]
        )
    }

    @Test("README describes the message module and omits services")
    func readmeModuleBoundary() throws {
        let readme = try text(at: "README.md")
        #expect(readme.contains("`BSVMessage`"))
        #expect(readme.contains("`SignedMessage` from `BSVMessage`"))
        #expect(readme.contains("`EncryptedMessage` from `BSVMessage`"))
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
