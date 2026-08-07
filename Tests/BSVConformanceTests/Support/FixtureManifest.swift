import Crypto
import Foundation

struct FixtureManifest: Equatable {
    let groups: [FixtureGroup]
}

struct FixtureGroup: Decodable, Equatable {
    let schema: String
    let id: String
    let source: FixtureSource
    let license: FixtureLicense
    let notes: String?
    let files: [FixtureFile]

    private enum CodingKeys: String, CodingKey {
        case schema
        case id
        case source
        case license
        case notes
        case files
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            in: decoder,
            allowed: ["schema", "id", "source", "license", "notes", "files"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schema = try container.decode(String.self, forKey: .schema)
        id = try container.decode(String.self, forKey: .id)
        source = try container.decode(FixtureSource.self, forKey: .source)
        license = try container.decode(FixtureLicense.self, forKey: .license)
        notes = try container.decodeIfPresent(String.self, forKey: .notes)
        files = try container.decode([FixtureFile].self, forKey: .files)
    }
}

struct FixtureSource: Decodable, Equatable {
    let url: String
    let revision: String

    private enum CodingKeys: String, CodingKey {
        case url
        case revision
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(in: decoder, allowed: ["url", "revision"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        url = try container.decode(String.self, forKey: .url)
        revision = try container.decode(String.self, forKey: .revision)
    }
}

struct FixtureLicense: Decodable, Equatable {
    let identifier: String
    let file: String
    let sha256: String

    private enum CodingKeys: String, CodingKey {
        case identifier
        case file
        case sha256
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(in: decoder, allowed: ["identifier", "file", "sha256"])
        let container = try decoder.container(keyedBy: CodingKeys.self)
        identifier = try container.decode(String.self, forKey: .identifier)
        file = try container.decode(String.self, forKey: .file)
        sha256 = try container.decode(String.self, forKey: .sha256)
    }
}

struct FixtureFile: Decodable, Equatable {
    let originalPath: String
    let localPath: String
    let sha256: String
    let transformation: String
    let notes: String?

    private enum CodingKeys: String, CodingKey {
        case originalPath
        case localPath
        case sha256
        case transformation
        case notes
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(
            in: decoder,
            allowed: ["originalPath", "localPath", "sha256", "transformation", "notes"]
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        originalPath = try container.decode(String.self, forKey: .originalPath)
        localPath = try container.decode(String.self, forKey: .localPath)
        sha256 = try container.decode(String.self, forKey: .sha256)
        transformation = try container.decode(String.self, forKey: .transformation)
        notes = try container.decodeIfPresent(String.self, forKey: .notes)
    }
}

enum FixtureManifestError: Error, Equatable {
    case bundledFixtureRootUnavailable
    case fixtureRootNotDirectory
    case manifestDirectoryNotDirectory
    case malformedJSON(manifest: String)
    case unsupportedSchema(manifest: String, schema: String)
    case invalidField(manifest: String, field: String)
    case duplicateGroupID(String)
    case duplicateLocalPath(String)
    case invalidRelativePath(path: String, field: String)
    case reservedLocalPath(String)
    case symbolicLink(path: String)
    case missingRegularFile(path: String)
    case unreadableDirectory(path: String)
    case unreadableFile(path: String)
    case malformedSHA256(path: String)
    case hashMismatch(path: String, expected: String, actual: String)
    case unreferencedFile(path: String)
}

struct FixtureManifestLoader {
    static let schema = "bsv-fixture-manifest/1"

    private let fixtureRoot: URL
    private let fileManager: FileManager

    init(fixtureRoot: URL, fileManager: FileManager = .default) {
        self.fixtureRoot = fixtureRoot.standardizedFileURL
        self.fileManager = fileManager
    }

    static func loadBundled() throws -> FixtureManifest {
        guard let fixtureRoot = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
            throw FixtureManifestError.bundledFixtureRootUnavailable
        }
        return try FixtureManifestLoader(fixtureRoot: fixtureRoot).load()
    }

    static func load(from fixtureRoot: URL) throws -> FixtureManifest {
        try FixtureManifestLoader(fixtureRoot: fixtureRoot).load()
    }

    func load() throws -> FixtureManifest {
        try requireDirectory(fixtureRoot, relativePath: ".", missingError: .fixtureRootNotDirectory)
        try rejectSymlinks(in: fixtureRoot, relativePath: "")

        let manifestsURL = fixtureRoot.appendingPathComponent("Manifests", isDirectory: true)
        try requireDirectory(
            manifestsURL,
            relativePath: "Manifests",
            missingError: .manifestDirectoryNotDirectory
        )

        let fragmentURLs: [URL]
        do {
            fragmentURLs = try fileManager.contentsOfDirectory(
                at: manifestsURL,
                includingPropertiesForKeys: nil,
                options: []
            )
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        } catch {
            throw FixtureManifestError.unreadableDirectory(path: "Manifests")
        }

        var groups: [FixtureGroup] = []
        var groupIDs = Set<String>()
        var localPaths = Set<String>()

        for fragmentURL in fragmentURLs {
            let manifestName = fragmentURL.lastPathComponent
            try requireRegularFile(fragmentURL, relativePath: "Manifests/\(manifestName)")

            let data: Data
            do {
                data = try Data(contentsOf: fragmentURL, options: [.mappedIfSafe])
            } catch {
                throw FixtureManifestError.unreadableFile(path: "Manifests/\(manifestName)")
            }

            let group: FixtureGroup
            do {
                group = try JSONDecoder().decode(FixtureGroup.self, from: data)
            } catch {
                throw FixtureManifestError.malformedJSON(manifest: manifestName)
            }

            try validate(group, manifestName: manifestName)

            guard groupIDs.insert(group.id).inserted else {
                throw FixtureManifestError.duplicateGroupID(group.id)
            }
            for file in group.files {
                guard localPaths.insert(file.localPath).inserted else {
                    throw FixtureManifestError.duplicateLocalPath(file.localPath)
                }
            }
            groups.append(group)
        }

        for group in groups {
            let licenseURL = try regularFileURL(for: group.license.file, field: "license.file")
            let licenseContents: Data
            do {
                licenseContents = try Data(contentsOf: licenseURL, options: [.mappedIfSafe])
            } catch {
                throw FixtureManifestError.unreadableFile(path: group.license.file)
            }
            let actualLicenseHash = sha256(licenseContents)
            guard actualLicenseHash == group.license.sha256 else {
                throw FixtureManifestError.hashMismatch(
                    path: group.license.file,
                    expected: group.license.sha256,
                    actual: actualLicenseHash
                )
            }
            for file in group.files {
                let fileURL = try regularFileURL(for: file.localPath, field: "files.localPath")
                let contents: Data
                do {
                    contents = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
                } catch {
                    throw FixtureManifestError.unreadableFile(path: file.localPath)
                }
                let actualHash = sha256(contents)
                guard actualHash == file.sha256 else {
                    throw FixtureManifestError.hashMismatch(
                        path: file.localPath,
                        expected: file.sha256,
                        actual: actualHash
                    )
                }
            }
        }

        let declaredPaths = Set(groups.flatMap(\.files).map(\.localPath))
        for dataPath in try fixtureDataPaths() where !declaredPaths.contains(dataPath) {
            throw FixtureManifestError.unreferencedFile(path: dataPath)
        }

        return FixtureManifest(groups: groups)
    }

    private func validate(_ group: FixtureGroup, manifestName: String) throws {
        guard group.schema == Self.schema else {
            throw FixtureManifestError.unsupportedSchema(
                manifest: manifestName,
                schema: group.schema
            )
        }
        guard !group.id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw FixtureManifestError.invalidField(manifest: manifestName, field: "id")
        }
        guard
            let sourceURL = URL(string: group.source.url),
            sourceURL.scheme != nil,
            !group.source.revision.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            throw FixtureManifestError.invalidField(manifest: manifestName, field: "source")
        }
        guard !group.license.identifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw FixtureManifestError.invalidField(manifest: manifestName, field: "license.identifier")
        }
        try validateRelativePath(group.license.file, field: "license.file")
        guard group.license.file.hasPrefix("Licenses/") else {
            throw FixtureManifestError.invalidRelativePath(
                path: group.license.file,
                field: "license.file"
            )
        }
        guard isLowercaseSHA256(group.license.sha256) else {
            throw FixtureManifestError.malformedSHA256(path: group.license.file)
        }
        guard !group.files.isEmpty else {
            throw FixtureManifestError.invalidField(manifest: manifestName, field: "files")
        }

        for file in group.files {
            try validateRelativePath(file.originalPath, field: "files.originalPath")
            try validateRelativePath(file.localPath, field: "files.localPath")
            if isReservedDataPath(file.localPath) {
                throw FixtureManifestError.reservedLocalPath(file.localPath)
            }
            guard !file.transformation.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw FixtureManifestError.invalidField(
                    manifest: manifestName,
                    field: "files.transformation"
                )
            }
            guard isLowercaseSHA256(file.sha256) else {
                throw FixtureManifestError.malformedSHA256(path: file.localPath)
            }
        }
    }

    private func isLowercaseSHA256(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy { byte in
            (48...57).contains(byte) || (97...102).contains(byte)
        }
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func validateRelativePath(_ path: String, field: String) throws {
        guard !path.isEmpty, !path.contains("\\") else {
            throw FixtureManifestError.invalidRelativePath(path: path, field: field)
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        let beginsWithWindowsDrive = components.first.map { component in
            let bytes = Array(component.utf8)
            return bytes.count == 2
                && ((65...90).contains(bytes[0]) || (97...122).contains(bytes[0]))
                && bytes[1] == 58
        } ?? false
        guard
            !path.hasPrefix("/"),
            !beginsWithWindowsDrive,
            components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
        else {
            throw FixtureManifestError.invalidRelativePath(path: path, field: field)
        }

        let resolved = fixtureRoot.appendingPathComponent(path).standardizedFileURL
        let rootPrefix = fixtureRoot.path.hasSuffix("/") ? fixtureRoot.path : fixtureRoot.path + "/"
        guard resolved.path.hasPrefix(rootPrefix) else {
            throw FixtureManifestError.invalidRelativePath(path: path, field: field)
        }
    }

    private func regularFileURL(for relativePath: String, field: String) throws -> URL {
        try validateRelativePath(relativePath, field: field)
        let fileURL = fixtureRoot.appendingPathComponent(relativePath).standardizedFileURL
        try requireRegularFile(fileURL, relativePath: relativePath)
        return fileURL
    }

    private func requireDirectory(
        _ url: URL,
        relativePath: String,
        missingError: FixtureManifestError
    ) throws {
        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try fileManager.attributesOfItem(atPath: url.path)
        } catch {
            throw missingError
        }
        if attributes[.type] as? FileAttributeType == .typeSymbolicLink {
            throw FixtureManifestError.symbolicLink(path: relativePath)
        }
        guard attributes[.type] as? FileAttributeType == .typeDirectory else {
            throw missingError
        }
    }

    private func requireRegularFile(_ url: URL, relativePath: String) throws {
        let components = relativePath.split(separator: "/")
        var currentURL = fixtureRoot
        var currentPath = ""
        for component in components {
            currentURL.appendPathComponent(String(component))
            currentPath = currentPath.isEmpty ? String(component) : "\(currentPath)/\(component)"
            let attributes: [FileAttributeKey: Any]
            do {
                attributes = try fileManager.attributesOfItem(atPath: currentURL.path)
            } catch {
                throw FixtureManifestError.missingRegularFile(path: relativePath)
            }
            if attributes[.type] as? FileAttributeType == .typeSymbolicLink {
                throw FixtureManifestError.symbolicLink(path: currentPath)
            }
        }

        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try fileManager.attributesOfItem(atPath: url.path)
        } catch {
            throw FixtureManifestError.missingRegularFile(path: relativePath)
        }
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw FixtureManifestError.missingRegularFile(path: relativePath)
        }
    }

    private func rejectSymlinks(in directoryURL: URL, relativePath: String) throws {
        let children: [URL]
        do {
            children = try fileManager.contentsOfDirectory(
                at: directoryURL,
                includingPropertiesForKeys: nil,
                options: []
            )
        } catch {
            throw FixtureManifestError.unreadableDirectory(
                path: relativePath.isEmpty ? "." : relativePath
            )
        }

        for child in children {
            let childPath = relativePath.isEmpty
                ? child.lastPathComponent
                : "\(relativePath)/\(child.lastPathComponent)"
            let attributes: [FileAttributeKey: Any]
            do {
                attributes = try fileManager.attributesOfItem(atPath: child.path)
            } catch {
                throw FixtureManifestError.unreadableFile(path: childPath)
            }
            let fileType = attributes[.type] as? FileAttributeType
            if fileType == .typeSymbolicLink {
                throw FixtureManifestError.symbolicLink(path: childPath)
            }
            if fileType == .typeDirectory {
                try rejectSymlinks(in: child, relativePath: childPath)
            }
        }
    }

    private func fixtureDataPaths() throws -> [String] {
        try fixtureDataPaths(in: fixtureRoot, relativePath: "").sorted()
    }

    private func fixtureDataPaths(in directoryURL: URL, relativePath: String) throws -> [String] {
        let children: [URL]
        do {
            children = try fileManager.contentsOfDirectory(
                at: directoryURL,
                includingPropertiesForKeys: nil,
                options: []
            )
        } catch {
            throw FixtureManifestError.unreadableDirectory(
                path: relativePath.isEmpty ? "." : relativePath
            )
        }

        var paths: [String] = []
        for child in children {
            let childPath = relativePath.isEmpty
                ? child.lastPathComponent
                : "\(relativePath)/\(child.lastPathComponent)"
            if childPath == "README.md" || isReservedMetadataPath(childPath) {
                continue
            }

            let attributes: [FileAttributeKey: Any]
            do {
                attributes = try fileManager.attributesOfItem(atPath: child.path)
            } catch {
                throw FixtureManifestError.unreadableFile(path: childPath)
            }
            switch attributes[.type] as? FileAttributeType {
            case .typeRegular:
                paths.append(childPath)
            case .typeDirectory:
                paths.append(contentsOf: try fixtureDataPaths(in: child, relativePath: childPath))
            case .typeSymbolicLink:
                throw FixtureManifestError.symbolicLink(path: childPath)
            default:
                throw FixtureManifestError.missingRegularFile(path: childPath)
            }
        }
        return paths
    }

    private func isReservedMetadataPath(_ path: String) -> Bool {
        path == "Manifests" || path.hasPrefix("Manifests/")
            || path == "Licenses" || path.hasPrefix("Licenses/")
    }

    private func isReservedDataPath(_ path: String) -> Bool {
        path == "README.md" || isReservedMetadataPath(path)
    }
}

private struct AnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func rejectUnknownKeys(in decoder: Decoder, allowed: Set<String>) throws {
    let container = try decoder.container(keyedBy: AnyCodingKey.self)
    if let unknownKey = container.allKeys.map(\.stringValue).first(where: { !allowed.contains($0) }) {
        throw DecodingError.dataCorrupted(
            .init(codingPath: decoder.codingPath, debugDescription: "Unknown key: \(unknownKey)")
        )
    }
}
