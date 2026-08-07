import Crypto
import Foundation
import Testing

@Suite("FixtureManifest")
struct FixtureManifestTests {
    @Test("loads a valid fragment and verifies its provenance")
    func loadsValidFragment() throws {
        try withFixtureRoot { fixture in
            try fixture.writeLicense("license", at: "Licenses/example.txt")
            try fixture.writeData("independently authored vector", at: "Permissive/Example/vector.txt")
            try fixture.writeManifest(
                fixture.manifest(
                    id: "example-v1",
                    licenseFile: "Licenses/example.txt",
                    files: [
                        fixture.fileEntry(
                            originalPath: "tests/vector.txt",
                            localPath: "Permissive/Example/vector.txt",
                            contents: "independently authored vector",
                            notes: "small bootstrap case"
                        )
                    ],
                    notes: "independently authored"
                ),
                named: "example.json"
            )

            let manifest = try FixtureManifestLoader.load(from: fixture.root)

            #expect(manifest.groups.map(\.id) == ["example-v1"])
            #expect(manifest.groups[0].source.revision == "0123456789abcdef")
            #expect(manifest.groups[0].files[0].transformation == "independently authored")
        }
    }

    @Test("loads the bundled fixture root and registered packet groups")
    func loadsBundledFixtureRoot() throws {
        let manifest = try FixtureManifestLoader.loadBundled()
        let groupIDs = Set(manifest.groups.map(\.id))
        #expect(groupIDs.contains("compactsize-btcd-v0.24.2"))
        #expect(groupIDs.contains("go-stdlib-encoding-go1.24.3"))
        #expect(groupIDs.contains("bsvutil-base58-1d77cf353ea9"))
    }

    @Test("permits an empty fragment directory")
    func permitsEmptyFragmentDirectory() throws {
        try withFixtureRoot { fixture in
            let manifest = try FixtureManifestLoader(fixtureRoot: fixture.root).load()
            #expect(manifest.groups.isEmpty)
        }
    }

    @Test("merges fragments in deterministic filename order")
    func deterministicMergeOrder() throws {
        try withFixtureRoot { fixture in
            try fixture.writeLicense("license", at: "Licenses/example.txt")
            try fixture.writeData("second bytes", at: "Permissive/second.txt")
            try fixture.writeData("first bytes", at: "Permissive/first.txt")
            try fixture.writeManifest(
                fixture.manifest(
                    id: "second-group",
                    files: [
                        fixture.fileEntry(
                            originalPath: "upstream/second.txt",
                            localPath: "Permissive/second.txt",
                            contents: "second bytes"
                        )
                    ]
                ),
                named: "20-second.json"
            )
            try fixture.writeManifest(
                fixture.manifest(
                    id: "first-group",
                    files: [
                        fixture.fileEntry(
                            originalPath: "upstream/first.txt",
                            localPath: "Permissive/first.txt",
                            contents: "first bytes"
                        )
                    ]
                ),
                named: "10-first.json"
            )

            let manifest = try FixtureManifestLoader.load(from: fixture.root)
            #expect(manifest.groups.map(\.id) == ["first-group", "second-group"])
        }
    }

    @Test("rejects duplicate group IDs across fragments")
    func rejectsDuplicateGroupIDs() throws {
        try withFixtureRoot { fixture in
            try fixture.writeLicense("license", at: "Licenses/example.txt")
            try fixture.writeData("one", at: "Permissive/one.txt")
            try fixture.writeData("two", at: "Permissive/two.txt")
            try fixture.writeManifest(
                fixture.manifest(
                    id: "duplicate",
                    files: [fixture.fileEntry(localPath: "Permissive/one.txt", contents: "one")]
                ),
                named: "one.json"
            )
            try fixture.writeManifest(
                fixture.manifest(
                    id: "duplicate",
                    files: [fixture.fileEntry(localPath: "Permissive/two.txt", contents: "two")]
                ),
                named: "two.json"
            )

            expectLoaderError(.duplicateGroupID("duplicate"), fixture: fixture)
        }
    }

    @Test("rejects duplicate local paths across fragments")
    func rejectsDuplicateLocalPaths() throws {
        try withFixtureRoot { fixture in
            try fixture.writeLicense("license", at: "Licenses/example.txt")
            try fixture.writeData("shared", at: "Permissive/shared.txt")
            let entry = fixture.fileEntry(localPath: "Permissive/shared.txt", contents: "shared")
            try fixture.writeManifest(
                fixture.manifest(id: "one", files: [entry]),
                named: "one.json"
            )
            try fixture.writeManifest(
                fixture.manifest(id: "two", files: [entry]),
                named: "two.json"
            )

            expectLoaderError(.duplicateLocalPath("Permissive/shared.txt"), fixture: fixture)
        }
    }

    @Test("rejects unsupported schema versions")
    func rejectsUnsupportedSchema() throws {
        try withFixtureRoot { fixture in
            var manifest = fixture.manifest(id: "unknown")
            manifest["schema"] = "bsv-fixture-manifest/2"
            try fixture.writeManifest(manifest, named: "unknown.json")

            expectLoaderError(
                .unsupportedSchema(manifest: "unknown.json", schema: "bsv-fixture-manifest/2"),
                fixture: fixture
            )
        }
    }

    @Test("rejects malformed JSON and unknown fields", arguments: [false, true])
    func rejectsMalformedJSON(hasUnknownField: Bool) throws {
        try withFixtureRoot { fixture in
            if hasUnknownField {
                var manifest = fixture.manifest(id: "unknown-field")
                manifest["unexpected"] = true
                try fixture.writeManifest(manifest, named: "bad.json")
            } else {
                try fixture.writeRawManifest(Data("{".utf8), named: "bad.json")
            }

            expectLoaderError(.malformedJSON(manifest: "bad.json"), fixture: fixture)
        }
    }

    @Test(
        "rejects hostile relative paths",
        arguments: [
            "/absolute/file.txt",
            "C:/absolute/file.txt",
            "",
            "./file.txt",
            "folder/../file.txt",
            "folder//file.txt",
            "folder\\file.txt",
            "folder/../../outside.txt",
        ]
    )
    func rejectsHostileLocalPaths(path: String) throws {
        try withFixtureRoot { fixture in
            let entry = fixture.fileEntry(localPath: path, contents: "bytes")
            try fixture.writeManifest(
                fixture.manifest(id: "hostile-path", files: [entry]),
                named: "hostile.json"
            )

            expectLoaderError(
                .invalidRelativePath(path: path, field: "files.localPath"),
                fixture: fixture
            )
        }
    }

    @Test("rejects traversal in original and license paths", arguments: ["original", "license"])
    func rejectsOtherTraversal(field: String) throws {
        try withFixtureRoot { fixture in
            if field == "original" {
                let entry = fixture.fileEntry(
                    originalPath: "../upstream.txt",
                    localPath: "Permissive/file.txt",
                    contents: "bytes"
                )
                try fixture.writeManifest(
                    fixture.manifest(id: "bad-original", files: [entry]),
                    named: "bad.json"
                )
                expectLoaderError(
                    .invalidRelativePath(path: "../upstream.txt", field: "files.originalPath"),
                    fixture: fixture
                )
            } else {
                try fixture.writeManifest(
                    fixture.manifest(id: "bad-license", licenseFile: "../LICENSE"),
                    named: "bad.json"
                )
                expectLoaderError(
                    .invalidRelativePath(path: "../LICENSE", field: "license.file"),
                    fixture: fixture
                )
            }
        }
    }

    @Test("rejects declarations in reserved metadata areas", arguments: [
        "README.md", "Manifests/data.txt", "Licenses/data.txt",
    ])
    func rejectsReservedLocalPaths(path: String) throws {
        try withFixtureRoot { fixture in
            let entry = fixture.fileEntry(localPath: path, contents: "bytes")
            try fixture.writeManifest(
                fixture.manifest(id: "reserved", files: [entry]),
                named: "reserved.json"
            )

            expectLoaderError(.reservedLocalPath(path), fixture: fixture)
        }
    }

    @Test("rejects malformed lowercase SHA-256", arguments: [
        String(repeating: "a", count: 63),
        String(repeating: "A", count: 64),
        String(repeating: "g", count: 64),
    ])
    func rejectsMalformedSHA256(hash: String) throws {
        try withFixtureRoot { fixture in
            var entry = fixture.fileEntry(localPath: "Permissive/file.txt", contents: "bytes")
            entry["sha256"] = hash
            try fixture.writeManifest(
                fixture.manifest(id: "bad-hash", files: [entry]),
                named: "hash.json"
            )

            expectLoaderError(.malformedSHA256(path: "Permissive/file.txt"), fixture: fixture)
        }
    }

    @Test("rejects a content hash mismatch")
    func rejectsHashMismatch() throws {
        try withFixtureRoot { fixture in
            try fixture.writeLicense("license", at: "Licenses/example.txt")
            try fixture.writeData("actual", at: "Permissive/file.txt")
            let entry = fixture.fileEntry(localPath: "Permissive/file.txt", contents: "expected")
            let expectedHash = try #require(entry["sha256"] as? String)
            try fixture.writeManifest(
                fixture.manifest(id: "mismatch", files: [entry]),
                named: "mismatch.json"
            )

            expectLoaderError(
                .hashMismatch(
                    path: "Permissive/file.txt",
                    expected: expectedHash,
                    actual: fixture.sha256("actual")
                ),
                fixture: fixture
            )
        }
    }

    @Test("rejects malformed license SHA-256")
    func rejectsMalformedLicenseSHA256() throws {
        try withFixtureRoot { fixture in
            try fixture.writeLicense("license", at: "Licenses/example.txt")
            var manifest = fixture.manifest(id: "bad-license-hash")
            var license = try #require(manifest["license"] as? [String: Any])
            license["sha256"] = String(repeating: "A", count: 64)
            manifest["license"] = license
            try fixture.writeManifest(manifest, named: "bad-license-hash.json")
            expectLoaderError(.malformedSHA256(path: "Licenses/example.txt"), fixture: fixture)
        }
    }

    @Test("rejects license content hash mismatch")
    func rejectsLicenseHashMismatch() throws {
        try withFixtureRoot { fixture in
            try fixture.writeLicense("changed", at: "Licenses/example.txt")
            try fixture.writeData("bytes", at: "Permissive/file.txt")
            try fixture.writeManifest(
                fixture.manifest(
                    id: "license-mismatch",
                    files: [fixture.fileEntry(localPath: "Permissive/file.txt", contents: "bytes")]
                ),
                named: "license-mismatch.json"
            )
            expectLoaderError(
                .hashMismatch(
                    path: "Licenses/example.txt",
                    expected: fixture.sha256("license"),
                    actual: fixture.sha256("changed")
                ),
                fixture: fixture
            )
        }
    }

    @Test("rejects unknown and missing license hash fields", arguments: ["unknown", "missing"])
    func rejectsLicenseSchemaViolation(kind: String) throws {
        try withFixtureRoot { fixture in
            var manifest = fixture.manifest(id: "license-schema")
            var license = try #require(manifest["license"] as? [String: Any])
            if kind == "unknown" { license["unexpected"] = true }
            else { license.removeValue(forKey: "sha256") }
            manifest["license"] = license
            try fixture.writeManifest(manifest, named: "license-schema.json")
            expectLoaderError(.malformedJSON(manifest: "license-schema.json"), fixture: fixture)
        }
    }

    @Test("rejects absent declared fixture and license files", arguments: ["fixture", "license"])
    func rejectsAbsentDeclarations(kind: String) throws {
        try withFixtureRoot { fixture in
            let entry = fixture.fileEntry(localPath: "Permissive/missing.txt", contents: "missing")
            try fixture.writeManifest(
                fixture.manifest(
                    id: "missing",
                    licenseFile: kind == "license" ? "Licenses/missing.txt" : "Licenses/example.txt",
                    files: [entry]
                ),
                named: "missing.json"
            )
            if kind == "fixture" {
                try fixture.writeLicense("license", at: "Licenses/example.txt")
            } else {
                try fixture.writeData("missing", at: "Permissive/missing.txt")
            }

            let missingPath = kind == "license" ? "Licenses/missing.txt" : "Permissive/missing.txt"
            expectLoaderError(.missingRegularFile(path: missingPath), fixture: fixture)
        }
    }

    @Test("rejects directories where regular files are required", arguments: ["fixture", "license"])
    func rejectsNonRegularDeclarations(kind: String) throws {
        try withFixtureRoot { fixture in
            let fixturePath = "Permissive/not-a-file"
            let licensePath = "Licenses/not-a-file"
            try fixture.createDirectory(at: kind == "fixture" ? fixturePath : licensePath)
            if kind == "fixture" {
                try fixture.writeLicense("license", at: "Licenses/example.txt")
            } else {
                try fixture.writeData("bytes", at: fixturePath)
            }
            let entry = fixture.fileEntry(localPath: fixturePath, contents: "bytes")
            try fixture.writeManifest(
                fixture.manifest(
                    id: "not-regular",
                    licenseFile: kind == "license" ? licensePath : "Licenses/example.txt",
                    files: [entry]
                ),
                named: "not-regular.json"
            )

            let badPath = kind == "license" ? licensePath : fixturePath
            expectLoaderError(.missingRegularFile(path: badPath), fixture: fixture)
        }
    }

    @Test("rejects unreferenced data files")
    func rejectsUnreferencedDataFiles() throws {
        try withFixtureRoot { fixture in
            try fixture.writeData("undeclared", at: "Permissive/undeclared.txt")
            expectLoaderError(
                .unreferencedFile(path: "Permissive/undeclared.txt"),
                fixture: fixture
            )
        }
    }

    @Test("does not treat reserved metadata as fixture data")
    func ignoresReservedMetadata() throws {
        try withFixtureRoot { fixture in
            try fixture.writeData("root documentation", at: "README.md")
            try fixture.writeData("manifest documentation", at: "Manifests/README.md")
            try fixture.writeData("license documentation", at: "Licenses/README.md")
            let manifest = try FixtureManifestLoader.load(from: fixture.root)
            #expect(manifest.groups.isEmpty)
        }
    }

    @Test("rejects symlinks without following an escape")
    func rejectsSymlinkEscape() throws {
        try withFixtureRoot { fixture in
            let outsideURL = fixture.root.deletingLastPathComponent()
                .appendingPathComponent("outside-\(UUID().uuidString).txt")
            try Data("outside".utf8).write(to: outsideURL)
            defer { try? FileManager.default.removeItem(at: outsideURL) }

            let linkURL = fixture.root.appendingPathComponent("Permissive/escape.txt")
            try FileManager.default.createDirectory(
                at: linkURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            do {
                try FileManager.default.createSymbolicLink(
                    atPath: linkURL.path,
                    withDestinationPath: outsideURL.path
                )
            } catch {
                // Some constrained platforms do not permit symlink creation.
                return
            }

            expectLoaderError(.symbolicLink(path: "Permissive/escape.txt"), fixture: fixture)
        }
    }

    @Test("rejects a JSON-named manifest directory")
    func rejectsManifestThatIsNotAFile() throws {
        try withFixtureRoot { fixture in
            try fixture.createDirectory(at: "Manifests/not-a-file.json")
            expectLoaderError(
                .missingRegularFile(path: "Manifests/not-a-file.json"),
                fixture: fixture
            )
        }
    }

    @Test("rejects missing fixture roots and manifest directories", arguments: ["root", "manifests"])
    func rejectsMissingRequiredDirectories(kind: String) throws {
        let fixtureRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("FixtureManifestTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: fixtureRoot) }
        if kind == "manifests" {
            try FileManager.default.createDirectory(at: fixtureRoot, withIntermediateDirectories: true)
        }

        let expected: FixtureManifestError = kind == "root"
            ? .fixtureRootNotDirectory
            : .manifestDirectoryNotDirectory
        do {
            _ = try FixtureManifestLoader.load(from: fixtureRoot)
            Issue.record("Expected \(expected)")
        } catch let error as FixtureManifestError {
            #expect(error == expected)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }
}

private struct TemporaryFixtureRoot {
    let root: URL

    func manifest(
        id: String,
        licenseFile: String = "Licenses/example.txt",
        files: [[String: Any]] = [],
        notes: String? = nil
    ) -> [String: Any] {
        var value: [String: Any] = [
            "schema": FixtureManifestLoader.schema,
            "id": id,
            "source": [
                "url": "https://example.invalid/fixture-source",
                "revision": "0123456789abcdef",
            ],
            "license": [
                "identifier": "CC0-1.0",
                "file": licenseFile,
                "sha256": sha256("license"),
            ],
            "files": files,
        ]
        if let notes {
            value["notes"] = notes
        }
        return value
    }

    func fileEntry(
        originalPath: String = "upstream/vector.txt",
        localPath: String,
        contents: String,
        notes: String? = nil
    ) -> [String: Any] {
        var value: [String: Any] = [
            "originalPath": originalPath,
            "localPath": localPath,
            "sha256": sha256(contents),
            "transformation": "independently authored",
        ]
        if let notes {
            value["notes"] = notes
        }
        return value
    }

    func sha256(_ contents: String) -> String {
        SHA256.hash(data: Data(contents.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    func writeManifest(_ manifest: [String: Any], named name: String) throws {
        let data = try JSONSerialization.data(
            withJSONObject: manifest,
            options: [.prettyPrinted, .sortedKeys]
        )
        try writeRawManifest(data, named: name)
    }

    func writeRawManifest(_ data: Data, named name: String) throws {
        try data.write(to: root.appendingPathComponent("Manifests/\(name)"))
    }

    func writeLicense(_ contents: String, at path: String) throws {
        try writeData(contents, at: path)
    }

    func writeData(_ contents: String, at path: String) throws {
        let url = root.appendingPathComponent(path)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data(contents.utf8).write(to: url)
    }

    func createDirectory(at path: String) throws {
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(path),
            withIntermediateDirectories: true
        )
    }
}

private func withFixtureRoot(_ body: (TemporaryFixtureRoot) throws -> Void) throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("FixtureManifestTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: root.appendingPathComponent("Manifests", isDirectory: true),
        withIntermediateDirectories: true
    )
    try FileManager.default.createDirectory(
        at: root.appendingPathComponent("Licenses", isDirectory: true),
        withIntermediateDirectories: true
    )
    defer { try? FileManager.default.removeItem(at: root) }
    try body(TemporaryFixtureRoot(root: root))
}

private func expectLoaderError(
    _ expected: FixtureManifestError,
    fixture: TemporaryFixtureRoot
) {
    do {
        _ = try FixtureManifestLoader.load(from: fixture.root)
        Issue.record("Expected \(expected)")
    } catch let error as FixtureManifestError {
        #expect(error == expected)
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}
