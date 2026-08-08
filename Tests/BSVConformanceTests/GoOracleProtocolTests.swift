import Foundation
import Testing

@Suite("GoOracleProtocol", .serialized)
struct GoOracleProtocolTests {
    @Test("Optional absence is one explicit unavailable result")
    func optionalAbsence() throws {
        var configuration = testConfiguration(executable: URL(fileURLWithPath: "/definitely/absent/go-oracle"))
        configuration.required = false
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available: Issue.record("unexpected available oracle")
        case .unavailable(let reason): #expect(reason.contains("absent"))
        }
    }

    @Test("Required absence fails")
    func requiredAbsence() {
        var configuration = testConfiguration(executable: URL(fileURLWithPath: "/definitely/absent/go-oracle"))
        configuration.required = true
        #expect(throws: GoOracleClientError.self) { try GoOracleClient.connect(configuration: configuration) }
    }

    @Test("Metadata mismatch is unavailable or fatal according to mode")
    func metadataMismatch() throws {
        var wrong = validMetadata()
        wrong = GoOracleMetadata(
            schema: wrong.schema, module: wrong.module, tag: wrong.tag, commit: "wrong",
            sourceMode: wrong.sourceMode, sourceTreeSHA256: wrong.sourceTreeSHA256, dirty: wrong.dirty,
            goVersion: wrong.goVersion, dependencyGraphSHA256: wrong.dependencyGraphSHA256,
            hashes: wrong.hashes, operations: wrong.operations
        )
        let script = try fakeOracle(metadata: wrong, serve: .success)
        var configuration = testConfiguration(executable: script)
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available: Issue.record("metadata mismatch was accepted")
        case .unavailable(let reason): #expect(reason.contains("metadataMismatch"))
        }
        configuration.required = true
        #expect(throws: GoOracleClientError.self) { try GoOracleClient.connect(configuration: configuration) }
    }

    @Test("Metadata validates the mode-specific trusted tree")
    func gitTreeMetadataPin() throws {
        let archive = validMetadata()
        let git = GoOracleMetadata(
            schema: archive.schema, module: archive.module, tag: archive.tag, commit: archive.commit,
            sourceMode: "git", sourceTreeSHA256: GoOracleExpectedPin.pinned.gitTreeSHA256,
            dirty: false, goVersion: archive.goVersion,
            dependencyGraphSHA256: archive.dependencyGraphSHA256,
            hashes: archive.hashes, operations: archive.operations
        )
        let client = try requireClient(fakeOracle(metadata: git, serve: .success))
        client.close()
        let wrong = GoOracleMetadata(
            schema: git.schema, module: git.module, tag: git.tag, commit: git.commit,
            sourceMode: "git", sourceTreeSHA256: GoOracleExpectedPin.pinned.archiveTreeSHA256,
            dirty: false, goVersion: git.goVersion,
            dependencyGraphSHA256: git.dependencyGraphSHA256,
            hashes: git.hashes, operations: git.operations
        )
        if case .available = try GoOracleClient.connect(configuration: testConfiguration(executable: fakeOracle(metadata: wrong, serve: .success))) {
            Issue.record("archive tree was accepted for Git mode")
        }
    }

    @Test("Metadata startup uses its independent deadline")
    func startupDeadline() throws {
        let script = try fakeOracle(metadata: validMetadata(), serve: .success, metadataHang: true)
        var configuration = testConfiguration(executable: script)
        configuration.deadline = 10
        configuration.startupDeadline = 0.2
        configuration.required = true
        let started = Date()
        #expect(throws: GoOracleClientError.timeout) { try GoOracleClient.connect(configuration: configuration) }
        // The client may spend up to two seconds terminating an unresponsive
        // child after the 0.2-second startup deadline expires. Keep enough
        // scheduler tolerance for loaded Linux runners while still proving
        // that the independent 10-second request deadline was not used.
        #expect(Date().timeIntervalSince(started) < 3.5)
    }

    @Test("Metadata process exit includes bounded diagnostics")
    func metadataExitDiagnostics() throws {
        let script = try fakeOracle(
            metadata: validMetadata(),
            serve: .success,
            metadataExitDiagnostic: "oracle pin validation failed: missing tag"
        )
        var configuration = testConfiguration(executable: script)
        configuration.required = true
        #expect(throws: GoOracleClientError.processExited(
            3,
            "oracle pin validation failed: missing tag"
        )) {
            try GoOracleClient.connect(configuration: configuration)
        }
    }

    @Test("Framing and normalized operation errors decode")
    func framingAndErrorDecode() throws {
        let successScript = try fakeOracle(metadata: validMetadata(), serve: .success)
        let client = try requireClient(successScript)
        let response = try client.request(id: "one", operation: "bytes.reverse", arguments: ["hex": .string("00")])
        #expect(response.ok)
        #expect(response.result == .object(["hex": .string("00")]))

        let errorScript = try fakeOracle(metadata: validMetadata(), serve: .operationError)
        let errorClient = try requireClient(errorScript)
        let error = try errorClient.request(id: "one", operation: "base58check.decode", arguments: ["text": .string("bad")])
        #expect(!error.ok)
        #expect(error.error?.category == "checksum")
    }

    @Test("Distinct request IDs reuse one serve child")
    func persistentServeChild() throws {
        let client = try requireClient(fakeOracle(metadata: validMetadata(), serve: .sameChild))
        let first = try client.request(id: "one", operation: "metadata", arguments: [:])
        let second = try client.request(id: "two", operation: "metadata", arguments: [:])
        #expect(first.result == .object(["sequence": .string("1")]))
        #expect(second.result == .object(["sequence": .string("2")]))
        client.close()
        #expect(throws: GoOracleClientError.transport("oracle client is closed")) {
            try client.request(id: "after", operation: "metadata", arguments: [:])
        }
    }

    @Test("Duplicate request IDs are rejected locally")
    func duplicateIDs() throws {
        let client = try requireClient(fakeOracle(metadata: validMetadata(), serve: .success))
        _ = try client.request(id: "one", operation: "metadata", arguments: [:])
        #expect(throws: GoOracleClientError.duplicateID("one")) {
            try client.request(id: "one", operation: "metadata", arguments: [:])
        }
    }

    @Test("Unknown response IDs and malformed framing are transport failures", arguments: [ServeBehavior.unknownID, .twoLines, .invalidJSON])
    func invalidResponses(behavior: ServeBehavior) throws {
        let client = try requireClient(fakeOracle(metadata: validMetadata(), serve: behavior))
        #expect(throws: GoOracleClientError.self) {
            try client.request(id: "one", operation: "metadata", arguments: [:])
        }
    }

    @Test("Overlong output is rejected")
    func overlongOutput() throws {
        let client = try requireClient(fakeOracle(metadata: validMetadata(), serve: .overlong))
        #expect(throws: GoOracleClientError.responseTooLarge) {
            try client.request(id: "one", operation: "metadata", arguments: [:])
        }
    }

    @Test("Timeout terminates the child within the two-second grace")
    func timeout() throws {
        let script = try fakeOracle(metadata: validMetadata(), serve: .hang)
        var configuration = testConfiguration(executable: script)
        configuration.deadline = 0.5
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let value): client = value
        case .unavailable(let reason): throw GoOracleClientError.unavailable(reason)
        }
        let started = Date()
        #expect(throws: GoOracleClientError.timeout) {
            try client.request(id: "one", operation: "metadata", arguments: [:])
        }
        // The bound is the 0.5-second request deadline plus the documented
        // two-second termination grace and scheduler tolerance.
        #expect(Date().timeIntervalSince(started) < 3.5)
        #expect(throws: GoOracleClientError.timeout) {
            try client.request(id: "two", operation: "metadata", arguments: [:])
        }
    }

    @Test("Request write shares the response deadline and invalidates on timeout")
    func writeTimeout() throws {
        let script = try fakeOracle(metadata: validMetadata(), serve: .noRead)
        var configuration = testConfiguration(executable: script)
        configuration.deadline = 0.2
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let value): client = value
        case .unavailable(let reason): throw GoOracleClientError.unavailable(reason)
        }
        let large = String(repeating: "00", count: 400_000)
        #expect(throws: GoOracleClientError.timeout) {
            try client.request(id: "one", operation: "hex.decode", arguments: ["text": .string(large)])
        }
        #expect(throws: GoOracleClientError.timeout) {
            try client.request(id: "two", operation: "metadata", arguments: [:])
        }
    }

    @Test("Nonzero process exit is typed")
    func processExit() throws {
        let client = try requireClient(fakeOracle(metadata: validMetadata(), serve: .exitSeven))
        #expect(throws: GoOracleClientError.processExited(7, "safe diagnostic")) {
            try client.request(id: "one", operation: "metadata", arguments: [:])
        }
        #expect(throws: GoOracleClientError.processExited(7, "safe diagnostic")) {
            try client.request(id: "two", operation: "metadata", arguments: [:])
        }
    }

    @Test("Response and nested error decoders reject unknown fields", arguments: [ServeBehavior.unknownResponseField, .unknownErrorField])
    func responseUnknownFields(behavior: ServeBehavior) throws {
        let client = try requireClient(fakeOracle(metadata: validMetadata(), serve: behavior))
        #expect(throws: GoOracleClientError.self) {
            try client.request(id: "one", operation: "metadata", arguments: [:])
        }
    }

    @Test("Metadata decoder rejects unknown fields")
    func metadataUnknownFields() throws {
        let scripts = [
            try fakeOracle(metadata: validMetadata(), serve: .success, metadataUnknownField: true),
            try fakeOracle(metadata: validMetadata(), serve: .success, metadataUnknownHash: true),
        ]
        for script in scripts {
            switch try GoOracleClient.connect(configuration: testConfiguration(executable: script)) {
            case .available: Issue.record("unknown metadata field was accepted")
            case .unavailable(let reason): #expect(reason.contains("Unknown field") || reason.contains("hashes"))
            }
        }
    }

    @Test("Exact external Go oracle integrates when provisioned")
    func exactGoOracleIntegration() throws {
        var configuration = GoOracleConfiguration.default()
        configuration.required = ProcessInfo.processInfo.environment["BSV_ORACLE_REQUIRED"] == "1"
        switch try GoOracleClient.connect(configuration: configuration) {
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("Go oracle unavailable: \(reason)")
        case .available(let client):
            var sequence = 0
            func check(_ op: String, _ args: [String: GoOracleJSON], _ expected: GoOracleJSON) throws {
                sequence += 1
                let response = try client.request(id: "integration-\(sequence)", operation: op, arguments: args)
                #expect(response.ok)
                #expect(response.result == expected)
            }
            try check("bytes.reverse", ["hex": .string("000102")], .object(["hex": .string("020100")]))
            try check("u16.encode", ["value": .string("4660"), "endian": .string("little")], .object(["bytes": .string("3412")]))
            try check("u32.decode", ["bytes": .string("12345678"), "endian": .string("big")], .object(["value": .string("305419896")]))
            try check("u64.encode", ["value": .string("81985529216486895"), "endian": .string("big")], .object(["bytes": .string("0123456789abcdef")]))
            try check("hex.decode", ["text": .string("00FF")], .object(["bytes": .string("00ff")]))
            try check("base64.encode", ["bytes": .string("666f6f")], .object(["text": .string("Zm9v")]))
            try check("varint.decode", ["bytes": .string("fdfc00"), "canonical": .string("permissive")], .object(["value": .string("252"), "bytesConsumed": .string("3"), "isCanonical": .bool(false)]))
            try check("varbytes.decode", ["bytes": .string("02aabb"), "canonical": .string("required")], .object(["bytes": .string("aabb"), "bytesConsumed": .string("3"), "isCanonical": .bool(true)]))
            try check("hash.sha256", ["bytes": .string("")], .object(["bytes": .string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]))
            try check("hmac.sha256", ["key": .string(String(repeating: "0b", count: 20)), "message": .string("4869205468657265")], .object(["bytes": .string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")]))
            let display = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            let wire = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
            try check("digest32.parse", ["display": .string(display.uppercased())], .object(["bytes": .string(wire)]))
            try check("digest32.display", ["bytes": .string(wire)], .object(["display": .string(display)]))
            try check("base58.encode", ["bytes": .string("0001")], .object(["text": .string("12")]))
            try check("base58check.encode", ["payload": .string(String(repeating: "00", count: 20)), "version": .string("0")], .object(["text": .string("1111111111111111111114oLvT2")]))
            try check("big.umod", ["dividend": .string("-5"), "divisor": .string("3")], .object(["value": .string("1")]))
            try check("scriptnum.encode", ["value": .string("-128"), "era": .string("postGenesis")], .object(["bytes": .string("8080")]))
            try check(
                "script.asm.decode",
                ["text": .string("OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG")],
                .object(["bytes": .string("76a914000000000000000000000000000000000000000088ac")])
            )
            try check(
                "script.asm.encode",
                ["bytes": .string("0051b3ff")],
                .object(["text": .string("OP_FALSE OP_TRUE OP_SUBSTR OP_INVALIDOPCODE")])
            )
            try check(
                "transaction.decode",
                ["bytes": .string("01000000000000000000")],
                .object([
                    "bytes": .string("01000000000000000000"),
                    "inputs": .string("0"),
                    "lockTime": .string("0"),
                    "outputs": .string("0"),
                    "txid": .string("d21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43"),
                    "version": .string("1"),
                ])
            )
        }
    }
}

enum ServeBehavior: String, CaseIterable, Sendable {
    case success, sameChild, operationError, unknownID, twoLines, invalidJSON, overlong, hang, noRead, exitSeven
    case unknownResponseField, unknownErrorField
}

private func validMetadata() -> GoOracleMetadata {
    let pin = GoOracleExpectedPin.pinned
    return GoOracleMetadata(
        schema: goOracleSchema, module: pin.module, tag: pin.tag, commit: pin.commit,
        sourceMode: "archive", sourceTreeSHA256: pin.archiveTreeSHA256, dirty: false,
        goVersion: pin.goVersion, dependencyGraphSHA256: pin.dependencyGraphSHA256,
        hashes: pin.hashes, operations: pin.operations
    )
}

private func testConfiguration(executable: URL) -> GoOracleConfiguration {
    GoOracleConfiguration(
        executable: executable, arguments: [], environment: ["BSV_GO_SDK_PATH": "/external/fake"],
        deadline: 5, startupDeadline: 5, required: false, expectedPin: .pinned
    )
}

private func requireClient(_ executable: URL) throws -> GoOracleClient {
    switch try GoOracleClient.connect(configuration: testConfiguration(executable: executable)) {
    case .available(let client): return client
    case .unavailable(let reason): throw GoOracleClientError.unavailable(reason)
    }
}

private func fakeOracle(
    metadata: GoOracleMetadata, serve behavior: ServeBehavior, metadataUnknownField: Bool = false,
    metadataUnknownHash: Bool = false, metadataHang: Bool = false,
    metadataExitDiagnostic: String? = nil
) throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("go-oracle-protocol-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let executable = directory.appendingPathComponent("oracle.sh")
    let encodedMetadata = try JSONEncoder().encode(metadata)
    var metadataObject = try #require(JSONSerialization.jsonObject(with: encodedMetadata) as? [String: Any])
    if metadataUnknownField { metadataObject["unknown"] = true }
    if metadataUnknownHash {
        var hashes = try #require(metadataObject["hashes"] as? [String: Any])
        hashes["unknown"] = "value"
        metadataObject["hashes"] = hashes
    }
    let metadataData = try JSONSerialization.data(withJSONObject: metadataObject, options: [.sortedKeys])
    let metadataLine = String(decoding: metadataData, as: UTF8.self)
    let serve: String
    switch behavior {
    case .success:
        serve = "while IFS= read -r request; do case \"$request\" in *two*) id=two ;; *) id=one ;; esac; printf '{\"schema\":\"bsv-conformance/1\",\"id\":\"%s\",\"ok\":true,\"result\":{\"hex\":\"00\"}}\\n' \"$id\"; done"
    case .sameChild:
        serve = "count=0; while IFS= read -r request; do count=$((count + 1)); case \"$request\" in *two*) id=two ;; *) id=one ;; esac; printf '{\"schema\":\"bsv-conformance/1\",\"id\":\"%s\",\"ok\":true,\"result\":{\"sequence\":\"%s\"}}\\n' \"$id\" \"$count\"; done"
    case .operationError:
        serve = "while IFS= read -r request; do printf '%s\\n' '{\"schema\":\"bsv-conformance/1\",\"id\":\"one\",\"ok\":false,\"error\":{\"category\":\"checksum\",\"message\":\"mismatch\"}}'; done"
    case .unknownID:
        serve = "printf '%s\\n' '{\"schema\":\"bsv-conformance/1\",\"id\":\"other\",\"ok\":true,\"result\":{}}'"
    case .twoLines:
        serve = "printf '%s\\n%s\\n' '{}' '{}'"
    case .invalidJSON:
        serve = "printf '%s\\n' '{broken}'"
    case .overlong:
        serve = "/usr/bin/yes x | /usr/bin/tr -d '\\n' | /usr/bin/head -c 1048577"
    case .hang:
        serve = "while :; do :; done"
    case .noRead:
        serve = "while :; do :; done"
    case .exitSeven:
        serve = "printf '%s\\n' 'safe diagnostic' >&2; exit 7"
    case .unknownResponseField:
        serve = "printf '%s\\n' '{\"schema\":\"bsv-conformance/1\",\"id\":\"one\",\"ok\":true,\"result\":{},\"unknown\":true}'"
    case .unknownErrorField:
        serve = "printf '%s\\n' '{\"schema\":\"bsv-conformance/1\",\"id\":\"one\",\"ok\":false,\"error\":{\"category\":\"internal\",\"message\":\"x\",\"unknown\":true}}'"
    }
    let metadataCommand: String
    if let metadataExitDiagnostic {
        metadataCommand = "printf '%s\\n' '\(metadataExitDiagnostic)' >&2; exit 3"
    } else if metadataHang {
        metadataCommand = "while :; do :; done"
    } else {
        metadataCommand = "printf '%s\\n' '\(metadataLine)'"
    }
    let script = """
        #!/bin/sh
        case "$1" in
          metadata) \(metadataCommand) ;;
          serve) \(serve) ;;
          *) exit 2 ;;
        esac
        """
    try script.write(to: executable, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    return executable
}
