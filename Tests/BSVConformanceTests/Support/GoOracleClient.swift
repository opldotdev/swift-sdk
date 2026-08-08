import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

let goOracleSchema = "bsv-conformance/1"
let goOracleMaximumLineBytes = 1 << 20

enum GoOracleJSON: Codable, Equatable, Sendable {
    case string(String)
    case bool(Bool)
    case object([String: GoOracleJSON])
    case array([GoOracleJSON])
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([String: GoOracleJSON].self) { self = .object(value) }
        else if let value = try? container.decode([GoOracleJSON].self) { self = .array(value) }
        else { throw DecodingError.dataCorruptedError(in: container, debugDescription: "Oracle JSON permits only strings, booleans, objects, arrays, and null") }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

private struct GoOracleAnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?
    init?(stringValue: String) { self.stringValue = stringValue; intValue = nil }
    init?(intValue: Int) { stringValue = String(intValue); self.intValue = intValue }
}

private func rejectUnknownFields(_ decoder: Decoder, allowed: Set<String>) throws {
    let container = try decoder.container(keyedBy: GoOracleAnyCodingKey.self)
    let unknown = Set(container.allKeys.map(\.stringValue)).subtracting(allowed)
    guard unknown.isEmpty else {
        throw DecodingError.dataCorruptedError(
            forKey: unknown.sorted().first.flatMap(GoOracleAnyCodingKey.init(stringValue:))!,
            in: container,
            debugDescription: "Unknown field: \(unknown.sorted().joined(separator: ", "))"
        )
    }
}

struct GoOracleErrorPayload: Codable, Equatable, Sendable {
    let category: String
    let message: String

    init(category: String, message: String) { self.category = category; self.message = message }

    init(from decoder: Decoder) throws {
        enum Keys: String, CodingKey { case category, message }
        try rejectUnknownFields(decoder, allowed: ["category", "message"])
        let container = try decoder.container(keyedBy: Keys.self)
        category = try container.decode(String.self, forKey: .category)
        message = try container.decode(String.self, forKey: .message)
    }

    func encode(to encoder: Encoder) throws {
        enum Keys: String, CodingKey { case category, message }
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode(category, forKey: .category)
        try container.encode(message, forKey: .message)
    }
}

struct GoOracleResponse: Codable, Equatable, Sendable {
    let schema: String
    let id: String
    let ok: Bool
    let result: GoOracleJSON?
    let error: GoOracleErrorPayload?

    init(from decoder: Decoder) throws {
        enum Keys: String, CodingKey, CaseIterable { case schema, id, ok, result, error }
        try rejectUnknownFields(decoder, allowed: Set(Keys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: Keys.self)
        schema = try container.decode(String.self, forKey: .schema)
        id = try container.decode(String.self, forKey: .id)
        ok = try container.decode(Bool.self, forKey: .ok)
        result = try container.decodeIfPresent(GoOracleJSON.self, forKey: .result)
        error = try container.decodeIfPresent(GoOracleErrorPayload.self, forKey: .error)
        guard (ok && result != nil && error == nil) || (!ok && result == nil && error != nil) else {
            throw DecodingError.dataCorruptedError(forKey: .ok, in: container, debugDescription: "Response must contain exactly one of result or error")
        }
    }

    func encode(to encoder: Encoder) throws {
        enum Keys: String, CodingKey { case schema, id, ok, result, error }
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode(schema, forKey: .schema)
        try container.encode(id, forKey: .id)
        try container.encode(ok, forKey: .ok)
        if let result { try container.encode(result, forKey: .result) }
        if let error { try container.encode(error, forKey: .error) }
    }
}

struct GoOracleMetadata: Codable, Equatable, Sendable {
    let schema: String
    let module: String
    let tag: String
    let commit: String
    let sourceMode: String
    let sourceTreeSHA256: String
    let dirty: Bool
    let goVersion: String
    let dependencyGraphSHA256: String
    let hashes: [String: String]
    let operations: [String]

    init(
        schema: String, module: String, tag: String, commit: String, sourceMode: String,
        sourceTreeSHA256: String, dirty: Bool, goVersion: String,
        dependencyGraphSHA256: String, hashes: [String: String], operations: [String]
    ) {
        self.schema = schema; self.module = module; self.tag = tag; self.commit = commit
        self.sourceMode = sourceMode; self.sourceTreeSHA256 = sourceTreeSHA256; self.dirty = dirty
        self.goVersion = goVersion; self.dependencyGraphSHA256 = dependencyGraphSHA256
        self.hashes = hashes; self.operations = operations
    }

    init(from decoder: Decoder) throws {
        enum Keys: String, CodingKey, CaseIterable {
            case schema, module, tag, commit, sourceMode, sourceTreeSHA256, dirty, goVersion
            case dependencyGraphSHA256, hashes, operations
        }
        try rejectUnknownFields(decoder, allowed: Set(Keys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: Keys.self)
        schema = try container.decode(String.self, forKey: .schema)
        module = try container.decode(String.self, forKey: .module)
        tag = try container.decode(String.self, forKey: .tag)
        commit = try container.decode(String.self, forKey: .commit)
        sourceMode = try container.decode(String.self, forKey: .sourceMode)
        sourceTreeSHA256 = try container.decode(String.self, forKey: .sourceTreeSHA256)
        dirty = try container.decode(Bool.self, forKey: .dirty)
        goVersion = try container.decode(String.self, forKey: .goVersion)
        dependencyGraphSHA256 = try container.decode(String.self, forKey: .dependencyGraphSHA256)
        hashes = try container.decode([String: String].self, forKey: .hashes)
        guard Set(hashes.keys) == ["license", "goMod", "goSum"] else {
            throw DecodingError.dataCorruptedError(forKey: .hashes, in: container, debugDescription: "Metadata hashes contain unknown or missing fields")
        }
        operations = try container.decode([String].self, forKey: .operations)
    }

    func encode(to encoder: Encoder) throws {
        enum Keys: String, CodingKey {
            case schema, module, tag, commit, sourceMode, sourceTreeSHA256, dirty, goVersion
            case dependencyGraphSHA256, hashes, operations
        }
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode(schema, forKey: .schema); try container.encode(module, forKey: .module)
        try container.encode(tag, forKey: .tag); try container.encode(commit, forKey: .commit)
        try container.encode(sourceMode, forKey: .sourceMode); try container.encode(sourceTreeSHA256, forKey: .sourceTreeSHA256)
        try container.encode(dirty, forKey: .dirty); try container.encode(goVersion, forKey: .goVersion)
        try container.encode(dependencyGraphSHA256, forKey: .dependencyGraphSHA256)
        try container.encode(hashes, forKey: .hashes); try container.encode(operations, forKey: .operations)
    }
}

enum GoOracleClientError: Error, Equatable, Sendable {
    case unavailable(String)
    case metadataMismatch(String)
    case duplicateID(String)
    case requestTooLarge
    case responseTooLarge
    case timeout
    case transport(String)
    case processExited(Int32)
    case malformedOutput(String)
}

enum GoOracleAvailability: Sendable {
    case available(GoOracleClient)
    case unavailable(String)
}

struct GoOracleExpectedPin: Sendable {
    let module: String
    let tag: String
    let commit: String
    let goVersion: String
    let dependencyGraphSHA256: String
    let archiveTreeSHA256: String
    let gitTreeSHA256: String
    let hashes: [String: String]
    let operations: [String]

    static let pinned = GoOracleExpectedPin(
        module: "github.com/bsv-blockchain/go-sdk",
        tag: "v1.3.3",
        commit: "de26fdec57a945ddc06de5d5617f6c32374f3929",
        goVersion: "go1.25.0",
        dependencyGraphSHA256: "7059259c4651297d37c4ee0949576b2e8d792b9b7efd1a9c4678f26ee2efed40",
        archiveTreeSHA256: "09f05c13ee9286d5f5d6ed8724625a28edcd923b5b3d961a277cfd16347e4337",
        gitTreeSHA256: "2d2b2012877f208b46a295dbc1cada9fabcb8416a85bcf35ad3c55afeb3ce367",
        hashes: [
            "license": "d869a62568556cc7f61304b768074b40d7511ddb414f4e546101f860ee0ea853",
            "goMod": "7dd043b15ec0f317eeb6aa2bbc336eed940c127343d613129c0f176153f9d8c5",
            "goSum": "3ae1f83b189e48db4a8577a10fc74e1d04ab83b8998852526040d509066e177d",
        ],
        operations: [
            "base58.decode", "base58.encode", "base58check.decode", "base58check.encode",
            "base64.decode", "base64.encode", "big.umod", "brc42.private.derive", "brc42.public.derive", "brc94.generate", "brc94.verify", "bytes.reverse", "digest32.display",
            "digest32.parse", "drbg.generate", "hash.hash160", "hash.ripemd160", "hash.sha256", "hash.sha256d",
            "hash.sha512", "hex.decode", "hex.encode", "hmac.sha256", "hmac.sha512", "metadata",
            "script.asm.decode", "script.asm.encode", "script.asm.names", "script.execute", "scriptnum.decode", "scriptnum.encode", "spv.verify", "symmetric.decrypt", "symmetric.encrypt", "transaction.beef.decode", "transaction.beef.merge", "transaction.beef.reencode", "transaction.beef.trim", "transaction.beef.txidonly", "transaction.beef.validate", "transaction.beef.verify", "transaction.decode", "transaction.fee", "transaction.merklepath.combine", "transaction.merklepath.decode", "transaction.merklepath.root", "transaction.p2pkh.sign", "transaction.sighash", "u16.decode", "u16.encode",
            "u32.decode", "u32.encode", "u64.decode", "u64.encode", "varbytes.decode", "varbytes.encode",
            "varint.decode", "varint.encode",
        ]
    )
}

struct GoOracleConfiguration: Sendable {
    var executable: URL
    var arguments: [String]
    var environment: [String: String]
    var deadline: TimeInterval
    var startupDeadline: TimeInterval
    var required: Bool
    var expectedPin: GoOracleExpectedPin

    static func `default`() -> GoOracleConfiguration {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        return GoOracleConfiguration(
            executable: root.appendingPathComponent("Tools/Conformance/GoOracle/run.sh"),
            arguments: [],
            environment: ProcessInfo.processInfo.environment,
            deadline: 10,
            startupDeadline: 60,
            required: ProcessInfo.processInfo.environment["BSV_ORACLE_REQUIRED"] == "1",
            expectedPin: .pinned
        )
    }
}

final class GoOracleClient: @unchecked Sendable {
    private struct RequestEnvelope: Encodable {
        let schema: String
        let id: String
        let op: String
        let args: [String: GoOracleJSON]
    }

    private let configuration: GoOracleConfiguration
    private let requestLock = NSLock()
    private var usedIDs = Set<String>()
    private let process: Process
    private let stdin: FileHandle
    private let stdout: FileHandle
    private let stderr: FileHandle
    private let responseReader: GoOracleLineReader
    private let diagnostics: LockedData
    private let terminated: DispatchSemaphore
    let metadata: GoOracleMetadata

    private init(
        configuration: GoOracleConfiguration, metadata: GoOracleMetadata, process: Process,
        stdin: FileHandle, stdout: FileHandle, stderr: FileHandle,
        responseReader: GoOracleLineReader, diagnostics: LockedData, terminated: DispatchSemaphore
    ) {
        self.configuration = configuration
        self.metadata = metadata
        self.process = process
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.responseReader = responseReader
        self.diagnostics = diagnostics
        self.terminated = terminated
    }

    static func connect(configuration: GoOracleConfiguration = .default()) throws -> GoOracleAvailability {
        do {
            guard FileManager.default.isExecutableFile(atPath: configuration.executable.path) else {
                throw GoOracleClientError.unavailable("oracle executable is absent or not executable")
            }
            guard configuration.environment["BSV_GO_SDK_PATH"]?.isEmpty == false else {
                throw GoOracleClientError.unavailable("BSV_GO_SDK_PATH is not set")
            }
            let output = try runProcess(configuration: configuration, command: "metadata", input: nil)
            let metadata = try decodeSingleLine(GoOracleMetadata.self, from: output)
            try validate(metadata, expected: configuration.expectedPin)
            return .available(try startServe(configuration: configuration, metadata: metadata))
        } catch {
            if configuration.required { throw error }
            return .unavailable(String(describing: error))
        }
    }

    func request(id: String, operation: String, arguments: [String: GoOracleJSON]) throws -> GoOracleResponse {
        requestLock.lock()
        defer { requestLock.unlock() }

        try responseReader.checkUsable()
        let inserted = usedIDs.insert(id).inserted
        guard inserted else { throw GoOracleClientError.duplicateID(id) }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var requestData = try encoder.encode(RequestEnvelope(schema: goOracleSchema, id: id, op: operation, args: arguments))
        requestData.append(0x0A)
        guard requestData.count <= goOracleMaximumLineBytes else { throw GoOracleClientError.requestTooLarge }
        let encodedRequest = requestData

        do {
            try responseReader.beginRequest()
            let deadline = Date().addingTimeInterval(configuration.deadline)
            let writeFinished = DispatchSemaphore(value: 0)
            let writeResult = GoOracleWriteResult()
            let inputHandle = stdin
            DispatchQueue.global(qos: .userInitiated).async {
                do { try inputHandle.write(contentsOf: encodedRequest) }
                catch { writeResult.set(error: error) }
                writeFinished.signal()
            }
            if writeFinished.wait(timeout: .now() + configuration.deadline) == .timedOut {
                throw GoOracleClientError.timeout
            }
            if let writeError = writeResult.errorDescription {
                throw GoOracleClientError.transport("could not write request: \(writeError)")
            }
            let output = try responseReader.waitForResponse(until: deadline)
            let response = try Self.decodeSingleLine(GoOracleResponse.self, from: output)
            guard response.schema == goOracleSchema, response.id == id else {
                throw GoOracleClientError.transport("response schema/id does not match request")
            }
            return response
        } catch let error as GoOracleClientError {
            invalidate(with: error)
            throw error
        } catch {
            let transport = GoOracleClientError.transport("oracle request failed: \(error)")
            invalidate(with: transport)
            throw transport
        }
    }

    func close() {
        requestLock.lock()
        defer { requestLock.unlock() }
        _ = responseReader.failIfUsable(with: .transport("oracle client is closed"))
        stopProcess(terminateFirst: true)
        try? stdin.close()
        clearHandlers()
    }

    deinit { close() }

    private static func startServe(configuration: GoOracleConfiguration, metadata: GoOracleMetadata) throws -> GoOracleClient {
        let process = Process()
        process.executableURL = configuration.executable
        process.arguments = configuration.arguments + ["serve"]
        process.environment = configuration.environment
        let inputPipe = Pipe(), outputPipe = Pipe(), errorPipe = Pipe()
        process.standardInput = inputPipe; process.standardOutput = outputPipe; process.standardError = errorPipe
#if canImport(Darwin)
        _ = fcntl(inputPipe.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
#else
        _ = signal(SIGPIPE, SIG_IGN)
#endif

        let reader = GoOracleLineReader(maximumBytes: goOracleMaximumLineBytes)
        let diagnostics = LockedData(maximumBytes: goOracleMaximumLineBytes)
        let terminated = DispatchSemaphore(value: 0)
        outputPipe.fileHandleForReading.readabilityHandler = { handle in
            if !reader.append(handle.availableData) { process.terminate() }
        }
        errorPipe.fileHandleForReading.readabilityHandler = { handle in
            if !diagnostics.append(handle.availableData) {
                reader.fail(with: .transport("oracle diagnostics exceeded 1 MiB"))
                process.terminate()
            }
        }
        let outputHandle = outputPipe.fileHandleForReading
        process.terminationHandler = { process in
            outputHandle.readabilityHandler = nil
            _ = reader.append(outputHandle.readDataToEndOfFile())
            reader.fail(with: .processExited(process.terminationStatus))
            terminated.signal()
        }
        do { try process.run() }
        catch {
            outputPipe.fileHandleForReading.readabilityHandler = nil
            errorPipe.fileHandleForReading.readabilityHandler = nil
            throw GoOracleClientError.transport("could not start oracle serve process: \(error)")
        }
        return GoOracleClient(
            configuration: configuration, metadata: metadata, process: process,
            stdin: inputPipe.fileHandleForWriting, stdout: outputPipe.fileHandleForReading,
            stderr: errorPipe.fileHandleForReading, responseReader: reader,
            diagnostics: diagnostics, terminated: terminated
        )
    }

    private func invalidate(with error: GoOracleClientError) {
        responseReader.fail(with: error)
        stopProcess(terminateFirst: true)
        try? stdin.close()
        clearHandlers()
    }

    private func stopProcess(terminateFirst: Bool) {
        guard process.isRunning else { return }
        if terminateFirst { process.terminate() }
        if terminated.wait(timeout: .now() + 2) == .timedOut {
            _ = kill(process.processIdentifier, SIGKILL)
            _ = terminated.wait(timeout: .now() + 0.25)
        }
    }

    private func clearHandlers() {
        stdout.readabilityHandler = nil
        stderr.readabilityHandler = nil
        process.terminationHandler = nil
    }

    private static func validate(_ metadata: GoOracleMetadata, expected: GoOracleExpectedPin) throws {
        guard metadata.schema == goOracleSchema else { throw GoOracleClientError.metadataMismatch("schema") }
        guard metadata.module == expected.module else { throw GoOracleClientError.metadataMismatch("module") }
        guard metadata.tag == expected.tag, metadata.commit == expected.commit else { throw GoOracleClientError.metadataMismatch("revision") }
        guard metadata.goVersion == expected.goVersion else { throw GoOracleClientError.metadataMismatch("Go toolchain") }
        guard metadata.dependencyGraphSHA256 == expected.dependencyGraphSHA256 else { throw GoOracleClientError.metadataMismatch("dependency graph") }
        guard metadata.hashes == expected.hashes else { throw GoOracleClientError.metadataMismatch("pinned files") }
        guard metadata.operations == expected.operations else { throw GoOracleClientError.metadataMismatch("operation registry") }
        guard metadata.operations == metadata.operations.sorted() else { throw GoOracleClientError.metadataMismatch("operation ordering") }
        guard !metadata.dirty else { throw GoOracleClientError.metadataMismatch("dirty source") }
        guard metadata.sourceMode == "git" || metadata.sourceMode == "archive" else { throw GoOracleClientError.metadataMismatch("source mode") }
        guard !metadata.sourceTreeSHA256.isEmpty else { throw GoOracleClientError.metadataMismatch("tree identity") }
        if metadata.sourceMode == "archive", metadata.sourceTreeSHA256 != expected.archiveTreeSHA256 {
            throw GoOracleClientError.metadataMismatch("archive tree")
        }
        if metadata.sourceMode == "git", metadata.sourceTreeSHA256 != expected.gitTreeSHA256 {
            throw GoOracleClientError.metadataMismatch("git tree")
        }
    }

    private static func decodeSingleLine<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        guard data.count <= goOracleMaximumLineBytes else { throw GoOracleClientError.responseTooLarge }
        guard let text = String(data: data, encoding: .utf8) else { throw GoOracleClientError.malformedOutput("output is not UTF-8") }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count == 2, lines[1].isEmpty, !lines[0].isEmpty else {
            throw GoOracleClientError.malformedOutput("expected exactly one newline-terminated JSON response")
        }
        do { return try JSONDecoder().decode(T.self, from: Data(lines[0].utf8)) }
        catch { throw GoOracleClientError.malformedOutput(String(describing: error)) }
    }

    private static func runProcess(configuration: GoOracleConfiguration, command: String, input: Data?) throws -> Data {
        let process = Process()
        process.executableURL = configuration.executable
        process.arguments = configuration.arguments + [command]
        process.environment = configuration.environment
        let stdout = Pipe(), stderr = Pipe(), stdin = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        if input != nil { process.standardInput = stdin }

        let output = LockedData(maximumBytes: goOracleMaximumLineBytes)
        let diagnostics = LockedData(maximumBytes: goOracleMaximumLineBytes)
        let reads = GoOracleReadResult()
        let outputFinished = DispatchSemaphore(value: 0)
        let diagnosticsFinished = DispatchSemaphore(value: 0)
        let completed = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in completed.signal() }
        do { try process.run() }
        catch { throw GoOracleClientError.transport("could not start oracle: \(error)") }

        func drain(
            _ handle: FileHandle,
            into destination: LockedData,
            label: String,
            finished: DispatchSemaphore
        ) {
            DispatchQueue.global(qos: .userInitiated).async {
                defer { finished.signal() }
                do {
                    while let chunk = try handle.read(upToCount: 64 * 1_024), !chunk.isEmpty {
                        guard destination.append(chunk) else {
                            process.terminate()
                            return
                        }
                    }
                } catch {
                    reads.set(label: label, error: error)
                    process.terminate()
                }
            }
        }
        drain(
            stdout.fileHandleForReading,
            into: output,
            label: "stdout",
            finished: outputFinished
        )
        drain(
            stderr.fileHandleForReading,
            into: diagnostics,
            label: "stderr",
            finished: diagnosticsFinished
        )
        if let input {
            do { try stdin.fileHandleForWriting.write(contentsOf: input); try stdin.fileHandleForWriting.close() }
            catch { process.terminate(); throw GoOracleClientError.transport("could not write request: \(error)") }
        }

        if completed.wait(timeout: .now() + configuration.startupDeadline) == .timedOut {
            process.terminate()
            if completed.wait(timeout: .now() + 2) == .timedOut {
                _ = kill(process.processIdentifier, SIGKILL)
                _ = completed.wait(timeout: .now() + 0.25)
            }
            _ = outputFinished.wait(timeout: .now() + 2)
            _ = diagnosticsFinished.wait(timeout: .now() + 2)
            throw GoOracleClientError.timeout
        }
        guard outputFinished.wait(timeout: .now() + 2) == .success,
              diagnosticsFinished.wait(timeout: .now() + 2) == .success else {
            throw GoOracleClientError.transport("oracle output pipes did not close")
        }
        if let readError = reads.errorDescription {
            throw GoOracleClientError.transport(readError)
        }
        if output.exceededLimit { throw GoOracleClientError.responseTooLarge }
        if diagnostics.exceededLimit { throw GoOracleClientError.transport("oracle diagnostics exceeded 1 MiB") }
        guard process.terminationStatus == 0 else { throw GoOracleClientError.processExited(process.terminationStatus) }
        let data = output.value
        guard data.count <= goOracleMaximumLineBytes else { throw GoOracleClientError.responseTooLarge }
        return data
    }
}

private final class GoOracleLineReader: @unchecked Sendable {
    private let condition = NSCondition()
    private let maximumBytes: Int
    private var buffer = Data()
    private var response: Data?
    private var waiting = false
    private var terminalError: GoOracleClientError?

    init(maximumBytes: Int) { self.maximumBytes = maximumBytes }

    func checkUsable() throws {
        condition.lock(); defer { condition.unlock() }
        if let terminalError { throw terminalError }
    }

    func beginRequest() throws {
        condition.lock(); defer { condition.unlock() }
        if let terminalError { throw terminalError }
        guard !waiting, response == nil, buffer.isEmpty else {
            throw GoOracleClientError.transport("oracle response stream is out of sync")
        }
        waiting = true
    }

    @discardableResult
    func append(_ data: Data) -> Bool {
        guard !data.isEmpty else { return true }
        condition.lock()
        defer { condition.unlock() }
        guard terminalError == nil else { return false }
        for byte in data {
            guard waiting else {
                setTerminal(.malformedOutput("unsolicited or duplicate response line"))
                return false
            }
            buffer.append(byte)
            if buffer.count > maximumBytes {
                setTerminal(.responseTooLarge)
                return false
            }
            if byte == 0x0A {
                response = buffer
                buffer.removeAll(keepingCapacity: true)
                waiting = false
                condition.broadcast()
            }
        }
        return terminalError == nil
    }

    func waitForResponse(until end: Date) throws -> Data {
        condition.lock()
        defer { condition.unlock() }
        while response == nil, terminalError == nil {
            if !condition.wait(until: end) {
                setTerminal(.timeout)
                break
            }
        }
        if let terminalError { throw terminalError }
        guard let line = response else { throw GoOracleClientError.transport("oracle produced no response") }
        response = nil
        return line
    }

    func fail(with error: GoOracleClientError) {
        condition.lock(); defer { condition.unlock() }
        setTerminal(error)
    }

    @discardableResult
    func failIfUsable(with error: GoOracleClientError) -> Bool {
        condition.lock(); defer { condition.unlock() }
        guard terminalError == nil else { return false }
        setTerminal(error)
        return true
    }

    private func setTerminal(_ error: GoOracleClientError) {
        guard terminalError == nil else { return }
        terminalError = error
        condition.broadcast()
    }
}

private final class GoOracleWriteResult: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: String?
    func set(error: Error) { lock.lock(); storage = String(describing: error); lock.unlock() }
    var errorDescription: String? { lock.lock(); defer { lock.unlock() }; return storage }
}

private final class GoOracleReadResult: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: String?
    func set(label: String, error: Error) {
        lock.lock()
        if storage == nil { storage = "could not read oracle \(label): \(error)" }
        lock.unlock()
    }
    var errorDescription: String? { lock.lock(); defer { lock.unlock() }; return storage }
}

private final class LockedData: @unchecked Sendable {
    private let lock = NSLock()
    private let maximumBytes: Int
    private var storage = Data()
    private var exceeded = false
    init(maximumBytes: Int) { self.maximumBytes = maximumBytes }
    @discardableResult func append(_ data: Data) -> Bool {
        guard !data.isEmpty else { return true }
        lock.lock()
        defer { lock.unlock() }
        guard !exceeded else { return false }
        if storage.count + data.count > maximumBytes {
            exceeded = true
            return false
        }
        storage.append(data)
        return true
    }
    var exceededLimit: Bool { lock.lock(); defer { lock.unlock() }; return exceeded }
    var value: Data { lock.lock(); defer { lock.unlock() }; return storage }
}
