import BSVInterpreter
import BSVScript
import Foundation
import Testing

@Suite("Script interpreter debugger")
struct ScriptDebugTests {
    @Test("emits a bounded immutable lifecycle covering execution, steps, and success")
    func lifecycle() throws {
        let recorder = EventRecorder()
        let session = ScriptDebugSession { recorder.append($0) }

        _ = try Self.execute(
            unlocking: [Opcode.one.rawValue],
            locking: [Opcode.dup.rawValue, Opcode.verify.rawValue, Opcode.one.rawValue],
            debugger: session
        )
        let events = recorder.events
        let kinds = events.map(\.kind)
        #expect(kinds.contains(.beforeExecution))
        #expect(kinds.contains(.afterExecution))
        #expect(kinds.contains(.beforeStep))
        #expect(kinds.contains(.afterStep))
        #expect(kinds.contains(.beforeOpcode))
        #expect(kinds.contains(.afterOpcode))
        #expect(kinds.contains(.beforeScriptChange))
        #expect(kinds.contains(.afterScriptChange))
        #expect(kinds.contains(.success))
        #expect(events.map(\.sequence) == Array(0..<UInt64(events.count)))
        #expect(events.allSatisfy { $0.snapshot.mainStack.count <= session.limits.maximumStackItemCount })
    }

    @Test("reports stack pushes and pops without exposing bytes in descriptions")
    func stackEventsAndRedaction() throws {
        let recorder = EventRecorder()
        let session = ScriptDebugSession { recorder.append($0) }
        _ = try Self.execute(
            unlocking: [2, 0xaa, 0xbb, Opcode.drop.rawValue],
            locking: [Opcode.one.rawValue],
            debugger: session
        )

        let events = recorder.events
        #expect(events.contains { $0.kind == .beforeStackPush && $0.stack == .main })
        #expect(events.contains { $0.kind == .afterStackPop && $0.stack == .main })
        let event = try #require(events.first { $0.stackValue == [0xaa, 0xbb] })
        #expect(!event.description.contains("aa"))
        #expect(!event.snapshot.description.contains("aa"))
        #expect(Mirror(reflecting: event).children.isEmpty)
    }

    @Test("enforces stack byte and item bounds")
    func snapshotBounds() throws {
        let recorder = EventRecorder()
        let limits = try ScriptDebugLimits(
            maximumEventCount: 100,
            maximumStackItemCount: 1,
            maximumStackByteCount: 1,
            maximumStackItemByteCount: 1
        )
        let session = ScriptDebugSession(limits: limits) { recorder.append($0) }
        _ = try Self.execute(
            unlocking: [2, 0xaa, 0xbb, Opcode.one.rawValue],
            locking: [Opcode.one.rawValue],
            debugger: session
        )
        let bounded = try #require(recorder.events.first { $0.snapshot.isTruncated })
        #expect(bounded.snapshot.mainStack.count <= 1)
        #expect(bounded.snapshot.mainStack.allSatisfy { $0.count <= 1 })
    }

    @Test("enforces the event ceiling without retaining an unbounded trace")
    func eventBounds() throws {
        let recorder = EventRecorder()
        let limits = try ScriptDebugLimits(maximumEventCount: 3)
        let session = ScriptDebugSession(limits: limits) { recorder.append($0) }
        _ = try Self.execute(
            unlocking: [],
            locking: [Opcode.one.rawValue, Opcode.dup.rawValue, Opcode.drop.rawValue],
            debugger: session
        )
        #expect(recorder.events.count == 3)
        #expect(recorder.events.map(\.sequence) == [0, 1, 2])
    }

    @Test("reports interpreter failures and never emits success")
    func failure() throws {
        let recorder = EventRecorder()
        let session = ScriptDebugSession { recorder.append($0) }
        #expect(throws: ScriptExecutionError.consensus(.evaluatedFalse)) {
            try Self.execute(unlocking: [], locking: [Opcode.zero.rawValue], debugger: session)
        }
        #expect(recorder.events.contains {
            $0.kind == .failure && $0.failure == .execution(.consensus(.evaluatedFalse))
        })
        #expect(!recorder.events.contains { $0.kind == .success })
    }

    @Test("cancellation stops an opted-in execution")
    func cancellation() throws {
        let session = ScriptDebugSession { _ in }
        session.cancel()
        #expect(throws: ScriptDebugError.cancelled) {
            try Self.execute(unlocking: [], locking: [Opcode.one.rawValue], debugger: session)
        }
    }

    @Test("sessions are safe to use from concurrent independent executions")
    func concurrentSessions() async throws {
        let recorder = EventRecorder()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    let session = ScriptDebugSession { recorder.append($0) }
                    _ = try Self.execute(
                        unlocking: [],
                        locking: [Opcode.one.rawValue],
                        debugger: session
                    )
                }
            }
            try await group.waitForAll()
        }
        #expect(recorder.events.count >= 8)
    }

    @Test("debug limits reject invalid values")
    func limitsValidation() {
        #expect(throws: ScriptDebugConfigurationError.nonPositiveLimit(
            name: "maximumEventCount",
            value: 0
        )) {
            _ = try ScriptDebugLimits(maximumEventCount: 0)
        }
    }

    private static func execute(
        unlocking: [UInt8],
        locking: [UInt8],
        debugger: ScriptDebugSession? = nil
    ) throws -> ScriptExecutionResult {
        try ScriptInterpreter.execute(
            unlockingScript: Script(bytes: unlocking, maximumByteCount: 1_024),
            lockingScript: Script(bytes: locking, maximumByteCount: 1_024),
            configuration: ScriptExecutionConfiguration(
                era: .afterGenesis,
                resourceLimits: .standard
            ),
            debugger: debugger
        )
    }
}

private final class EventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [ScriptDebugEvent] = []

    func append(_ event: ScriptDebugEvent) {
        lock.lock()
        stored.append(event)
        lock.unlock()
    }

    var events: [ScriptDebugEvent] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}
