import BSVScript
import Foundation

/// Bounds applied to opt-in Script execution diagnostics.
public struct ScriptDebugLimits: Hashable, Sendable {
    public let maximumEventCount: Int
    public let maximumStackItemCount: Int
    public let maximumStackByteCount: Int
    public let maximumStackItemByteCount: Int

    public init(
        maximumEventCount: Int = 10_000,
        maximumStackItemCount: Int = 64,
        maximumStackByteCount: Int = 16 * 1_024,
        maximumStackItemByteCount: Int = 1_024
    ) throws {
        let values = [
            ("maximumEventCount", maximumEventCount),
            ("maximumStackItemCount", maximumStackItemCount),
            ("maximumStackByteCount", maximumStackByteCount),
            ("maximumStackItemByteCount", maximumStackItemByteCount),
        ]
        if let invalid = values.first(where: { $0.1 <= 0 }) {
            throw ScriptDebugConfigurationError.nonPositiveLimit(
                name: invalid.0,
                value: invalid.1
            )
        }
        self.maximumEventCount = maximumEventCount
        self.maximumStackItemCount = maximumStackItemCount
        self.maximumStackByteCount = maximumStackByteCount
        self.maximumStackItemByteCount = maximumStackItemByteCount
    }

    public static let standard = try! Self()
}

public enum ScriptDebugConfigurationError: Error, Equatable, Sendable {
    case nonPositiveLimit(name: String, value: Int)
}

/// The stack affected by a stack-operation event.
public enum ScriptDebugStack: String, Equatable, Sendable {
    case main
    case alternate
}

/// An immutable debugger lifecycle event. Event descriptions deliberately omit script,
/// transaction, and stack bytes; inspect the explicit bounded snapshot when needed.
public enum ScriptDebugEventKind: String, Equatable, Sendable {
    case beforeExecution
    case afterExecution
    case beforeStep
    case afterStep
    case beforeOpcode
    case afterOpcode
    case beforeScriptChange
    case afterScriptChange
    case success
    case failure
    case beforeStackPush
    case afterStackPush
    case beforeStackPop
    case afterStackPop
}

public enum ScriptDebugFailure: Equatable, Sendable {
    case execution(ScriptExecutionError)
    case cancelled
}

/// A bounded copy of the interpreter state at one debugger event.
public struct ScriptDebugSnapshot: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let phase: ScriptPhase?
    public let opcode: Opcode?
    public let instructionOffset: Int?
    public let operationCount: Int
    public let mainStack: [[UInt8]]
    public let alternateStack: [[UInt8]]
    public let mainStackItemCount: Int
    public let alternateStackItemCount: Int
    public let mainStackByteCount: Int
    public let alternateStackByteCount: Int
    public let isTruncated: Bool

    public var description: String {
        let phaseDescription = phase?.rawValue ?? "none"
        let opcodeDescription = opcode.map { String($0.rawValue) } ?? "none"
        return "ScriptDebugSnapshot(phase: \(phaseDescription), opcode: \(opcodeDescription), operationCount: \(operationCount), stackBytes: redacted)"
    }

    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// A bounded immutable diagnostic event delivered by ``ScriptDebugSession``.
public struct ScriptDebugEvent: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let sequence: UInt64
    public let kind: ScriptDebugEventKind
    public let snapshot: ScriptDebugSnapshot
    public let stack: ScriptDebugStack?
    public let stackValue: [UInt8]?
    public let isStackValueTruncated: Bool
    public let failure: ScriptDebugFailure?

    public var description: String {
        "ScriptDebugEvent(sequence: \(sequence), kind: \(kind.rawValue), stackValue: redacted)"
    }

    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// Raised only when an opted-in ``ScriptDebugSession`` has been cancelled.
public enum ScriptDebugError: Error, Equatable, Sendable {
    case cancelled
}

/// A thread-safe, opt-in sink for immutable execution events.
///
/// The callback is intentionally a single immutable event stream rather than Go's mutable
/// callback list. The interpreter never retains a mutable VM state for consumers.
public final class ScriptDebugSession: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public typealias Handler = @Sendable (ScriptDebugEvent) -> Void

    public let limits: ScriptDebugLimits
    private let handler: Handler
    private let lock = NSLock()
    private var cancelled = false
    private var nextSequence: UInt64 = 0

    public init(limits: ScriptDebugLimits = .standard, handler: @escaping Handler) {
        self.limits = limits
        self.handler = handler
    }

    public func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    public var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    public var description: String { "ScriptDebugSession(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }

    fileprivate func emit(_ event: ScriptDebugEvent) throws {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled else { throw ScriptDebugError.cancelled }
        guard nextSequence < UInt64(limits.maximumEventCount) else { return }
        let delivered = ScriptDebugEvent(
            sequence: nextSequence,
            kind: event.kind,
            snapshot: event.snapshot,
            stack: event.stack,
            stackValue: event.stackValue,
            isStackValueTruncated: event.isStackValueTruncated,
            failure: event.failure
        )
        nextSequence += 1
        lock.unlock()
        handler(delivered)
        lock.lock()
    }

    fileprivate func emitBestEffort(_ event: ScriptDebugEvent) {
        try? emit(event)
    }
}

package final class ScriptDebugState: @unchecked Sendable {
    private let session: ScriptDebugSession
    private var phase: ScriptPhase?
    private var opcode: Opcode?
    private var offset: Int?
    private var operationCount = 0
    private var mainStack: [[UInt8]] = []
    private var alternateStack: [[UInt8]] = []

    init(session: ScriptDebugSession) { self.session = session }

    func execution(_ kind: ScriptDebugEventKind, failure: ScriptDebugFailure? = nil) throws {
        try emit(kind, failure: failure)
    }

    func executionBestEffort(_ kind: ScriptDebugEventKind, failure: ScriptDebugFailure? = nil) {
        emitBestEffort(kind, failure: failure)
    }

    func beginStep(phase: ScriptPhase, opcode: Opcode, offset: Int, operationCount: Int) throws {
        self.phase = phase
        self.opcode = opcode
        self.offset = offset
        self.operationCount = operationCount
        try emit(.beforeStep)
        try emit(.beforeOpcode)
    }

    func transition(to phase: ScriptPhase, operationCount: Int) throws {
        self.phase = phase
        opcode = nil
        offset = nil
        self.operationCount = operationCount
        try emit(.afterScriptChange)
    }

    func completeStep(operationCount: Int) {
        self.operationCount = operationCount
        emitBestEffort(.afterOpcode)
        emitBestEffort(.afterStep)
    }

    func stackWillChange(_ stack: ScriptDebugStack, push: Bool, value: [UInt8], items: [[UInt8]]) {
        update(stack, items: items)
        emitBestEffort(push ? .beforeStackPush : .beforeStackPop, stack: stack, value: value)
    }

    func stackDidChange(_ stack: ScriptDebugStack, push: Bool, value: [UInt8], items: [[UInt8]]) {
        update(stack, items: items)
        emitBestEffort(push ? .afterStackPush : .afterStackPop, stack: stack, value: value)
    }

    func stackChanged(_ stack: ScriptDebugStack, items: [[UInt8]]) {
        update(stack, items: items)
    }

    private func update(_ stack: ScriptDebugStack, items: [[UInt8]]) {
        switch stack {
        case .main: mainStack = items
        case .alternate: alternateStack = items
        }
    }

    private func emit(_ kind: ScriptDebugEventKind, stack: ScriptDebugStack? = nil, value: [UInt8]? = nil, failure: ScriptDebugFailure? = nil) throws {
        try session.emit(event(kind, stack: stack, value: value, failure: failure))
    }

    private func emitBestEffort(_ kind: ScriptDebugEventKind, stack: ScriptDebugStack? = nil, value: [UInt8]? = nil, failure: ScriptDebugFailure? = nil) {
        session.emitBestEffort(event(kind, stack: stack, value: value, failure: failure))
    }

    private func event(_ kind: ScriptDebugEventKind, stack: ScriptDebugStack? = nil, value: [UInt8]? = nil, failure: ScriptDebugFailure? = nil) -> ScriptDebugEvent {
        let boundedValue = value.map { Array($0.prefix(session.limits.maximumStackItemByteCount)) }
        return ScriptDebugEvent(
            sequence: 0,
            kind: kind,
            snapshot: snapshot(),
            stack: stack,
            stackValue: boundedValue,
            isStackValueTruncated: value.map { $0.count > session.limits.maximumStackItemByteCount } ?? false,
            failure: failure
        )
    }

    private func snapshot() -> ScriptDebugSnapshot {
        let main = bounded(mainStack)
        let alternate = bounded(alternateStack)
        return ScriptDebugSnapshot(
            phase: phase,
            opcode: opcode,
            instructionOffset: offset,
            operationCount: operationCount,
            mainStack: main.items,
            alternateStack: alternate.items,
            mainStackItemCount: mainStack.count,
            alternateStackItemCount: alternateStack.count,
            mainStackByteCount: mainStack.reduce(0) { $0 + $1.count },
            alternateStackByteCount: alternateStack.reduce(0) { $0 + $1.count },
            isTruncated: main.isTruncated || alternate.isTruncated
        )
    }

    private func bounded(_ stack: [[UInt8]]) -> (items: [[UInt8]], isTruncated: Bool) {
        var bytes = 0
        var result: [[UInt8]] = []
        var truncated = stack.count > session.limits.maximumStackItemCount
        for item in stack.suffix(session.limits.maximumStackItemCount).reversed() {
            guard bytes < session.limits.maximumStackByteCount else {
                truncated = true
                break
            }
            let allowed = min(
                item.count,
                session.limits.maximumStackItemByteCount,
                session.limits.maximumStackByteCount - bytes
            )
            result.append(Array(item.prefix(allowed)))
            bytes += allowed
            truncated = truncated || allowed < item.count
        }
        return (result.reversed(), truncated)
    }
}
