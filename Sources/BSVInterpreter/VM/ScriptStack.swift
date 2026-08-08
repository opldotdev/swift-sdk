package struct ScriptStack: Sendable {
    private(set) var items: [[UInt8]] = []
    private(set) var memoryByteCount = 0
    private let debugState: ScriptDebugState?
    private let debugStack: ScriptDebugStack

    init(
        debugState: ScriptDebugState? = nil,
        debugStack: ScriptDebugStack = .main
    ) {
        self.debugState = debugState
        self.debugStack = debugStack
    }

    var count: Int { items.count }

    mutating func push(_ value: [UInt8]) {
        debugState?.stackWillChange(debugStack, push: true, value: value, items: items)
        items.append(value)
        memoryByteCount += value.count
        debugState?.stackDidChange(debugStack, push: true, value: value, items: items)
    }

    mutating func pop() throws -> [UInt8] {
        guard let value = items.popLast() else {
            throw ScriptExecutionError.consensus(.stackUnderflow(required: 1, available: 0))
        }
        // Restore the pre-pop state before emitting the before hook; `popLast` above
        // lets us preserve the existing underflow behaviour without an extra lookup.
        items.append(value)
        debugState?.stackWillChange(debugStack, push: false, value: value, items: items)
        _ = items.popLast()
        memoryByteCount -= value.count
        debugState?.stackDidChange(debugStack, push: false, value: value, items: items)
        return value
    }

    func peek(_ depth: Int = 0) throws -> [UInt8] {
        guard depth >= 0, depth < items.count else {
            throw ScriptExecutionError.consensus(.invalidStackIndex(depth))
        }
        return items[items.count - depth - 1]
    }

    mutating func remove(depth: Int) throws -> [UInt8] {
        guard depth >= 0, depth < items.count else {
            throw ScriptExecutionError.consensus(.invalidStackIndex(depth))
        }
        let value = items.remove(at: items.count - depth - 1)
        memoryByteCount -= value.count
        debugState?.stackChanged(debugStack, items: items)
        return value
    }

    mutating func require(_ count: Int) throws {
        guard items.count >= count else {
            throw ScriptExecutionError.consensus(.stackUnderflow(
                required: count,
                available: items.count
            ))
        }
    }

    mutating func removeAll() {
        items.removeAll(keepingCapacity: true)
        memoryByteCount = 0
        debugState?.stackChanged(debugStack, items: items)
    }
}

package func scriptBoolean(_ bytes: [UInt8]) -> Bool {
    for index in bytes.indices where bytes[index] != 0 {
        return !(index == bytes.index(before: bytes.endIndex) && bytes[index] == 0x80)
    }
    return false
}

package func scriptBooleanBytes(_ value: Bool) -> [UInt8] {
    value ? [1] : []
}
