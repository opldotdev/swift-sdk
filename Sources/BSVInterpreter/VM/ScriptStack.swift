package struct ScriptStack: Sendable {
    private(set) var items: [[UInt8]] = []
    private(set) var memoryByteCount = 0

    var count: Int { items.count }

    mutating func push(_ value: [UInt8]) {
        items.append(value)
        memoryByteCount += value.count
    }

    mutating func pop() throws -> [UInt8] {
        guard let value = items.popLast() else {
            throw ScriptExecutionError.consensus(.stackUnderflow(required: 1, available: 0))
        }
        memoryByteCount -= value.count
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
