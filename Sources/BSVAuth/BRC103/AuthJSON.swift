/// A JSON value that keeps object members in the order they arrived.
///
/// Certificate request and response signatures cover `JSON.stringify` output of
/// the received objects (`Peer.ts:1070`, `Peer.ts:1205` in `@bsv/sdk` 4.1.1).
/// `JSON.stringify` writes members in insertion order, so a verifier must keep
/// the order the sender used. Foundation's `JSONSerialization` does not.
indirect enum AuthJSONValue: Equatable {
    case null
    case bool(Bool)
    case number(String)
    case string(String)
    case array([AuthJSONValue])
    case object([AuthJSONMember])

    subscript(key: String) -> AuthJSONValue? {
        guard case .object(let members) = self else { return nil }
        return members.first { $0.key == key }?.value
    }
}

struct AuthJSONMember: Equatable {
    let key: String
    let value: AuthJSONValue
}

/// Strict JSON parser for BRC-103 envelopes.
///
/// It rejects duplicate object keys (compared after unescaping), invalid UTF-8,
/// lone surrogate escapes, control characters, excessive nesting, and trailing
/// data. Only the top-level members named in `retaining` are materialized; the
/// rest is validated and skipped so large payload arrays are not copied twice.
struct AuthJSONParser {
    static let maximumNestingDepth = 64

    private let bytes: [UInt8]
    private var offset = 0

    private init(bytes: [UInt8]) { self.bytes = bytes }

    /// Validates a complete envelope and returns the retained top-level members.
    static func parseEnvelope(
        _ bytes: [UInt8],
        retaining names: Set<String>
    ) throws -> [String: AuthJSONValue] {
        var parser = Self(bytes: bytes)
        try parser.skipWhitespace()
        guard parser.peek() == 0x7b else { throw AuthError.invalidMessage }
        var retained: [String: AuthJSONValue] = [:]
        try parser.parseObject(depth: 1, build: false) { key, parser, depth in
            if names.contains(key) {
                retained[key] = try parser.parseValue(depth: depth, build: true)
            } else {
                _ = try parser.parseValue(depth: depth, build: false)
            }
        }
        try parser.skipWhitespace()
        guard parser.offset == bytes.count else { throw AuthError.invalidMessage }
        return retained
    }

    /// Parses one complete JSON document into an ordered tree.
    static func parse(_ bytes: [UInt8]) throws -> AuthJSONValue {
        var parser = Self(bytes: bytes)
        try parser.skipWhitespace()
        guard let value = try parser.parseValue(depth: 0, build: true) else {
            throw AuthError.invalidMessage
        }
        try parser.skipWhitespace()
        guard parser.offset == bytes.count else { throw AuthError.invalidMessage }
        return value
    }

    private mutating func parseValue(depth: Int, build: Bool) throws -> AuthJSONValue? {
        guard depth <= Self.maximumNestingDepth, let byte = peek() else {
            throw AuthError.invalidMessage
        }
        switch byte {
        case 0x7b:
            var members: [AuthJSONMember] = []
            try parseObject(depth: depth + 1, build: build) { key, parser, depth in
                let value = try parser.parseValue(depth: depth, build: build)
                if build, let value { members.append(.init(key: key, value: value)) }
            }
            return build ? .object(members) : nil
        case 0x5b:
            return try parseArray(depth: depth + 1, build: build)
        case 0x22:
            let text = try parseString()
            return build ? .string(text) : nil
        case 0x74:
            try consumeLiteral("true")
            return .bool(true)
        case 0x66:
            try consumeLiteral("false")
            return .bool(false)
        case 0x6e:
            try consumeLiteral("null")
            return .null
        case 0x2d, 0x30...0x39:
            let start = offset
            try parseNumber()
            return build ? .number(String(decoding: bytes[start..<offset], as: UTF8.self)) : nil
        default:
            throw AuthError.invalidMessage
        }
    }

    private mutating func parseObject(
        depth: Int,
        build: Bool,
        member: (String, inout AuthJSONParser, Int) throws -> Void
    ) throws {
        guard depth <= Self.maximumNestingDepth else { throw AuthError.invalidMessage }
        try consume(0x7b)
        try skipWhitespace()
        if consumeIfPresent(0x7d) { return }
        var names = Set<String>()
        while true {
            guard peek() == 0x22 else { throw AuthError.invalidMessage }
            let key = try parseString()
            guard names.insert(key).inserted else { throw AuthError.invalidMessage }
            try skipWhitespace()
            try consume(0x3a)
            try skipWhitespace()
            try member(key, &self, depth)
            try skipWhitespace()
            if consumeIfPresent(0x7d) { return }
            try consume(0x2c)
            try skipWhitespace()
        }
    }

    private mutating func parseArray(depth: Int, build: Bool) throws -> AuthJSONValue? {
        guard depth <= Self.maximumNestingDepth else { throw AuthError.invalidMessage }
        try consume(0x5b)
        try skipWhitespace()
        var values: [AuthJSONValue] = []
        if consumeIfPresent(0x5d) { return build ? .array(values) : nil }
        while true {
            let value = try parseValue(depth: depth, build: build)
            if build, let value { values.append(value) }
            try skipWhitespace()
            if consumeIfPresent(0x5d) { return build ? .array(values) : nil }
            try consume(0x2c)
            try skipWhitespace()
        }
    }

    private mutating func parseString() throws -> String {
        try consume(0x22)
        var scalars = String.UnicodeScalarView()
        var run = offset
        func flush(_ end: Int) throws {
            guard run < end else { return }
            var iterator = bytes[run..<end].makeIterator()
            var decoder = UTF8()
            while true {
                switch decoder.decode(&iterator) {
                case .scalarValue(let scalar): scalars.append(scalar)
                case .emptyInput: return
                case .error: throw AuthError.invalidMessage
                }
            }
        }
        while offset < bytes.count {
            let byte = bytes[offset]
            switch byte {
            case 0x22:
                try flush(offset)
                offset += 1
                return String(scalars)
            case 0x00...0x1f:
                throw AuthError.invalidMessage
            case 0x5c:
                try flush(offset)
                offset += 1
                scalars.append(try parseEscape())
                run = offset
            default:
                offset += 1
            }
        }
        throw AuthError.invalidMessage
    }

    private mutating func parseEscape() throws -> Unicode.Scalar {
        guard let escaped = peek() else { throw AuthError.invalidMessage }
        offset += 1
        switch escaped {
        case 0x22: return "\""
        case 0x5c: return "\\"
        case 0x2f: return "/"
        case 0x62: return "\u{08}"
        case 0x66: return "\u{0c}"
        case 0x6e: return "\n"
        case 0x72: return "\r"
        case 0x74: return "\t"
        case 0x75:
            let first = try parseHex4()
            if (0xd800...0xdbff).contains(first) {
                guard consumeIfPresent(0x5c), consumeIfPresent(0x75) else {
                    throw AuthError.invalidMessage
                }
                let second = try parseHex4()
                guard (0xdc00...0xdfff).contains(second) else { throw AuthError.invalidMessage }
                let value = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                guard let scalar = Unicode.Scalar(value) else { throw AuthError.invalidMessage }
                return scalar
            }
            guard let scalar = Unicode.Scalar(first) else { throw AuthError.invalidMessage }
            return scalar
        default:
            throw AuthError.invalidMessage
        }
    }

    private mutating func parseHex4() throws -> UInt32 {
        guard bytes.count - offset >= 4 else { throw AuthError.invalidMessage }
        var value: UInt32 = 0
        for _ in 0..<4 {
            let byte = bytes[offset]
            let digit: UInt32
            switch byte {
            case 0x30...0x39: digit = UInt32(byte - 0x30)
            case 0x41...0x46: digit = UInt32(byte - 0x41 + 10)
            case 0x61...0x66: digit = UInt32(byte - 0x61 + 10)
            default: throw AuthError.invalidMessage
            }
            value = value << 4 | digit
            offset += 1
        }
        return value
    }

    private mutating func parseNumber() throws {
        _ = consumeIfPresent(0x2d)
        guard let first = peek() else { throw AuthError.invalidMessage }
        if first == 0x30 {
            offset += 1
            if let next = peek(), isDigit(next) { throw AuthError.invalidMessage }
        } else {
            guard (0x31...0x39).contains(first) else { throw AuthError.invalidMessage }
            skipDigits()
        }
        if consumeIfPresent(0x2e) {
            guard let next = peek(), isDigit(next) else { throw AuthError.invalidMessage }
            skipDigits()
        }
        if let next = peek(), next == 0x65 || next == 0x45 {
            offset += 1
            if let sign = peek(), sign == 0x2b || sign == 0x2d { offset += 1 }
            guard let digit = peek(), isDigit(digit) else { throw AuthError.invalidMessage }
            skipDigits()
        }
    }

    private mutating func skipDigits() {
        while let byte = peek(), isDigit(byte) { offset += 1 }
    }

    private mutating func consumeLiteral(_ literal: StaticString) throws {
        let expected = Array(String(describing: literal).utf8)
        guard bytes.count - offset >= expected.count,
            bytes[offset..<(offset + expected.count)].elementsEqual(expected)
        else { throw AuthError.invalidMessage }
        offset += expected.count
    }

    private mutating func skipWhitespace() throws {
        while let byte = peek(), byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0d {
            offset += 1
        }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard consumeIfPresent(expected) else { throw AuthError.invalidMessage }
    }

    private mutating func consumeIfPresent(_ expected: UInt8) -> Bool {
        guard peek() == expected else { return false }
        offset += 1
        return true
    }

    private func peek() -> UInt8? { offset < bytes.count ? bytes[offset] : nil }

    private func isDigit(_ byte: UInt8) -> Bool { (0x30...0x39).contains(byte) }
}

/// Writes JSON exactly as ECMAScript `JSON.stringify` does for strings,
/// arrays and plain objects.
///
/// - Object members follow ECMAScript property order: array-index keys first in
///   ascending numeric order, then the other keys in insertion order. This is
///   the order a TypeScript peer sees after `JSON.parse`.
/// - Strings escape only `"`, `\`, `\b`, `\t`, `\n`, `\f`, `\r` and the other
///   C0 controls (as lowercase `\u00xx`). `/`, `&`, `<`, `>`, U+2028 and U+2029
///   are written as they are.
struct AuthJSONWriter {
    private(set) var bytes: [UInt8] = []
    private let maximumByteCount: Int

    init(maximumByteCount: Int) {
        self.maximumByteCount = maximumByteCount
        bytes.reserveCapacity(min(maximumByteCount, 4_096))
    }

    mutating func append(_ text: String) throws {
        try append(Array(text.utf8))
    }

    mutating func append(_ value: [UInt8]) throws {
        let (next, overflow) = bytes.count.addingReportingOverflow(value.count)
        guard !overflow, next <= maximumByteCount else { throw AuthError.resourceLimit }
        bytes.append(contentsOf: value)
    }

    mutating func appendString(_ text: String) throws {
        try append([0x22])
        var run: [UInt8] = []
        for scalar in text.unicodeScalars {
            let escape: String?
            switch scalar.value {
            case 0x08: escape = #"\b"#
            case 0x09: escape = #"\t"#
            case 0x0a: escape = #"\n"#
            case 0x0c: escape = #"\f"#
            case 0x0d: escape = #"\r"#
            case 0x22: escape = #"\""#
            case 0x5c: escape = #"\\"#
            case 0x00...0x1f:
                let digits = Array("0123456789abcdef")
                escape = "\\u00" + String(digits[Int(scalar.value >> 4)])
                    + String(digits[Int(scalar.value & 0x0f)])
            default: escape = nil
            }
            if let escape {
                run.append(contentsOf: escape.utf8)
            } else {
                run.append(contentsOf: String(scalar).utf8)
            }
        }
        try append(run)
        try append([0x22])
    }

    /// Writes `value` as `JSON.stringify(JSON.parse(text))` would.
    mutating func appendValue(_ value: AuthJSONValue) throws {
        switch value {
        case .null: try append("null")
        case .bool(let flag): try append(flag ? "true" : "false")
        case .number:
            // No certificate request or response member is numeric. ECMAScript
            // would renormalize the number text, so refuse instead of guessing.
            throw AuthError.invalidMessage
        case .string(let text): try appendString(text)
        case .array(let values):
            try append("[")
            for index in values.indices {
                if index > 0 { try append(",") }
                try appendValue(values[index])
            }
            try append("]")
        case .object(let members):
            try append("{")
            for (index, member) in Self.ecmaScriptOrder(members).enumerated() {
                if index > 0 { try append(",") }
                try appendString(member.key)
                try append(":")
                try appendValue(member.value)
            }
            try append("}")
        }
    }

    /// ECMAScript `OrdinaryOwnPropertyKeys` order for string keys.
    static func ecmaScriptOrder(_ members: [AuthJSONMember]) -> [AuthJSONMember] {
        let indexed = members.compactMap { member in
            arrayIndex(member.key).map { (index: $0, member: member) }
        }
        guard !indexed.isEmpty else { return members }
        return indexed.sorted { $0.index < $1.index }.map(\.member)
            + members.filter { arrayIndex($0.key) == nil }
    }

    /// Orders names the way this SDK writes them: array-index names first (as
    /// ECMAScript places them), then the rest by UTF-8 bytes.
    static func canonicalOrder(_ names: [String]) -> [String] {
        names.sorted { lhs, rhs in
            switch (arrayIndex(lhs), arrayIndex(rhs)) {
            case (let left?, let right?): return left < right
            case (.some, .none): return true
            case (.none, .some): return false
            case (.none, .none): return lhs.utf8.lexicographicallyPrecedes(rhs.utf8)
            }
        }
    }

    /// A canonical decimal array index below 2^32 - 1, as ECMAScript defines it.
    static func arrayIndex(_ key: String) -> UInt32? {
        let utf8 = Array(key.utf8)
        guard !utf8.isEmpty, utf8.count <= 10, utf8.allSatisfy({ (0x30...0x39).contains($0) }),
            utf8.count == 1 || utf8[0] != 0x30,
            let value = UInt64(key), value < 0xffff_ffff
        else { return nil }
        return UInt32(value)
    }
}
