struct StrictOverlayJSONPreflight {
    private static let maximumNestingDepth = 64
    private let bytes: [UInt8]
    private var offset = 0

    static func accepts(_ bytes: [UInt8]) -> Bool {
        var parser = Self(bytes: bytes)
        do {
            parser.skipWhitespace()
            try parser.parseValue(depth: 0)
            parser.skipWhitespace()
            return parser.offset == bytes.count
        } catch {
            return false
        }
    }

    private mutating func parseValue(depth: Int) throws {
        guard depth <= Self.maximumNestingDepth, offset < bytes.count else {
            throw OverlayHTTPError.malformedResponse
        }
        switch bytes[offset] {
        case 0x7b: try parseObject(depth: depth + 1)
        case 0x5b: try parseArray(depth: depth + 1)
        case 0x22: try parseString()
        case 0x74: try consumeLiteral("true")
        case 0x66: try consumeLiteral("false")
        case 0x6e: try consumeLiteral("null")
        case 0x2d, 0x30...0x39: try parseNumber()
        default: throw OverlayHTTPError.malformedResponse
        }
    }

    private mutating func parseObject(depth: Int) throws {
        try consume(0x7b)
        skipWhitespace()
        if consumeIfPresent(0x7d) { return }
        var names = Set<String>()
        while true {
            let name = try parseObjectKey()
            guard names.insert(name).inserted else { throw OverlayHTTPError.malformedResponse }
            skipWhitespace()
            try consume(0x3a)
            skipWhitespace()
            try parseValue(depth: depth)
            skipWhitespace()
            if consumeIfPresent(0x7d) { return }
            try consume(0x2c)
            skipWhitespace()
        }
    }

    private mutating func parseArray(depth: Int) throws {
        try consume(0x5b)
        skipWhitespace()
        if consumeIfPresent(0x5d) { return }
        while true {
            try parseValue(depth: depth)
            skipWhitespace()
            if consumeIfPresent(0x5d) { return }
            try consume(0x2c)
            skipWhitespace()
        }
    }

    private mutating func parseObjectKey() throws -> String {
        try consume(0x22)
        let start = offset
        while offset < bytes.count, bytes[offset] != 0x22 {
            let byte = bytes[offset]
            guard byte >= 0x20, byte <= 0x7e, byte != 0x5c else {
                throw OverlayHTTPError.malformedResponse
            }
            offset += 1
        }
        guard offset < bytes.count else { throw OverlayHTTPError.malformedResponse }
        let name = String(decoding: bytes[start..<offset], as: UTF8.self)
        offset += 1
        return name
    }

    private mutating func parseString() throws {
        try consume(0x22)
        while offset < bytes.count {
            let byte = bytes[offset]
            offset += 1
            switch byte {
            case 0x22: return
            case 0x00...0x1f: throw OverlayHTTPError.malformedResponse
            case 0x5c:
                guard offset < bytes.count else { throw OverlayHTTPError.malformedResponse }
                let escaped = bytes[offset]
                offset += 1
                if escaped == 0x75 {
                    for _ in 0..<4 {
                        guard offset < bytes.count, isHexDigit(bytes[offset]) else {
                            throw OverlayHTTPError.malformedResponse
                        }
                        offset += 1
                    }
                } else if ![0x22, 0x5c, 0x2f, 0x62, 0x66, 0x6e, 0x72, 0x74].contains(escaped) {
                    throw OverlayHTTPError.malformedResponse
                }
            default: continue
            }
        }
        throw OverlayHTTPError.malformedResponse
    }

    private mutating func parseNumber() throws {
        _ = consumeIfPresent(0x2d)
        guard offset < bytes.count else { throw OverlayHTTPError.malformedResponse }
        if consumeIfPresent(0x30) {
            if offset < bytes.count, isDigit(bytes[offset]) {
                throw OverlayHTTPError.malformedResponse
            }
        } else {
            guard (0x31...0x39).contains(bytes[offset]) else {
                throw OverlayHTTPError.malformedResponse
            }
            offset += 1
            while offset < bytes.count, isDigit(bytes[offset]) { offset += 1 }
        }
        if consumeIfPresent(0x2e) {
            guard offset < bytes.count, isDigit(bytes[offset]) else {
                throw OverlayHTTPError.malformedResponse
            }
            while offset < bytes.count, isDigit(bytes[offset]) { offset += 1 }
        }
        if offset < bytes.count, bytes[offset] == 0x65 || bytes[offset] == 0x45 {
            offset += 1
            if offset < bytes.count, bytes[offset] == 0x2b || bytes[offset] == 0x2d {
                offset += 1
            }
            guard offset < bytes.count, isDigit(bytes[offset]) else {
                throw OverlayHTTPError.malformedResponse
            }
            while offset < bytes.count, isDigit(bytes[offset]) { offset += 1 }
        }
    }

    private mutating func consumeLiteral(_ literal: StaticString) throws {
        let expected = Array(String(describing: literal).utf8)
        guard bytes.count - offset >= expected.count,
            bytes[offset..<(offset + expected.count)].elementsEqual(expected)
        else { throw OverlayHTTPError.malformedResponse }
        offset += expected.count
    }

    private mutating func skipWhitespace() {
        while offset < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[offset]) {
            offset += 1
        }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard consumeIfPresent(expected) else { throw OverlayHTTPError.malformedResponse }
    }

    private mutating func consumeIfPresent(_ expected: UInt8) -> Bool {
        guard offset < bytes.count, bytes[offset] == expected else { return false }
        offset += 1
        return true
    }

    private func isDigit(_ byte: UInt8) -> Bool { (0x30...0x39).contains(byte) }
    private func isHexDigit(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte)
            || (0x41...0x46).contains(byte)
            || (0x61...0x66).contains(byte)
    }
}
