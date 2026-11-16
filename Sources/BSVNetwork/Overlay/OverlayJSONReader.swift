import Foundation

/// A forward-only reader over JSON that ``StrictOverlayJSONPreflight`` has
/// already accepted.
///
/// Lookup answers carry BEEF as JSON arrays of numbers. Parsing those with
/// `JSONSerialization` boxes every byte as an object, so a 64 MiB answer could
/// cost gigabytes. This reader decodes byte arrays straight into `[UInt8]`,
/// skips values it does not need without building them, and so keeps memory
/// proportional to the body.
final class OverlayJSONReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ bytes: [UInt8], offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    /// Calls `visit` with each member name of the object at the cursor. The
    /// visitor must consume the member's value.
    func readObject(_ visit: (String) throws -> Void) throws {
        try consume(0x7b)
        skipWhitespace()
        if consumeIfPresent(0x7d) { return }
        while true {
            let key = try readKey()
            skipWhitespace()
            try consume(0x3a)
            skipWhitespace()
            try visit(key)
            skipWhitespace()
            if consumeIfPresent(0x7d) { return }
            try consume(0x2c)
            skipWhitespace()
        }
    }

    /// Calls `visit` for each element of the array at the cursor. The visitor
    /// must consume the element.
    func readArray(_ visit: () throws -> Void) throws {
        try consume(0x5b)
        skipWhitespace()
        if consumeIfPresent(0x5d) { return }
        while true {
            try visit()
            skipWhitespace()
            if consumeIfPresent(0x5d) { return }
            try consume(0x2c)
            skipWhitespace()
        }
    }

    /// The first byte of the value at the cursor.
    var next: UInt8? { offset < bytes.count ? bytes[offset] : nil }

    func readNull() -> Bool {
        let literal: [UInt8] = [0x6e, 0x75, 0x6c, 0x6c]
        guard bytes.count - offset >= 4, bytes[offset..<(offset + 4)].elementsEqual(literal)
        else { return false }
        offset += 4
        return true
    }

    /// A JSON string value, with escapes decoded.
    func readString() throws -> String {
        let range = try valueRange()
        guard bytes[range.lowerBound] == 0x22,
            let text = try? JSONSerialization.jsonObject(
                with: Data(bytes[range]), options: .fragmentsAllowed) as? String
        else { throw OverlayHTTPError.malformedResponse }
        return text
    }

    /// A JSON number that is a whole number in `0...UInt32.max`, or nil for
    /// any other value. The value is consumed either way.
    func readUInt32() throws -> UInt32? {
        let range = try valueRange()
        let token = bytes[range]
        if token.count <= 3, token.allSatisfy({ (0x30...0x39).contains($0) }) {
            return token.reduce(UInt32(0)) { $0 * 10 + UInt32($1 - 0x30) }
        }
        guard let first = token.first, first == 0x2d || (0x30...0x39).contains(first),
            let number = Double(String(decoding: token, as: UTF8.self)),
            number.isFinite,
            number.rounded(.towardZero) == number,
            number >= 0,
            number <= Double(UInt32.max)
        else { return nil }
        return UInt32(number)
    }

    /// A JSON array of integers 0...255, or an object whose keys are exactly
    /// "0" through "n-1" with byte values, as `normalizeBRC100ByteArray` in
    /// `@bsv/sdk` reads it (`wallet/BRC100ByteEncoding.ts:45-87,126-146`). An
    /// empty object is an empty byte array there.
    func readByteArray(maximum: Int) throws -> [UInt8] {
        switch next {
        case 0x5b:
            var result: [UInt8] = []
            try readArray {
                guard result.count < maximum else { throw OverlayHTTPError.resourceLimit }
                guard let value = try readUInt32(), value <= 255 else {
                    throw OverlayHTTPError.malformedResponse
                }
                result.append(UInt8(value))
            }
            return result
        case 0x7b:
            var indexes: [Int] = []
            var values: [UInt8] = []
            try readObject { key in
                guard indexes.count < maximum else { throw OverlayHTTPError.resourceLimit }
                guard let index = Int(key), String(index) == key,
                    let value = try readUInt32(), value <= 255
                else { throw OverlayHTTPError.malformedResponse }
                indexes.append(index)
                values.append(UInt8(value))
            }
            var result = [UInt8](repeating: 0, count: indexes.count)
            var seen = [Bool](repeating: false, count: indexes.count)
            for (index, value) in zip(indexes, values) {
                guard result.indices.contains(index), !seen[index] else {
                    throw OverlayHTTPError.malformedResponse
                }
                seen[index] = true
                result[index] = value
            }
            return result
        default:
            throw OverlayHTTPError.malformedResponse
        }
    }

    /// Skips the value at the cursor and returns where it was.
    func valueRange() throws -> Range<Int> {
        let start = offset
        guard let first = next else { throw OverlayHTTPError.malformedResponse }
        switch first {
        case 0x22:
            try skipString()
        case 0x7b, 0x5b:
            var depth = 0
            repeat {
                guard let byte = next else { throw OverlayHTTPError.malformedResponse }
                switch byte {
                case 0x22:
                    try skipString()
                    continue
                case 0x7b, 0x5b: depth += 1
                case 0x7d, 0x5d: depth -= 1
                default: break
                }
                offset += 1
            } while depth > 0
        default:
            while let byte = next,
                !(byte == 0x2c || byte == 0x7d || byte == 0x5d || byte == 0x20
                    || byte == 0x09 || byte == 0x0a || byte == 0x0d)
            {
                offset += 1
            }
        }
        guard offset > start else { throw OverlayHTTPError.malformedResponse }
        return start..<offset
    }

    func skipValue() throws {
        _ = try valueRange()
    }

    /// Object keys are printable ASCII without escapes; the preflight
    /// rejects any other key.
    private func readKey() throws -> String {
        try consume(0x22)
        let start = offset
        while let byte = next, byte != 0x22 { offset += 1 }
        guard next == 0x22 else { throw OverlayHTTPError.malformedResponse }
        let key = String(decoding: bytes[start..<offset], as: UTF8.self)
        offset += 1
        return key
    }

    private func skipString() throws {
        try consume(0x22)
        while let byte = next {
            offset += 1
            if byte == 0x22 { return }
            if byte == 0x5c { offset += 1 }
        }
        throw OverlayHTTPError.malformedResponse
    }

    private func skipWhitespace() {
        while let byte = next, byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0d {
            offset += 1
        }
    }

    private func consume(_ expected: UInt8) throws {
        guard consumeIfPresent(expected) else { throw OverlayHTTPError.malformedResponse }
    }

    private func consumeIfPresent(_ expected: UInt8) -> Bool {
        guard next == expected else { return false }
        offset += 1
        return true
    }
}
