private let scriptJSONHexDigits = Array("0123456789abcdef".utf8)

/// Caller-selected resource limits for Script JSON parsing and serialization.
public struct ScriptJSONLimits: Hashable, Sendable {
    public let maximumJSONByteCount: Int
    public let maximumScriptByteCount: Int

    public init(
        maximumJSONByteCount: Int,
        maximumScriptByteCount: Int
    ) throws {
        guard maximumJSONByteCount >= 0 else {
            throw ScriptError.invalidMaximumJSONByteCount(maximumJSONByteCount)
        }
        guard maximumScriptByteCount >= 0 else {
            throw ScriptError.invalidMaximumScriptByteCount(maximumScriptByteCount)
        }

        self.maximumJSONByteCount = maximumJSONByteCount
        self.maximumScriptByteCount = maximumScriptByteCount
    }
}

extension Script {
    /// Parses one bounded Script JSON value.
    ///
    /// The value is one unescaped lowercase hexadecimal string. RFC JSON
    /// whitespace is accepted around that value, but no other token or trailing
    /// data is accepted.
    public init(jsonBytes: [UInt8], limits: ScriptJSONLimits) throws {
        guard jsonBytes.count <= limits.maximumJSONByteCount else {
            throw ScriptError.jsonTooLarge(
                actual: jsonBytes.count,
                maximum: limits.maximumJSONByteCount
            )
        }

        var offset = 0
        Self.skipJSONWhitespace(in: jsonBytes, offset: &offset)
        guard offset < jsonBytes.count, jsonBytes[offset] == 0x22 else {
            throw ScriptError.invalidJSON
        }
        offset += 1
        let hexStart = offset

        while offset < jsonBytes.count, jsonBytes[offset] != 0x22 {
            let byte = jsonBytes[offset]
            guard byte >= 0x20, byte <= 0x7e, byte != 0x5c else {
                throw ScriptError.invalidJSON
            }
            if !(byte >= 0x30 && byte <= 0x39) && !(byte >= 0x61 && byte <= 0x66) {
                if byte >= 0x41 && byte <= 0x46 {
                    throw ScriptError.invalidJSON
                }
                throw ScriptError.invalidHex(
                    .invalidCharacter(index: offset - hexStart)
                )
            }
            offset += 1
        }
        guard offset < jsonBytes.count else {
            throw ScriptError.invalidJSON
        }

        let hexByteCount = offset - hexStart
        guard hexByteCount.isMultiple(of: 2) else {
            throw ScriptError.invalidHex(.oddLength)
        }
        let scriptByteCount = hexByteCount / 2
        guard scriptByteCount <= limits.maximumScriptByteCount else {
            throw ScriptError.scriptTooLarge(
                actual: scriptByteCount,
                maximum: limits.maximumScriptByteCount
            )
        }

        let hex = String(decoding: jsonBytes[hexStart..<offset], as: UTF8.self)
        offset += 1
        Self.skipJSONWhitespace(in: jsonBytes, offset: &offset)
        guard offset == jsonBytes.count else {
            throw ScriptError.invalidJSON
        }

        self = try Script(hex: hex, maximumByteCount: limits.maximumScriptByteCount)
    }

    /// Returns the bounded canonical Script JSON value.
    public func jsonBytes(limits: ScriptJSONLimits) throws -> [UInt8] {
        guard byteCount <= limits.maximumScriptByteCount else {
            throw ScriptError.scriptTooLarge(
                actual: byteCount,
                maximum: limits.maximumScriptByteCount
            )
        }

        let (hexByteCount, hexOverflow) = byteCount.multipliedReportingOverflow(by: 2)
        let (jsonByteCount, jsonOverflow) = hexByteCount.addingReportingOverflow(2)
        guard !hexOverflow, !jsonOverflow else {
            throw ScriptError.jsonTooLarge(
                actual: .max,
                maximum: limits.maximumJSONByteCount
            )
        }
        guard jsonByteCount <= limits.maximumJSONByteCount else {
            throw ScriptError.jsonTooLarge(
                actual: jsonByteCount,
                maximum: limits.maximumJSONByteCount
            )
        }

        var result: [UInt8] = []
        result.reserveCapacity(jsonByteCount)
        result.append(0x22)
        for byte in bytes {
            result.append(scriptJSONHexDigits[Int(byte >> 4)])
            result.append(scriptJSONHexDigits[Int(byte & 0x0f)])
        }
        result.append(0x22)
        return result
    }

    private static func skipJSONWhitespace(in bytes: [UInt8], offset: inout Int) {
        while offset < bytes.count {
            switch bytes[offset] {
            case 0x20, 0x09, 0x0a, 0x0d:
                offset += 1
            default:
                return
            }
        }
    }
}
