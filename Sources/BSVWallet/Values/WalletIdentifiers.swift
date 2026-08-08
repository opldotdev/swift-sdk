import BSVCore

public enum WalletSecurityLevel: UInt8, CaseIterable, Codable, Sendable {
    case silent = 0
    case everyApp = 1
    case everyAppAndCounterparty = 2

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(Int.self)
        guard let value = Self(rawValue: UInt8(exactly: raw) ?? .max) else {
            throw WalletValidationError.invalidSecurityLevel(raw)
        }
        self = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public enum WalletValidationError: Error, Equatable, Sendable {
    case invalidSecurityLevel(Int)
    case protocolNameTooShort(actualUTF8ByteCount: Int, minimum: Int)
    case protocolNameTooLong(actualUTF8ByteCount: Int, maximum: Int)
    case invalidProtocolCharacter(asciiByteOffset: Int)
    case consecutiveProtocolSpaces
    case redundantProtocolSuffix
    case reservedAdminProtocol
    case keyIDTooShort
    case keyIDTooLong(actualUTF8ByteCount: Int, maximum: Int)
    case privilegedReasonTooLong(actualUTF8ByteCount: Int, maximum: Int)
    case invalidLimit(name: String, value: Int)
}

/// A validated, canonical BRC-43 protocol identifier.
///
/// This safety profile accepts only lowercase-normalized ASCII letters,
/// digits, and single spaces after trimming ASCII whitespace. It also reserves
/// the `admin` prefix. Inputs accepted by the pinned Go SDK outside this
/// profile fail with a typed error instead of deriving a different key.
public struct WalletProtocolID: Hashable, Codable, Sendable {
    public static let minimumNameUTF8ByteCount = 5
    public static let maximumNameUTF8ByteCount = 400

    public let securityLevel: WalletSecurityLevel
    public let name: String

    public init(securityLevel: WalletSecurityLevel, name: String) throws {
        let source = Array(name.utf8)
        let start = source.firstIndex(where: { !Self.isASCIIWhitespace($0) }) ?? source.endIndex
        let end: Int
        if let last = source.lastIndex(where: { !Self.isASCIIWhitespace($0) }) {
            end = source.index(after: last)
        } else {
            end = start
        }
        var bytes = Array(source[start..<end])
        for index in bytes.indices where (65...90).contains(bytes[index]) {
            bytes[index] += 32
        }

        guard bytes.count >= Self.minimumNameUTF8ByteCount else {
            throw WalletValidationError.protocolNameTooShort(
                actualUTF8ByteCount: bytes.count,
                minimum: Self.minimumNameUTF8ByteCount
            )
        }
        guard bytes.count <= Self.maximumNameUTF8ByteCount else {
            throw WalletValidationError.protocolNameTooLong(
                actualUTF8ByteCount: bytes.count,
                maximum: Self.maximumNameUTF8ByteCount
            )
        }

        for (offset, byte) in bytes.enumerated() {
            let permitted = (97...122).contains(byte)
                || (48...57).contains(byte)
                || byte == 32
            guard permitted else {
                throw WalletValidationError.invalidProtocolCharacter(asciiByteOffset: offset)
            }
        }
        for index in bytes.indices.dropFirst() where bytes[index] == 32 && bytes[index - 1] == 32 {
            throw WalletValidationError.consecutiveProtocolSpaces
        }

        let normalized = String(decoding: bytes, as: UTF8.self)
        guard !normalized.hasSuffix(" protocol") else {
            throw WalletValidationError.redundantProtocolSuffix
        }
        guard !normalized.hasPrefix("admin") else {
            throw WalletValidationError.reservedAdminProtocol
        }

        self.securityLevel = securityLevel
        self.name = normalized
    }

    public init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        guard container.count == 2 else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "protocolID must contain exactly two values"
            )
        }
        let level = try container.decode(WalletSecurityLevel.self)
        let name = try container.decode(String.self)
        guard container.isAtEnd else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "protocolID must contain exactly two values"
            )
        }
        try self.init(securityLevel: level, name: name)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.unkeyedContainer()
        try container.encode(securityLevel)
        try container.encode(name)
    }

    private static func isASCIIWhitespace(_ byte: UInt8) -> Bool {
        byte == 32 || (9...13).contains(byte)
    }
}

/// A BRC-43 key identifier. Swift strings and value copies cannot guarantee
/// zeroization, so avoid retaining unnecessary copies of sensitive IDs.
public struct WalletKeyID:
    Hashable,
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public static let minimumUTF8ByteCount = 1
    public static let maximumUTF8ByteCount = 800

    /// Explicit export. The value is otherwise redacted from diagnostics.
    public let value: String

    public init(_ value: String) throws {
        let byteCount = value.utf8.count
        guard byteCount >= Self.minimumUTF8ByteCount else {
            throw WalletValidationError.keyIDTooShort
        }
        guard byteCount <= Self.maximumUTF8ByteCount else {
            throw WalletValidationError.keyIDTooLong(
                actualUTF8ByteCount: byteCount,
                maximum: Self.maximumUTF8ByteCount
            )
        }
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(container.decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.value.utf8.elementsEqual(rhs.value.utf8)
    }

    public func hash(into hasher: inout Hasher) {
        for byte in value.utf8 { hasher.combine(byte) }
    }

    public var description: String { "<redacted wallet key ID>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

internal func walletEmptyMirror<T>(_ value: T) -> Mirror {
    Mirror(value, children: EmptyCollection<(label: String?, value: Any)>())
}
