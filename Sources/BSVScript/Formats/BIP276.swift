import BSVCore
import BSVCrypto

/// Explicit allocation limits for BIP-276 text and payloads.
public struct BIP276Limits: Hashable, Sendable {
    public let maximumTextByteCount: Int
    public let maximumPrefixByteCount: Int
    public let maximumDataByteCount: Int

    public init(
        maximumTextByteCount: Int,
        maximumPrefixByteCount: Int,
        maximumDataByteCount: Int
    ) throws {
        guard maximumTextByteCount >= 0,
              maximumPrefixByteCount >= 0,
              maximumDataByteCount >= 0 else {
            throw BIP276Error.invalidLimits
        }
        self.maximumTextByteCount = maximumTextByteCount
        self.maximumPrefixByteCount = maximumPrefixByteCount
        self.maximumDataByteCount = maximumDataByteCount
    }
}

/// Typed data carried by the canonical BIP-276 textual envelope.
public struct BIP276: Hashable, Sendable {
    public static let scriptPrefix = "bitcoin-script"
    public static let templatePrefix = "bitcoin-template"
    public static let currentVersion: UInt8 = 1
    public static let mainnet: UInt8 = 1
    public static let testnet: UInt8 = 2

    public let prefix: String
    public let version: UInt8
    public let network: UInt8
    public let data: [UInt8]

    public init(prefix: String, version: UInt8, network: UInt8, data: [UInt8]) {
        self.prefix = prefix
        self.version = version
        self.network = network
        self.data = data
    }

    public static func encode(_ value: BIP276, limits: BIP276Limits) throws -> String {
        try value.encoded(limits: limits)
    }

    public static func decode(_ text: String, limits: BIP276Limits) throws -> BIP276 {
        try BIP276(text: text, limits: limits)
    }

    /// Encodes lowercase canonical text and the first four bytes of SHA256d as checksum.
    public func encoded(limits: BIP276Limits) throws -> String {
        try Self.validatePrefix(prefix, maximumByteCount: limits.maximumPrefixByteCount)
        guard version != 0 else { throw BIP276Error.invalidVersion }
        guard network != 0 else { throw BIP276Error.invalidNetwork }
        guard data.count <= limits.maximumDataByteCount else {
            throw BIP276Error.dataTooLarge(actual: data.count, maximum: limits.maximumDataByteCount)
        }

        let prefixByteCount = prefix.utf8.count
        let (hexByteCount, hexOverflow) = data.count.multipliedReportingOverflow(by: 2)
        let (baseByteCount, baseOverflow) = prefixByteCount.addingReportingOverflow(13)
        let (textByteCount, totalOverflow) = baseByteCount.addingReportingOverflow(hexByteCount)
        guard !hexOverflow, !baseOverflow, !totalOverflow else {
            throw BIP276Error.textTooLarge(actual: Int.max, maximum: limits.maximumTextByteCount)
        }
        guard textByteCount <= limits.maximumTextByteCount else {
            throw BIP276Error.textTooLarge(actual: textByteCount, maximum: limits.maximumTextByteCount)
        }

        let payload = "\(prefix):\(Self.byteHex(version))\(Self.byteHex(network))\(Hex.encode(data))"
        let checksum = Hex.encode(Array(BSVHashing.sha256d(Array(payload.utf8)).bytes.prefix(4)))
        return payload + checksum
    }

    /// Decodes exactly one lowercase canonical BIP-276 value.
    public init(text: String, limits: BIP276Limits) throws {
        let inspectionLimit = limits.maximumTextByteCount == Int.max
            ? Int.max : limits.maximumTextByteCount + 1
        let bounded = Array(text.utf8.prefix(inspectionLimit))
        guard bounded.count <= limits.maximumTextByteCount else {
            throw BIP276Error.textTooLarge(
                actual: limits.maximumTextByteCount == Int.max ? Int.max : limits.maximumTextByteCount + 1,
                maximum: limits.maximumTextByteCount
            )
        }
        guard bounded.allSatisfy({ $0 < 0x80 }) else { throw BIP276Error.nonCanonicalText }
        guard let separator = bounded.firstIndex(of: 0x3a),
              separator > 0,
              bounded[bounded.index(after: separator)...].firstIndex(of: 0x3a) == nil else {
            throw BIP276Error.invalidFormat
        }
        let prefixBytes = Array(bounded[..<separator])
        guard prefixBytes.count <= limits.maximumPrefixByteCount else {
            throw BIP276Error.prefixTooLarge(actual: prefixBytes.count, maximum: limits.maximumPrefixByteCount)
        }
        let suffix = Array(bounded[bounded.index(after: separator)...])
        guard suffix.count >= 12, suffix.count.isMultiple(of: 2) else {
            throw BIP276Error.invalidFormat
        }
        guard suffix.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }) else {
            throw BIP276Error.nonCanonicalText
        }

        let dataHexByteCount = suffix.count - 12
        let dataByteCount = dataHexByteCount / 2
        guard dataByteCount <= limits.maximumDataByteCount else {
            throw BIP276Error.dataTooLarge(actual: dataByteCount, maximum: limits.maximumDataByteCount)
        }
        let prefix = String(decoding: prefixBytes, as: UTF8.self)
        try Self.validatePrefix(prefix, maximumByteCount: limits.maximumPrefixByteCount)
        let version = try Self.decodeByte(Array(suffix[0..<2]))
        let network = try Self.decodeByte(Array(suffix[2..<4]))
        guard version != 0 else { throw BIP276Error.invalidVersion }
        guard network != 0 else { throw BIP276Error.invalidNetwork }
        let dataText = String(decoding: suffix[4..<(4 + dataHexByteCount)], as: UTF8.self)
        let data: [UInt8]
        do {
            data = try Hex.decode(dataText, maximumDecodedByteCount: limits.maximumDataByteCount)
        } catch let error as TextEncodingError {
            throw BIP276Error.invalidHex(error)
        }

        let payloadBytes = Array(bounded[..<(bounded.count - 8)])
        let expected = Hex.encode(Array(BSVHashing.sha256d(payloadBytes).bytes.prefix(4)))
        let supplied = String(decoding: bounded.suffix(8), as: UTF8.self)
        guard supplied == expected else { throw BIP276Error.invalidChecksum }

        self.init(prefix: prefix, version: version, network: network, data: data)
    }

    private static func validatePrefix(_ prefix: String, maximumByteCount: Int) throws {
        let inspectionLimit = maximumByteCount == Int.max ? Int.max : maximumByteCount + 1
        let bounded = Array(prefix.utf8.prefix(inspectionLimit))
        guard bounded.count <= maximumByteCount else {
            throw BIP276Error.prefixTooLarge(actual: bounded.count, maximum: maximumByteCount)
        }
        guard let first = bounded.first, (0x61...0x7a).contains(first),
              bounded.dropFirst().allSatisfy({
                  (0x61...0x7a).contains($0) || (0x30...0x39).contains($0) || $0 == 0x2d
              }) else {
            throw BIP276Error.invalidPrefix
        }
    }

    private static func byteHex(_ byte: UInt8) -> String {
        Hex.encode([byte])
    }

    private static func decodeByte(_ bytes: [UInt8]) throws -> UInt8 {
        do {
            let decoded = try Hex.decode(
                String(decoding: bytes, as: UTF8.self),
                maximumDecodedByteCount: 1
            )
            guard decoded.count == 1, let value = decoded.first else {
                throw BIP276Error.invalidFormat
            }
            return value
        } catch let error as TextEncodingError {
            throw BIP276Error.invalidHex(error)
        }
    }
}

public enum BIP276Error: Error, Equatable, Sendable {
    case invalidLimits
    case textTooLarge(actual: Int, maximum: Int)
    case prefixTooLarge(actual: Int, maximum: Int)
    case dataTooLarge(actual: Int, maximum: Int)
    case invalidFormat
    case invalidPrefix
    case invalidVersion
    case invalidNetwork
    case invalidHex(TextEncodingError)
    case invalidChecksum
    case nonCanonicalText
}
