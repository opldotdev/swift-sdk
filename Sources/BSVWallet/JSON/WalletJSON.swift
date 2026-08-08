import Foundation

public enum WalletJSON {
    /// Encodes compact JSON with stable object-key ordering.
    public static func encode<T: Encodable>(
        _ value: T,
        limits: WalletCryptoLimits = .standard
    ) throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        if let key = WalletCodingContext.limitsKey {
            encoder.userInfo[key] = limits
        }
        let data: Data
        do {
            data = try encoder.encode(value)
        } catch let error as WalletCryptoError {
            throw error
        } catch let error as WalletValidationError {
            throw error
        } catch {
            throw WalletCryptoError.invalidJSON
        }
        guard data.count <= limits.maximumJSONByteCount else {
            throw WalletCryptoError.encodedJSONTooLarge(
                actual: data.count,
                maximum: limits.maximumJSONByteCount
            )
        }
        return [UInt8](data)
    }

    /// Decodes bounded JSON. The byte limit is checked before parsing.
    public static func decode<T: Decodable>(
        _ type: T.Type,
        from bytes: [UInt8],
        limits: WalletCryptoLimits = .standard
    ) throws -> T {
        guard bytes.count <= limits.maximumJSONByteCount else {
            throw WalletCryptoError.jsonTooLarge(
                actual: bytes.count,
                maximum: limits.maximumJSONByteCount
            )
        }
        let decoder = JSONDecoder()
        if let key = WalletCodingContext.limitsKey {
            decoder.userInfo[key] = limits
        }
        do {
            return try decoder.decode(type, from: Data(bytes))
        } catch let error as WalletCryptoError {
            throw error
        } catch let error as WalletValidationError {
            throw error
        } catch {
            throw WalletCryptoError.invalidJSON
        }
    }
}

internal enum WalletCodingContext {
    static var limitsKey: CodingUserInfoKey? {
        CodingUserInfoKey(rawValue: "org.bsv.swift-sdk.wallet.crypto-limits")
    }

    static func limits(from decoder: Decoder) -> WalletCryptoLimits {
        guard let key = limitsKey,
              let value = decoder.userInfo[key] as? WalletCryptoLimits else {
            return .standard
        }
        return value
    }

    static func limits(from encoder: Encoder) -> WalletCryptoLimits {
        guard let key = limitsKey,
              let value = encoder.userInfo[key] as? WalletCryptoLimits else {
            return .standard
        }
        return value
    }
}

internal struct WalletBoundedBytes: Codable {
    let bytes: [UInt8]

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    init(from decoder: Decoder) throws {
        try self.init(from: decoder, maximum: .max, limitKind: .payload)
    }

    init(
        from decoder: Decoder,
        maximum: Int,
        limitKind: WalletByteLimitKind = .payload
    ) throws {
        var container = try decoder.unkeyedContainer()
        var decoded: [UInt8] = []
        decoded.reserveCapacity(min(container.count ?? 0, maximum))
        while !container.isAtEnd {
            guard decoded.count < maximum else {
                let (nextCount, overflow) = decoded.count.addingReportingOverflow(1)
                throw limitKind.error(actual: overflow ? Int.max : nextCount, maximum: maximum)
            }
            decoded.append(try container.decode(UInt8.self))
        }
        self.bytes = decoded
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.unkeyedContainer()
        for byte in bytes {
            try container.encode(byte)
        }
    }
}

internal enum WalletByteLimitKind {
    case payload
    case ciphertext
    case invalidJSON

    func error(actual: Int, maximum: Int) -> WalletCryptoError {
        switch self {
        case .payload:
            return .payloadTooLarge(actual: actual, maximum: maximum)
        case .ciphertext:
            return .ciphertextTooLarge(actual: actual, maximum: maximum)
        case .invalidJSON:
            return .invalidJSON
        }
    }
}

internal extension KeyedDecodingContainer {
    func decodeWalletBytes(
        forKey key: Key,
        maximum: Int,
        limitKind: WalletByteLimitKind = .payload
    ) throws -> [UInt8] {
        let decoder = try superDecoder(forKey: key)
        return try WalletBoundedBytes(
            from: decoder,
            maximum: maximum,
            limitKind: limitKind
        ).bytes
    }
}

internal extension KeyedEncodingContainer {
    mutating func encodeWalletBytes(_ bytes: [UInt8], forKey key: Key) throws {
        try encode(WalletBoundedBytes(bytes), forKey: key)
    }
}

internal func walletRequirePayloadLimit(_ count: Int, limits: WalletCryptoLimits) throws {
    guard count <= limits.maximumPayloadByteCount else {
        throw WalletCryptoError.payloadTooLarge(
            actual: count,
            maximum: limits.maximumPayloadByteCount
        )
    }
}

internal func walletRequireCiphertextLimit(_ count: Int, limits: WalletCryptoLimits) throws {
    guard count >= 48 else {
        throw WalletCryptoError.ciphertextTooShort(actual: count, minimum: 48)
    }
    guard count <= limits.maximumCiphertextByteCount else {
        throw WalletCryptoError.ciphertextTooLarge(
            actual: count,
            maximum: limits.maximumCiphertextByteCount
        )
    }
}
