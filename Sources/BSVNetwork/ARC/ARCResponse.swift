import BSVCore
import CoreFoundation
import Foundation

/// A validated ARC response using the Go SDK's JSON field vocabulary.
///
/// ARC uses related but different response shapes for transaction submission
/// and status lookup. A submission has `status`, `txStatus`, and `txid`. A
/// status lookup has `txStatus` and `txid`, but it does not have `status`.
/// Error responses can have `status` and `txid` without `txStatus`.
///
/// `txid` is required for every response that this SDK returns. `status` and
/// `txStatus` are optional so one value type can represent the official ARC
/// response union and the Go SDK `ArcResponse` type. Each client operation
/// checks the fields that its response requires.
public struct ARCResponse: Hashable, Sendable {
    public let blockHash: String?
    public let blockHeight: UInt64?
    public let extraInfo: String?
    public let status: Int?
    public let timestamp: Date?
    public let title: String?
    public let txStatus: ARCStatus?
    public let instance: String?
    public let transactionID: TransactionID
    public let detail: String?
    public let merklePath: String?

    /// The Go-compatible `txid` field in canonical display order.
    public var txid: String { transactionID.displayHex }

    package init(
        body: Data,
        redacting secrets: [String]
    ) throws {
        guard let value = try? JSONSerialization.jsonObject(with: body),
              let object = value as? [String: Any],
              object["txid"] is String
        else {
            throw NetworkServiceError.malformedResponse
        }

        let parsedStatus: Int?
        if let value = object["status"], !(value is NSNull) {
            guard let status = strictARCInteger(value) else {
                throw NetworkServiceError.malformedResponse
            }
            parsedStatus = status
        } else {
            parsedStatus = nil
        }

        let parsedTxStatus: ARCStatus?
        if let value = object["txStatus"], !(value is NSNull) {
            guard let status = value as? String,
                  isValidARCStatusText(status)
            else {
                throw NetworkServiceError.malformedResponse
            }
            parsedTxStatus = ARCStatus(rawValue: status)
        } else {
            parsedTxStatus = nil
        }

        let wire: ARCWireResponse
        do {
            wire = try JSONDecoder().decode(ARCWireResponse.self, from: body)
        } catch {
            throw NetworkServiceError.malformedResponse
        }

        let parsedTransactionID: TransactionID
        do {
            parsedTransactionID = try TransactionID(displayHex: wire.txid)
        } catch {
            throw NetworkServiceError.malformedResponse
        }
        guard parsedTransactionID.displayHex == wire.txid else {
            throw NetworkServiceError.malformedResponse
        }

        blockHash = Self.cleanHexData(
            wire.blockHash,
            exactUTF8ByteCount: 64,
            maximumUTF8ByteCount: 64
        )
        blockHeight = strictARCUInt64(object["blockHeight"])
        extraInfo = Self.clean(wire.extraInfo, secrets: secrets, maximum: 1_024)
        status = parsedStatus
        timestamp = Self.parseTimestamp(wire.timestamp)
        title = Self.clean(wire.title, secrets: secrets, maximum: 1_024)
        txStatus = parsedTxStatus
        instance = Self.clean(wire.instance, secrets: secrets, maximum: 1_024)
        transactionID = parsedTransactionID
        detail = Self.clean(wire.detail, secrets: secrets, maximum: 1_024)
        merklePath = Self.cleanHexData(
            wire.merklePath,
            maximumUTF8ByteCount: 64 * 1_024
        )
    }

    private static func clean(
        _ value: String?,
        secrets: [String],
        maximum: Int
    ) -> String? {
        guard let value else { return nil }
        return sanitizedProviderText(
            value,
            redacting: secrets,
            maximumUTF8ByteCount: maximum
        )
    }

    private static func cleanHexData(
        _ value: String?,
        exactUTF8ByteCount: Int? = nil,
        maximumUTF8ByteCount: Int
    ) -> String? {
        guard let value else { return nil }
        let byteCount = value.utf8.count
        guard byteCount > 0,
              byteCount <= maximumUTF8ByteCount,
              byteCount.isMultiple(of: 2),
              exactUTF8ByteCount.map({ byteCount == $0 }) ?? true,
              value.unicodeScalars.allSatisfy({ scalar in
                (48...57).contains(scalar.value) || (97...102).contains(scalar.value)
              })
        else {
            return nil
        }
        return value
    }

    private static func parseTimestamp(_ value: String?) -> Date? {
        guard let value else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) {
            return date
        }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }
}

private func isValidARCStatusText(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 128 else { return false }
    return value.unicodeScalars.allSatisfy { scalar in
        (48...57).contains(scalar.value)
            || (65...90).contains(scalar.value)
            || scalar.value == 95
    }
}

private func strictARCInteger(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID()
    else {
        return nil
    }
    let type = String(cString: number.objCType)
    if ["C", "S", "I", "L", "Q"].contains(type) {
        return Int(exactly: number.uint64Value)
    }
    guard ["c", "s", "i", "l", "q"].contains(type) else { return nil }
    return Int(exactly: number.int64Value)
}

private func strictARCUInt64(_ value: Any?) -> UInt64? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID()
    else {
        return nil
    }
    let type = String(cString: number.objCType)
    if ["C", "S", "I", "L", "Q"].contains(type) {
        return number.uint64Value
    }
    guard ["c", "s", "i", "l", "q"].contains(type) else { return nil }
    let value = number.int64Value
    guard value >= 0 else { return nil }
    return UInt64(value)
}

private struct ARCWireResponse: Decodable {
    let blockHash: String?
    let extraInfo: String?
    let timestamp: String?
    let title: String?
    let instance: String?
    let txid: String
    let detail: String?
    let merklePath: String?

    private enum CodingKeys: String, CodingKey {
        case blockHash
        case blockHeight
        case extraInfo
        case timestamp
        case title
        case instance
        case txid
        case detail
        case merklePath
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        txid = try container.decode(String.self, forKey: .txid)

        blockHash = container.decodeLossy(String.self, forKey: .blockHash)
        extraInfo = container.decodeLossy(String.self, forKey: .extraInfo)
        timestamp = container.decodeLossy(String.self, forKey: .timestamp)
        title = container.decodeLossy(String.self, forKey: .title)
        instance = container.decodeLossy(String.self, forKey: .instance)
        detail = container.decodeLossy(String.self, forKey: .detail)
        merklePath = container.decodeLossy(String.self, forKey: .merklePath)
    }
}

private extension KeyedDecodingContainer {
    func decodeLossy<T: Decodable>(
        _ type: T.Type,
        forKey key: Key
    ) -> T? {
        try? decodeIfPresent(type, forKey: key)
    }
}
