import BSVCore

/// A reference to one output of an earlier transaction.
public struct Outpoint: Hashable, Sendable, CustomStringConvertible {
    public let transactionID: TransactionID
    public let outputIndex: UInt32

    public init(transactionID: TransactionID, outputIndex: UInt32) {
        self.transactionID = transactionID
        self.outputIndex = outputIndex
    }

    /// Creates an outpoint from its exact 36-byte transaction-wire encoding.
    public init(wireBytes: [UInt8]) throws {
        guard wireBytes.count == 36 else {
            throw FixedByteCountError.invalidByteCount(expected: 36, actual: wireBytes.count)
        }
        self.transactionID = try TransactionID(wireBytes: Array(wireBytes[0..<32]))
        self.outputIndex = UInt32(wireBytes[32])
            | (UInt32(wireBytes[33]) << 8)
            | (UInt32(wireBytes[34]) << 16)
            | (UInt32(wireBytes[35]) << 24)
    }

    /// Parses `txid.index`, requiring one decimal UInt32 output index.
    public init(_ text: String) throws {
        self = try Self.parse(text, separator: 0x2e)
    }

    /// Parses the ordinal-style `txid_index` representation.
    public init(ordinal text: String) throws {
        self = try Self.parse(text, separator: 0x5f)
    }

    public var wireBytes: [UInt8] {
        transactionID.wireBytes + [
            UInt8(truncatingIfNeeded: outputIndex),
            UInt8(truncatingIfNeeded: outputIndex >> 8),
            UInt8(truncatingIfNeeded: outputIndex >> 16),
            UInt8(truncatingIfNeeded: outputIndex >> 24),
        ]
    }

    public var description: String {
        "\(transactionID.displayHex).\(outputIndex)"
    }

    public var ordinalDescription: String {
        "\(transactionID.displayHex)_\(outputIndex)"
    }

    private static func parse(_ text: String, separator: UInt8) throws -> Outpoint {
        // A valid form is 64 hex bytes, one separator, and at most ten
        // decimal UInt32 digits. Bound inspection before copying hostile text.
        let utf8 = Array(text.utf8.prefix(76))
        guard utf8.count >= 66, utf8[64] == separator else {
            throw OutpointError.invalidFormat
        }
        guard utf8.count <= 75 else {
            throw OutpointError.invalidOutputIndex
        }
        let transactionText = String(decoding: utf8[0..<64], as: UTF8.self)
        let indexBytes = utf8[65...]
        guard !indexBytes.isEmpty,
              indexBytes.allSatisfy({ (0x30...0x39).contains($0) }),
              let index = UInt32(String(decoding: indexBytes, as: UTF8.self)) else {
            throw OutpointError.invalidOutputIndex
        }
        do {
            return Outpoint(
                transactionID: try TransactionID(displayHex: transactionText),
                outputIndex: index
            )
        } catch let error as TextEncodingError {
            throw OutpointError.invalidTransactionID(error)
        } catch {
            throw OutpointError.invalidTransactionIDLength
        }
    }
}

public enum OutpointError: Error, Equatable, Sendable {
    case invalidFormat
    case invalidTransactionID(TextEncodingError)
    case invalidTransactionIDLength
    case invalidOutputIndex
}
