import BSVCore
import BSVCrypto

/// A 32-byte block hash stored in Bitcoin wire order.
public struct BlockHash: Hashable, Sendable, CustomStringConvertible {
    private let storage: FixedByteStorage

    /// Creates a block hash from exactly 32 bytes in wire order.
    public init(wireBytes: [UInt8]) throws {
        storage = try FixedByteStorage(wireBytes, count: 32)
    }

    /// Creates a block hash from its 64-character human-display hexadecimal form.
    public init(displayHex: String) throws {
        guard displayHex.utf8.prefix(65).count == 64 else {
            throw TextEncodingError.invalidLength
        }
        let displayBytes = try Hex.decode(displayHex, maximumDecodedByteCount: 32)
        storage = try FixedByteStorage(Array(displayBytes.reversed()), count: 32)
    }

    package init(exactDigestBytesGuaranteed bytes: [UInt8]) {
        storage = FixedByteStorage(exactByteCountGuaranteed: bytes, count: 32)
    }

    /// The hash bytes in wire order.
    public var wireBytes: [UInt8] { storage.bytes }

    /// The hash bytes in human-display order.
    public var displayBytes: [UInt8] { Array(storage.bytes.reversed()) }

    /// The conventional lowercase block hash shown to users.
    public var displayHex: String { Hex.encode(displayBytes) }

    public var description: String { displayHex }
}

/// An 80-byte Bitcoin block header.
public struct BlockHeader: Hashable, Sendable, CustomStringConvertible {
    /// The exact serialized size of a block header.
    public static let byteCount = 80

    /// The signed block-version field.
    public let version: Int32
    /// The previous block identifier in wire order.
    public let previousBlockHash: BlockHash
    /// The Merkle root in wire order.
    public let merkleRoot: Hash256
    /// The Unix timestamp.
    public let timestamp: UInt32
    /// The compact proof-of-work target.
    public let bits: UInt32
    /// The proof-of-work nonce.
    public let nonce: UInt32

    /// Creates a block header from its fields.
    public init(
        version: Int32,
        previousBlockHash: BlockHash,
        merkleRoot: Hash256,
        timestamp: UInt32,
        bits: UInt32,
        nonce: UInt32
    ) {
        self.version = version
        self.previousBlockHash = previousBlockHash
        self.merkleRoot = merkleRoot
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
    }

    /// Parses exactly one 80-byte block header.
    public init(bytes: [UInt8]) throws {
        guard bytes.count == Self.byteCount else {
            throw FixedByteCountError.invalidByteCount(
                expected: Self.byteCount,
                actual: bytes.count
            )
        }

        var cursor = ByteCursor(bytes)
        version = Int32(bitPattern: try cursor.readUInt32LE())
        previousBlockHash = try BlockHash(wireBytes: cursor.read(count: 32))
        merkleRoot = try Hash256(cursor.read(count: 32))
        timestamp = try cursor.readUInt32LE()
        bits = try cursor.readUInt32LE()
        nonce = try cursor.readUInt32LE()
        try cursor.requireFinished()
    }

    /// Parses an 80-byte block header from hexadecimal text.
    public init(hex: String) throws {
        try self.init(bytes: Hex.decode(hex, maximumDecodedByteCount: Self.byteCount))
    }

    /// The canonical 80-byte wire encoding.
    public var serializedBytes: [UInt8] {
        var writer = ByteWriter(capacity: Self.byteCount)
        writer.writeUInt32LE(UInt32(bitPattern: version))
        writer.write(previousBlockHash.wireBytes)
        writer.write(merkleRoot.bytes)
        writer.writeUInt32LE(timestamp)
        writer.writeUInt32LE(bits)
        writer.writeUInt32LE(nonce)
        return writer.bytes
    }

    /// The canonical lowercase hexadecimal wire encoding.
    public var hex: String {
        Hex.encode(serializedBytes)
    }

    /// The double-SHA-256 block identifier.
    public var hash: BlockHash {
        BlockHash(
            exactDigestBytesGuaranteed: BSVHashing.sha256d(serializedBytes).bytes
        )
    }

    /// A compact diagnostic that does not include the Merkle root.
    public var description: String {
        "BlockHeader(hash: \(hash.displayHex), previousBlockHash: \(previousBlockHash.displayHex), bits: \(bits))"
    }
}
