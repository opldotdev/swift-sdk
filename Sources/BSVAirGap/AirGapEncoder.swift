import BSVCore
import BSVCrypto

/// An immutable BRC-141 encoder for one arbitrary byte payload.
public struct AirGapEncoder: Sendable {
    private let blocks: [[UInt8]]
    private let checksum: UInt32

    /// Number of source blocks, `ceil(messageLength / blockBytes)`.
    public let blockCount: Int

    /// Bytes in every source block and encoded part body.
    public let blockBytes: Int

    /// Original unpadded message length.
    public let messageLength: Int

    /// Eight-byte identity carried by every part in this stream.
    public let sessionID: [UInt8]

    /// Creates an encoder. The message and optional session identity are copied.
    public init(
        _ message: [UInt8],
        blockBytes: Int = AirGap.defaultBlockBytes,
        sessionID: [UInt8]? = nil,
        randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) throws {
        guard !message.isEmpty else { throw AirGapError.emptyMessage }
        guard message.count <= AirGap.maximumMessageBytes else {
            throw AirGapError.messageTooLarge(
                actual: message.count,
                maximum: AirGap.maximumMessageBytes
            )
        }
        guard (1...AirGap.maximumBlockBytes).contains(blockBytes) else {
            throw AirGapError.invalidBlockByteCount(blockBytes)
        }

        let blockCount = (message.count + blockBytes - 1) / blockBytes
        guard blockCount <= AirGap.maximumBlockCount else {
            throw AirGapError.tooManyBlocks(
                actual: blockCount,
                maximum: AirGap.maximumBlockCount
            )
        }

        let chosenSessionID: [UInt8]
        if let sessionID {
            guard sessionID.count == AirGap.sessionIDByteCount else {
                throw AirGapError.invalidSessionIDByteCount(sessionID.count)
            }
            chosenSessionID = sessionID
        } else {
            do {
                chosenSessionID = try randomSource.randomBytes(count: AirGap.sessionIDByteCount)
            } catch {
                throw AirGapError.randomGenerationFailed
            }
            guard chosenSessionID.count == AirGap.sessionIDByteCount else {
                throw AirGapError.randomGenerationFailed
            }
        }

        var padded = [UInt8](repeating: 0, count: blockCount * blockBytes)
        padded.replaceSubrange(0..<message.count, with: message)
        self.blocks = (0..<blockCount).map { index in
            let start = index * blockBytes
            return Array(padded[start..<(start + blockBytes)])
        }
        self.checksum = crc32(message)
        self.blockCount = blockCount
        self.blockBytes = blockBytes
        self.messageLength = message.count
        self.sessionID = chosenSessionID
    }

    /// Returns one canonical BRC-141 part for `sequence`.
    ///
    /// Values below ``blockCount`` are the systematic source blocks. Later values are
    /// deterministic fountain mixtures. The caller owns animation cadence and sequence looping.
    public func part(at sequence: UInt32) -> String {
        var payload = [UInt8](repeating: 0, count: blockBytes)
        if sequence < UInt32(blockCount) {
            payload = blocks[Int(sequence)]
        } else {
            for index in airGapBlocksForPart(sequence, blockCount: blockCount) {
                airGapXOR(blocks[index], into: &payload)
            }
        }

        var writer = ByteWriter(capacity: AirGap.headerByteCount + blockBytes)
        writer.write([AirGap.wireVersion])
        writer.write(sessionID)
        writer.writeUInt32BE(sequence)
        writer.writeUInt16BE(UInt16(blockCount))
        writer.writeUInt32BE(UInt32(messageLength))
        writer.writeUInt32BE(checksum)
        writer.write(payload)
        let body = Base64Encoding.encode(
            writer.bytes,
            alphabet: .urlSafe,
            padding: .omitted
        )
        return AirGap.prefix + body
    }
}
