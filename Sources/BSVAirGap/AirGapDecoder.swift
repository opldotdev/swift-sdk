import BSVCore

/// Result of feeding one scanned string to ``AirGapDecoder``.
public struct AirGapProgress: Equatable, Sendable {
    /// Whether this read was usable for the current message or a known duplicate.
    public let ok: Bool

    /// Whether every source block has been recovered.
    public let done: Bool

    /// Number of recovered source blocks.
    public let have: Int

    /// Number of source blocks in the locked session, or zero before the first part.
    public let total: Int

    public init(ok: Bool, done: Bool, have: Int, total: Int) {
        self.ok = ok
        self.done = done
        self.have = have
        self.total = total
    }
}

/// Stateful, bounded BRC-141 reassembly for a stream of camera scans.
///
/// ``accept(_:)`` never throws. It soft-rejects malformed, foreign, and resource-exhausting input,
/// and ``message()`` never emits partial bytes or bytes that fail the complete-payload CRC.
public struct AirGapDecoder: Sendable {
    private var identity: SessionIdentity?
    private var blockBytes = 0
    private var seen: Set<UInt32> = []
    private var solved: [[UInt8]?] = []
    private var solvedCount = 0
    private var pending: [PendingPart] = []
    private var pendingIndexCount = 0
    private var candidateIdentity: SessionIdentity?
    private var candidateCount = 0

    public init() {}

    /// Forgets the current and candidate sessions.
    public mutating func reset() {
        startSession(nil)
    }

    /// Feeds one scanned string and returns current progress without throwing.
    public mutating func accept(_ text: String) -> AirGapProgress {
        guard let part = parse(text) else { return progress(ok: false) }
        guard enterSession(part) else { return progress(ok: false) }

        if isDone { return progress(ok: true) }

        if blockBytes == 0 {
            blockBytes = part.payload.count
        } else if part.payload.count != blockBytes {
            return progress(ok: false)
        }

        if seen.contains(part.sequence) { return progress(ok: true) }
        return ingest(part)
    }

    /// Returns the complete verified message, or `nil` while incomplete or after a CRC failure.
    ///
    /// A CRC failure resets the decoder so a still-looping sender can refill it.
    public mutating func message() -> [UInt8]? {
        guard let identity, isDone, blockBytes > 0 else { return nil }
        var result: [UInt8] = []
        result.reserveCapacity(identity.total * blockBytes)
        for block in solved {
            guard let block else { return nil }
            result.append(contentsOf: block)
        }
        result.removeLast(result.count - identity.messageLength)
        guard crc32(result) == identity.checksum else {
            reset()
            return nil
        }
        return result
    }

    private var isDone: Bool {
        guard let identity else { return false }
        return identity.total > 0 && solvedCount == identity.total
    }

    private func progress(ok: Bool) -> AirGapProgress {
        AirGapProgress(
            ok: ok,
            done: isDone,
            have: solvedCount,
            total: identity?.total ?? 0
        )
    }

    private mutating func startSession(_ newIdentity: SessionIdentity?) {
        identity = newIdentity
        blockBytes = 0
        seen = []
        solved = [Array<UInt8>?](
            repeating: nil,
            count: newIdentity?.total ?? 0
        )
        solvedCount = 0
        pending = []
        pendingIndexCount = 0
        candidateIdentity = nil
        candidateCount = 0
    }

    private func parse(_ text: String) -> ParsedPart? {
        guard text.hasPrefix(AirGap.prefix) else { return nil }
        guard text.utf8.count <= airGapPartCharLength(AirGap.maximumBlockBytes) else {
            return nil
        }

        let encoded = String(text.dropFirst(AirGap.prefix.count))
        let bytes: [UInt8]
        do {
            bytes = try Base64Encoding.decode(
                encoded,
                alphabet: .urlSafe,
                padding: .omitted,
                maximumDecodedByteCount: AirGap.headerByteCount + AirGap.maximumBlockBytes
            )
        } catch {
            return nil
        }
        guard bytes.count > AirGap.headerByteCount else { return nil }

        var cursor = ByteCursor(bytes)
        guard let version = try? cursor.read(count: 1).first,
              version == AirGap.wireVersion,
              let sessionID = try? cursor.read(count: AirGap.sessionIDByteCount),
              let sequence = try? cursor.readUInt32BE(),
              let rawTotal = try? cursor.readUInt16BE(),
              let rawMessageLength = try? cursor.readUInt32BE(),
              let checksum = try? cursor.readUInt32BE(),
              let payload = try? cursor.read(count: cursor.remaining) else {
            return nil
        }

        let total = Int(rawTotal)
        let messageLength = Int(rawMessageLength)
        guard total > 0,
              messageLength > 0,
              messageLength <= AirGap.maximumMessageBytes,
              !payload.isEmpty,
              payload.count <= AirGap.maximumBlockBytes,
              (messageLength + payload.count - 1) / payload.count == total else {
            return nil
        }

        return ParsedPart(
            identity: SessionIdentity(
                sessionID: sessionID,
                total: total,
                messageLength: messageLength,
                checksum: checksum
            ),
            sequence: sequence,
            payload: payload
        )
    }

    private mutating func enterSession(_ part: ParsedPart) -> Bool {
        guard let identity else {
            startSession(part.identity)
            return true
        }
        if part.identity == identity {
            candidateIdentity = nil
            candidateCount = 0
            return true
        }

        if part.identity == candidateIdentity {
            candidateCount += 1
        } else {
            candidateIdentity = part.identity
            candidateCount = 1
        }
        guard candidateCount >= AirGap.sessionSwitchPartCount else { return false }
        startSession(part.identity)
        return true
    }

    private mutating func ingest(_ part: ParsedPart) -> AirGapProgress {
        guard let identity else { return progress(ok: false) }
        let rawIndices = part.sequence < UInt32(identity.total)
            ? [Int(part.sequence)]
            : airGapBlocksForPart(part.sequence, blockCount: identity.total)
        var candidate = PendingPart(indices: Set(rawIndices), payload: part.payload)
        reduce(&candidate)

        if candidate.indices.count > 1 {
            guard pending.count < AirGap.maximumPendingParts,
                  pendingIndexCount + candidate.indices.count <= AirGap.maximumPendingIndices else {
                return progress(ok: false)
            }
            pending.append(candidate)
            pendingIndexCount += candidate.indices.count
        } else if candidate.indices.count == 1 {
            solve(candidate)
            cascade()
        }

        if seen.count < AirGap.maximumTrackedSequences {
            seen.insert(part.sequence)
        }
        return progress(ok: true)
    }

    private mutating func cascade() {
        var progressed = true
        while progressed {
            progressed = false
            var stillPending: [PendingPart] = []
            var stillPendingIndexCount = 0
            for var part in pending {
                reduce(&part)
                if part.indices.count == 1 {
                    solve(part)
                    progressed = true
                } else if part.indices.count > 1 {
                    stillPending.append(part)
                    stillPendingIndexCount += part.indices.count
                }
            }
            pending = stillPending
            pendingIndexCount = stillPendingIndexCount
        }
    }

    private func reduce(_ part: inout PendingPart) {
        for index in Array(part.indices) {
            if let known = solved[index] {
                airGapXOR(known, into: &part.payload)
                part.indices.remove(index)
            }
        }
    }

    private mutating func solve(_ part: PendingPart) {
        guard let index = part.indices.first else { return }
        solved[index] = part.payload
        solvedCount += 1
    }
}

private struct SessionIdentity: Equatable, Sendable {
    let sessionID: [UInt8]
    let total: Int
    let messageLength: Int
    let checksum: UInt32
}

private struct ParsedPart: Sendable {
    let identity: SessionIdentity
    let sequence: UInt32
    let payload: [UInt8]
}

private struct PendingPart: Sendable {
    var indices: Set<Int>
    var payload: [UInt8]
}
