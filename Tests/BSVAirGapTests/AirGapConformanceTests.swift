import BSVAirGap
import BSVCore
import BSVCrypto
import Foundation
import Testing

@Suite("BRC-141 air-gap conformance", .serialized)
struct AirGapConformanceTests {
    @Test("complete official append-only corpus")
    func officialCorpus() throws {
        let vectors = try loadVectors()
        #expect(vectors.count == 31)

        var operations: Set<String> = []
        for vector in vectors {
            let id = try requiredString(vector, "id")
            let input = try requiredObject(vector, "input")
            let expected = try requiredObject(vector, "expected")
            let operation = try requiredString(input, "operation")
            operations.insert(operation)

            switch operation {
            case "crc32":
                let message = try hexBytes(requiredString(input, "message_hex"))
                let expectedHex = try requiredString(expected, "crc32_hex")
                #expect(String(format: "%08x", crc32(message)) == expectedHex, Comment(rawValue: id))

            case "part-char-length":
                let blockBytes = try requiredInt(input, "block_bytes")
                let expectedChars = try requiredInt(expected, "chars")
                #expect(
                    try estimatePartCharLength(blockBytes) == expectedChars,
                    Comment(rawValue: id)
                )

            case "encode-part":
                let encoder = try AirGapEncoder(
                    hexBytes(requiredString(input, "message_hex")),
                    blockBytes: requiredInt(input, "block_bytes"),
                    sessionID: hexBytes(requiredString(input, "session_id_hex"))
                )
                let sequence = try requiredUInt32(input, "seq")
                let expectedPart = try requiredString(expected, "part")
                #expect(
                    encoder.part(at: sequence) == expectedPart,
                    Comment(rawValue: id)
                )

            case "decode":
                var decoder = AirGapDecoder()
                var done = false
                for part in try requiredStrings(input, "parts") {
                    done = decoder.accept(part).done || done
                }
                #expect(done, Comment(rawValue: id))
                let message = decoder.message()
                let expectedMessage = try requiredString(expected, "message_hex")
                #expect(message != nil, Comment(rawValue: id))
                #expect(
                    message.map(hexString) == expectedMessage,
                    Comment(rawValue: id)
                )

            case "progress":
                var decoder = AirGapDecoder()
                var progress = decoder.accept("")
                for part in try requiredStrings(input, "parts") {
                    progress = decoder.accept(part)
                }
                let expectedHave = try requiredInt(expected, "have")
                let expectedTotal = try requiredInt(expected, "total")
                let expectedDone = try requiredBool(expected, "done")
                #expect(progress.have == expectedHave, Comment(rawValue: id))
                #expect(progress.total == expectedTotal, Comment(rawValue: id))
                #expect(progress.done == expectedDone, Comment(rawValue: id))

            case "accept-one":
                var decoder = AirGapDecoder()
                let progress = decoder.accept(try requiredString(input, "text"))
                let expectedOK = try requiredBool(expected, "ok")
                #expect(progress.ok == expectedOK, Comment(rawValue: id))
                #expect(decoder.message() == nil, Comment(rawValue: id))

            default:
                Issue.record("Unsupported corpus operation \(operation) in \(id)")
            }
        }

        #expect(operations == [
            "accept-one", "crc32", "decode", "encode-part", "part-char-length", "progress",
        ])
    }

    @Test("frozen sequence-to-block mapping")
    func frozenMapping() {
        #expect(airGapBlocksForPart(3, blockCount: 3) == [2, 1])
        #expect(airGapBlocksForPart(4, blockCount: 3) == [0])
        #expect(airGapBlocksForPart(5, blockCount: 5) == [1, 3])
        #expect(airGapBlocksForPart(3_393_264, blockCount: 5) == [2, 4])
        #expect(airGapBlocksForPart(3_393_265, blockCount: 5) == [2, 0])
        #expect(airGapBlocksForPart(0x7fff_ffff, blockCount: 5) == [3, 0])
        #expect(airGapBlocksForPart(0xffff_ffff, blockCount: 5) == [1, 0, 3, 2])
        #expect(airGapBlocksForPart(0, blockCount: 4) == [2, 0, 1, 3])
    }

    @Test("encoder bounds and random session validation")
    func encoderBounds() throws {
        #expect(throws: AirGapError.emptyMessage) {
            try AirGapEncoder([])
        }
        #expect(throws: AirGapError.messageTooLarge(actual: 65_537, maximum: 65_536)) {
            try AirGapEncoder([UInt8](repeating: 0, count: 65_537))
        }
        for invalid in [0, 2_049] {
            #expect(throws: AirGapError.invalidBlockByteCount(invalid)) {
                try AirGapEncoder([1], blockBytes: invalid)
            }
        }
        #expect(throws: AirGapError.tooManyBlocks(actual: 65_536, maximum: 65_535)) {
            try AirGapEncoder([UInt8](repeating: 0, count: 65_536), blockBytes: 1)
        }
        #expect(throws: AirGapError.invalidSessionIDByteCount(7)) {
            try AirGapEncoder([1], sessionID: [UInt8](repeating: 0, count: 7))
        }
        #expect(throws: AirGapError.randomGenerationFailed) {
            try AirGapEncoder([1], randomSource: ShortRandomSource())
        }

        let encoder = try AirGapEncoder([1], randomSource: FixedRandomSource())
        #expect(encoder.sessionID == Array(0..<8))
    }

    @Test("final CRC mismatch resets without emitting bytes")
    func crcMismatchResets() throws {
        let encoder = try AirGapEncoder(
            Array("Hello".utf8),
            blockBytes: 8,
            sessionID: Array(1...8)
        )
        let part = encoder.part(at: 0)
        let body = String(part.dropFirst(AirGap.prefix.count))
        var decoded = try Base64Encoding.decode(
            body,
            alphabet: .urlSafe,
            padding: .omitted,
            maximumDecodedByteCount: 31
        )
        decoded[23] ^= 1
        let corrupted = AirGap.prefix + Base64Encoding.encode(
            decoded,
            alphabet: .urlSafe,
            padding: .omitted
        )

        var decoder = AirGapDecoder()
        #expect(decoder.accept(corrupted).done)
        #expect(decoder.message() == nil)
        let afterReset = decoder.accept("")
        #expect(afterReset.total == 0)
        #expect(afterReset.have == 0)
    }

    @Test("later body-length mismatch is rejected without corrupting the session")
    func bodyLengthMismatchDoesNotCorruptSession() throws {
        let message = Array("123456789".utf8)
        let sessionID = Array(UInt8(1)...UInt8(8))
        let fourByteBlocks = try AirGapEncoder(
            message,
            blockBytes: 4,
            sessionID: sessionID
        )
        let threeByteBlocks = try AirGapEncoder(
            message,
            blockBytes: 3,
            sessionID: sessionID
        )
        #expect(fourByteBlocks.blockCount == threeByteBlocks.blockCount)

        var decoder = AirGapDecoder()
        let initial = decoder.accept(fourByteBlocks.part(at: 0))
        #expect(initial.ok)
        #expect(initial.have == 1)

        let mismatch = decoder.accept(threeByteBlocks.part(at: 1))
        #expect(!mismatch.ok)
        #expect(mismatch.have == 1)
        #expect(mismatch.total == fourByteBlocks.blockCount)

        for sequence in 1..<fourByteBlocks.blockCount {
            _ = decoder.accept(fourByteBlocks.part(at: UInt32(sequence)))
        }
        #expect(decoder.message() == message)
    }

    @Test("pending-part limit rejects overflow without starving systematic recovery")
    func pendingPartLimitDoesNotStarveRecovery() throws {
        let message = Array(0..<UInt8(8))
        let encoder = try AirGapEncoder(
            message,
            blockBytes: 1,
            sessionID: Array(1...8)
        )
        let sequences = sequencesWithDegree(
            2,
            blockCount: encoder.blockCount,
            count: AirGap.maximumPendingParts + 1
        )

        var decoder = AirGapDecoder()
        for sequence in sequences.dropLast() {
            let progress = decoder.accept(encoder.part(at: sequence))
            #expect(progress.ok)
            #expect(progress.have == 0)
        }
        let overflowSequence = try #require(sequences.last)
        let overflow = decoder.accept(encoder.part(at: overflowSequence))
        #expect(!overflow.ok)
        #expect(overflow.have == 0)

        for sequence in 0..<encoder.blockCount {
            _ = decoder.accept(encoder.part(at: UInt32(sequence)))
        }
        #expect(decoder.message() == message)
    }

    @Test("pending-reference limit rejects overflow without starving systematic recovery")
    func pendingReferenceLimitDoesNotStarveRecovery() throws {
        let message = Array(0..<UInt8(16))
        let encoder = try AirGapEncoder(
            message,
            blockBytes: 1,
            sessionID: Array(1...8)
        )
        let degree = 5
        let acceptedPartCount = AirGap.maximumPendingIndices / degree
        let acceptedSequences = sequencesWithDegree(
            degree,
            blockCount: encoder.blockCount,
            count: acceptedPartCount
        )
        let lastAcceptedSequence = try #require(acceptedSequences.last)
        let overflowSequence = try #require(
            sequencesWithDegree(
                2,
                blockCount: encoder.blockCount,
                count: 1,
                startingAt: lastAcceptedSequence + 1
            ).first
        )

        var decoder = AirGapDecoder()
        for sequence in acceptedSequences {
            let progress = decoder.accept(encoder.part(at: sequence))
            #expect(progress.ok)
            #expect(progress.have == 0)
        }
        let overflow = decoder.accept(encoder.part(at: overflowSequence))
        #expect(!overflow.ok)
        #expect(overflow.have == 0)

        for sequence in 0..<encoder.blockCount {
            _ = decoder.accept(encoder.part(at: UInt32(sequence)))
        }
        #expect(decoder.message() == message)
    }

    @Test("sequence tracking stops at its cap without starving systematic recovery")
    func sequenceTrackingCapDoesNotStarveRecovery() throws {
        let message = [UInt8](repeating: 0x5a, count: AirGap.maximumBlockCount)
        let encoder = try AirGapEncoder(
            message,
            blockBytes: 1,
            sessionID: Array(1...8)
        )
        var decoder = AirGapDecoder()

        for sequence in 0..<(encoder.blockCount - 1) {
            let progress = decoder.accept(encoder.part(at: UInt32(sequence)))
            #expect(progress.ok)
        }
        #expect(mirroredCollectionCount(decoder, label: "seen") == encoder.blockCount - 1)

        let missingIndex = encoder.blockCount - 1
        let redundantSequences = sequencesExcludingIndex(
            missingIndex,
            blockCount: encoder.blockCount,
            count: 3
        )
        for sequence in redundantSequences {
            let progress = decoder.accept(encoder.part(at: sequence))
            #expect(progress.ok)
            #expect(progress.have == missingIndex)
        }
        #expect(mirroredCollectionCount(decoder, label: "seen") == AirGap.maximumTrackedSequences)

        let complete = decoder.accept(encoder.part(at: UInt32(missingIndex)))
        #expect(complete.ok)
        #expect(complete.done)
        #expect(decoder.message() == message)
    }
}

private func sequencesWithDegree(
    _ degree: Int,
    blockCount: Int,
    count: Int,
    startingAt: UInt32? = nil
) -> [UInt32] {
    var sequence = startingAt ?? UInt32(blockCount)
    var result: [UInt32] = []
    result.reserveCapacity(count)
    while result.count < count {
        if airGapBlocksForPart(sequence, blockCount: blockCount).count == degree {
            result.append(sequence)
        }
        sequence += 1
    }
    return result
}

private func sequencesExcludingIndex(
    _ excludedIndex: Int,
    blockCount: Int,
    count: Int
) -> [UInt32] {
    var sequence = UInt32(blockCount)
    var result: [UInt32] = []
    result.reserveCapacity(count)
    while result.count < count {
        let indices = airGapBlocksForPart(sequence, blockCount: blockCount)
        if !indices.contains(excludedIndex) {
            result.append(sequence)
        }
        sequence += 1
    }
    return result
}

private func mirroredCollectionCount<Value>(_ value: Value, label: String) -> Int? {
    guard let child = Mirror(reflecting: value).children.first(where: { $0.label == label }) else {
        return nil
    }
    return Mirror(reflecting: child.value).children.count
}

private struct FixedRandomSource: SecureRandomSource {
    func randomBytes(count: Int) throws -> [UInt8] {
        Array(0..<UInt8(count))
    }
}

private struct ShortRandomSource: SecureRandomSource {
    func randomBytes(count: Int) throws -> [UInt8] {
        [UInt8](repeating: 0, count: max(0, count - 1))
    }
}

private enum FixtureError: Error {
    case missingFixture
    case wrongShape(String)
    case invalidHex(String)
}

private typealias JSONObject = [String: Any]

private func loadVectors() throws -> [JSONObject] {
    guard let fixtureRoot = Bundle.module.url(forResource: "Fixtures", withExtension: nil) else {
        throw FixtureError.missingFixture
    }
    let data = try Data(contentsOf: fixtureRoot.appendingPathComponent("air-gap-optical.json"))
    guard let root = try JSONSerialization.jsonObject(with: data) as? JSONObject,
          let vectors = root["vectors"] as? [JSONObject] else {
        throw FixtureError.wrongShape("vectors")
    }
    return vectors
}

private func requiredObject(_ object: JSONObject, _ key: String) throws -> JSONObject {
    guard let value = object[key] as? JSONObject else { throw FixtureError.wrongShape(key) }
    return value
}

private func requiredString(_ object: JSONObject, _ key: String) throws -> String {
    guard let value = object[key] as? String else { throw FixtureError.wrongShape(key) }
    return value
}

private func requiredStrings(_ object: JSONObject, _ key: String) throws -> [String] {
    guard let value = object[key] as? [String] else { throw FixtureError.wrongShape(key) }
    return value
}

private func requiredInt(_ object: JSONObject, _ key: String) throws -> Int {
    guard let value = object[key] as? NSNumber else { throw FixtureError.wrongShape(key) }
    return value.intValue
}

private func requiredUInt32(_ object: JSONObject, _ key: String) throws -> UInt32 {
    guard let value = object[key] as? NSNumber,
          value.uint64Value <= UInt64(UInt32.max) else {
        throw FixtureError.wrongShape(key)
    }
    return UInt32(value.uint64Value)
}

private func requiredBool(_ object: JSONObject, _ key: String) throws -> Bool {
    guard let value = object[key] as? Bool else { throw FixtureError.wrongShape(key) }
    return value
}

private func hexBytes(_ text: String) throws -> [UInt8] {
    guard text.utf8.count.isMultiple(of: 2) else { throw FixtureError.invalidHex(text) }
    var result: [UInt8] = []
    result.reserveCapacity(text.utf8.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let end = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<end], radix: 16) else {
            throw FixtureError.invalidHex(text)
        }
        result.append(byte)
        index = end
    }
    return result
}

private func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}
