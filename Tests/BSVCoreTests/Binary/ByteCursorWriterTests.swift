import BSVCore
import Testing

@Suite("ByteCursor and ByteWriter")
struct ByteCursorWriterTests {
    @Test("Cursor reads exact and reversed bytes and tracks its bounds")
    func exactAndReversedReads() throws {
        var cursor = ByteCursor([0, 1, 2, 3, 4])
        #expect(cursor.position == 0)
        #expect(cursor.remaining == 5)
        #expect(try cursor.read(count: 2) == [0, 1])
        #expect(cursor.position == 2)
        #expect(cursor.remaining == 3)
        #expect(try cursor.readReversed(count: 3) == [4, 3, 2])
        #expect(cursor.position == 5)
        #expect(cursor.remaining == 0)
        try cursor.requireFinished()
    }

    @Test("Invalid and truncated reads leave position unchanged")
    func failedReadsAreTransactional() throws {
        var cursor = ByteCursor([0xaa, 0xbb])
        #expect(throws: BinaryDecodingError.invalidCount(-1)) {
            try cursor.read(count: -1)
        }
        #expect(cursor.position == 0)
        #expect(throws: BinaryDecodingError.truncatedInput(expected: 3, remaining: 2)) {
            try cursor.read(count: 3)
        }
        #expect(cursor.position == 0)

        _ = try cursor.read(count: 1)
        #expect(throws: BinaryDecodingError.truncatedInput(expected: 2, remaining: 1)) {
            try cursor.readReversed(count: 2)
        }
        #expect(cursor.position == 1)
        #expect(cursor.remaining == 1)
    }

    @Test("Completion is explicit")
    func explicitCompletion() throws {
        var cursor = ByteCursor([1, 2, 3])
        _ = try cursor.read(count: 1)
        #expect(throws: BinaryDecodingError.trailingBytes(2)) {
            try cursor.requireFinished()
        }
        #expect(cursor.position == 1)
        _ = try cursor.read(count: 2)
        try cursor.requireFinished()
    }

    @Test("All integer readers use their explicit endian")
    func integerReaders() throws {
        var u16le = ByteCursor([0x34, 0x12])
        var u16be = ByteCursor([0x12, 0x34])
        var u32le = ByteCursor([0x78, 0x56, 0x34, 0x12])
        var u32be = ByteCursor([0x12, 0x34, 0x56, 0x78])
        var u64le = ByteCursor([0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01])
        var u64be = ByteCursor([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])

        #expect(try u16le.readUInt16LE() == 0x1234)
        #expect(try u16be.readUInt16BE() == 0x1234)
        #expect(try u32le.readUInt32LE() == 0x1234_5678)
        #expect(try u32be.readUInt32BE() == 0x1234_5678)
        #expect(try u64le.readUInt64LE() == 0x0123_4567_89ab_cdef)
        #expect(try u64be.readUInt64BE() == 0x0123_4567_89ab_cdef)
    }

    @Test("Truncated integer reads leave position unchanged")
    func truncatedIntegerReadsAreTransactional() {
        var cursor = ByteCursor([1, 2, 3, 4, 5, 6, 7])
        #expect(throws: BinaryDecodingError.truncatedInput(expected: 8, remaining: 7)) {
            try cursor.readUInt64LE()
        }
        #expect(cursor.position == 0)
        #expect(cursor.remaining == 7)
    }

    @Test("Writer emits exact, reversed, and endian-specific bytes")
    func writerImages() {
        var writer = ByteWriter()
        writer.write([0xaa])
        writer.writeReversed([1, 2, 3])
        writer.writeUInt16LE(0x1234)
        writer.writeUInt16BE(0x1234)
        writer.writeUInt32LE(0x1234_5678)
        writer.writeUInt32BE(0x1234_5678)
        writer.writeUInt64LE(0x0123_4567_89ab_cdef)
        writer.writeUInt64BE(0x0123_4567_89ab_cdef)

        #expect(writer.bytes == [
            0xaa,
            3, 2, 1,
            0x34, 0x12,
            0x12, 0x34,
            0x78, 0x56, 0x34, 0x12,
            0x12, 0x34, 0x56, 0x78,
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ])
    }

    @Test("Writer/parser integer round trips")
    func writerParserRoundTrips() throws {
        var writer = ByteWriter()
        writer.writeUInt16LE(.max)
        writer.writeUInt16BE(0x0102)
        writer.writeUInt32LE(.max)
        writer.writeUInt32BE(0x0102_0304)
        writer.writeUInt64LE(.max)
        writer.writeUInt64BE(0x0102_0304_0506_0708)

        var cursor = ByteCursor(writer.bytes)
        #expect(try cursor.readUInt16LE() == .max)
        #expect(try cursor.readUInt16BE() == 0x0102)
        #expect(try cursor.readUInt32LE() == .max)
        #expect(try cursor.readUInt32BE() == 0x0102_0304)
        #expect(try cursor.readUInt64LE() == .max)
        #expect(try cursor.readUInt64BE() == 0x0102_0304_0506_0708)
        try cursor.requireFinished()
    }
}
