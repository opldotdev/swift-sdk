import BSVCore
import Testing

@Suite("Fixed-width values")
struct FixedBytesTests {
    @Test("Exact-width constructors accept only their declared sizes")
    func exactWidths() throws {
        #expect(try Hash160(Array(repeating: 0x01, count: 20)).bytes.count == 20)
        #expect(try Hash256(Array(repeating: 0x02, count: 32)).bytes.count == 32)
        #expect(try Hash512(Array(repeating: 0x03, count: 64)).bytes.count == 64)

        #expect(throws: FixedByteCountError.invalidByteCount(expected: 20, actual: 19)) {
            try Hash160(Array(repeating: 0, count: 19))
        }
        #expect(throws: FixedByteCountError.invalidByteCount(expected: 32, actual: 33)) {
            try Hash256(Array(repeating: 0, count: 33))
        }
        #expect(throws: FixedByteCountError.invalidByteCount(expected: 64, actual: 0)) {
            try Hash512([])
        }
    }

    @Test("Stored and returned bytes have value semantics")
    func safeByteCopies() throws {
        var input = Array(repeating: UInt8(0x11), count: 20)
        let hash = try Hash160(input)
        input[0] = 0x22
        #expect(hash.bytes[0] == 0x11)

        var returned = hash.bytes
        returned[1] = 0x33
        #expect(hash.bytes[1] == 0x11)
    }

    @Test("Equality and hashing include every byte")
    func hashAndEquality() throws {
        let first = try Hash256(Array(repeating: 0, count: 32))
        let same = try Hash256(Array(repeating: 0, count: 32))
        var changedBytes = Array(repeating: UInt8(0), count: 32)
        changedBytes[31] = 1
        let changed = try Hash256(changedBytes)

        #expect(first == same)
        #expect(first != changed)
        #expect(Set([first, same, changed]).count == 2)
    }

    @Test("TransactionID preserves wire order and reverses display order")
    func transactionIDOrder() throws {
        let wire = Array(UInt8(0)..<UInt8(32))
        let transactionID = try TransactionID(wireBytes: wire)
        #expect(transactionID.wireBytes == wire)
        #expect(transactionID.displayBytes == Array(wire.reversed()))
        #expect(transactionID == (try TransactionID(wireBytes: wire)))
        #expect(Set([transactionID, try TransactionID(wireBytes: wire)]).count == 1)
    }

    @Test("TransactionID enforces 32 bytes")
    func transactionIDWidth() {
        #expect(throws: FixedByteCountError.invalidByteCount(expected: 32, actual: 31)) {
            try TransactionID(wireBytes: Array(repeating: 0, count: 31))
        }
    }
}
