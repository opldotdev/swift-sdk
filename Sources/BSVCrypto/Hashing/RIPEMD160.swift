struct RIPEMD160 {
    private static let leftWordOrder = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]

    private static let rightWordOrder = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]

    private static let leftRotation = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]

    private static let rightRotation = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]

    private var state: [UInt32] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ]
    private var buffered: [UInt8] = []
    private var byteCount: UInt64 = 0

    static func digest(_ bytes: [UInt8]) -> [UInt8] {
        var hasher = RIPEMD160()
        hasher.update(bytes)
        return hasher.finalize()
    }

    private mutating func update(_ bytes: [UInt8]) {
        byteCount = byteCount &+ UInt64(bytes.count)
        var offset = 0

        if !buffered.isEmpty {
            let appendedCount = min(64 - buffered.count, bytes.count)
            buffered.append(contentsOf: bytes.prefix(appendedCount))
            offset = appendedCount
            if buffered.count == 64 {
                compress(buffered)
                buffered.removeAll(keepingCapacity: true)
            }
        }

        while bytes.count - offset >= 64 {
            let end = offset + 64
            compress(Array(bytes[offset..<end]))
            offset = end
        }

        if offset < bytes.count {
            buffered.append(contentsOf: bytes[offset...])
        }
    }

    private mutating func finalize() -> [UInt8] {
        let bitCount = byteCount &* 8
        var tail = buffered
        tail.append(0x80)
        while tail.count % 64 != 56 {
            tail.append(0)
        }
        for shift in stride(from: 0, to: 64, by: 8) {
            tail.append(UInt8(truncatingIfNeeded: bitCount >> shift))
        }
        var offset = 0
        while offset < tail.count {
            let end = offset + 64
            compress(Array(tail[offset..<end]))
            offset = end
        }

        var digest: [UInt8] = []
        digest.reserveCapacity(20)
        for word in state {
            digest.append(UInt8(truncatingIfNeeded: word))
            digest.append(UInt8(truncatingIfNeeded: word >> 8))
            digest.append(UInt8(truncatingIfNeeded: word >> 16))
            digest.append(UInt8(truncatingIfNeeded: word >> 24))
        }
        return digest
    }

    private mutating func compress(_ block: [UInt8]) {
        precondition(block.count == 64, "RIPEMD-160 compression requires one block")
        var words: [UInt32] = []
        words.reserveCapacity(16)
        for offset in stride(from: 0, to: 64, by: 4) {
            let word = UInt32(block[offset])
                | (UInt32(block[offset + 1]) << 8)
                | (UInt32(block[offset + 2]) << 16)
                | (UInt32(block[offset + 3]) << 24)
            words.append(word)
        }

        var leftA = state[0]
        var leftB = state[1]
        var leftC = state[2]
        var leftD = state[3]
        var leftE = state[4]
        var rightA = leftA
        var rightB = leftB
        var rightC = leftC
        var rightD = leftD
        var rightE = leftE

        for round in 0..<80 {
            let left = rotateLeft(
                leftA &+ leftFunction(round, leftB, leftC, leftD)
                    &+ words[Self.leftWordOrder[round]]
                    &+ leftConstant(round),
                by: Self.leftRotation[round]
            ) &+ leftE
            leftA = leftE
            leftE = leftD
            leftD = rotateLeft(leftC, by: 10)
            leftC = leftB
            leftB = left

            let right = rotateLeft(
                rightA &+ rightFunction(round, rightB, rightC, rightD)
                    &+ words[Self.rightWordOrder[round]]
                    &+ rightConstant(round),
                by: Self.rightRotation[round]
            ) &+ rightE
            rightA = rightE
            rightE = rightD
            rightD = rotateLeft(rightC, by: 10)
            rightC = rightB
            rightB = right
        }

        let combined = state[1] &+ leftC &+ rightD
        state[1] = state[2] &+ leftD &+ rightE
        state[2] = state[3] &+ leftE &+ rightA
        state[3] = state[4] &+ leftA &+ rightB
        state[4] = state[0] &+ leftB &+ rightC
        state[0] = combined
    }

    private func leftFunction(
        _ round: Int,
        _ x: UInt32,
        _ y: UInt32,
        _ z: UInt32
    ) -> UInt32 {
        switch round {
        case 0..<16: x ^ y ^ z
        case 16..<32: (x & y) | (~x & z)
        case 32..<48: (x | ~y) ^ z
        case 48..<64: (x & z) | (y & ~z)
        default: x ^ (y | ~z)
        }
    }

    private func rightFunction(
        _ round: Int,
        _ x: UInt32,
        _ y: UInt32,
        _ z: UInt32
    ) -> UInt32 {
        switch round {
        case 0..<16: x ^ (y | ~z)
        case 16..<32: (x & z) | (y & ~z)
        case 32..<48: (x | ~y) ^ z
        case 48..<64: (x & y) | (~x & z)
        default: x ^ y ^ z
        }
    }

    private func leftConstant(_ round: Int) -> UInt32 {
        switch round {
        case 0..<16: 0x0000_0000
        case 16..<32: 0x5a82_7999
        case 32..<48: 0x6ed9_eba1
        case 48..<64: 0x8f1b_bcdc
        default: 0xa953_fd4e
        }
    }

    private func rightConstant(_ round: Int) -> UInt32 {
        switch round {
        case 0..<16: 0x50a2_8be6
        case 16..<32: 0x5c4d_d124
        case 32..<48: 0x6d70_3ef3
        case 48..<64: 0x7a6d_76e9
        default: 0x0000_0000
        }
    }

    private func rotateLeft(_ value: UInt32, by amount: Int) -> UInt32 {
        (value << amount) | (value >> (32 - amount))
    }
}
