package func airGapBlocksForPart(_ sequence: UInt32, blockCount: Int) -> [Int] {
    var generator = AirGapXorShift32(seed: sequence &* 0x9e37_79b1)
    let scale = UInt64(1 << 23)
    let random = UInt64(generator.draw23())
    var degree = Int((scale + random) / (random + 1))
    if degree > blockCount { degree = 1 }

    var pool = Array(0..<blockCount)
    for index in 0..<degree {
        let draw = UInt64(generator.draw23())
        let offset = Int((draw * UInt64(blockCount - index)) / scale)
        pool.swapAt(index, index + offset)
    }
    return Array(pool.prefix(degree))
}

package func airGapXOR(_ source: [UInt8], into target: inout [UInt8]) {
    precondition(source.count == target.count)
    for index in target.indices {
        target[index] ^= source[index]
    }
}

private struct AirGapXorShift32 {
    private var state: UInt32

    init(seed: UInt32) {
        state = seed == 0 ? 0x6d2b_79f5 : seed
    }

    mutating func next() -> UInt32 {
        state ^= state << 13
        state ^= state >> 17
        state ^= state << 5
        return state
    }

    mutating func draw23() -> UInt32 {
        next() >> 9
    }
}
