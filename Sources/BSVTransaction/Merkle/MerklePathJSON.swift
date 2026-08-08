import BSVCore
import Foundation

extension MerklePath {
    /// Parses one strict, bounded BRC-74 JSON object.
    ///
    /// Hash strings use conventional reversed display order. Unknown fields,
    /// false marker values, ambiguous hash/duplicate leaves, and noncanonical
    /// hash strings are rejected.
    public init(jsonBytes: [UInt8], limits: MerklePathLimits) throws {
        guard jsonBytes.count <= limits.maximumByteCount else {
            throw MerklePathError.pathTooLarge(
                actual: jsonBytes.count,
                maximum: limits.maximumByteCount
            )
        }

        let representation: MerklePathJSONRepresentation
        do {
            representation = try JSONDecoder().decode(
                MerklePathJSONRepresentation.self,
                from: Data(jsonBytes)
            )
        } catch {
            throw MerklePathError.invalidJSON
        }

        var totalLeaves: UInt64 = 0
        var levels: [[MerklePathElement]] = []
        levels.reserveCapacity(representation.path.count)
        for (levelIndex, representedLevel) in representation.path.enumerated() {
            let count = UInt64(representedLevel.count)
            guard count <= limits.maximumLeavesPerLevel else {
                throw MerklePathError.leafCountExceedsLimit(
                    level: levelIndex,
                    actual: count,
                    maximum: limits.maximumLeavesPerLevel
                )
            }
            let (nextTotal, overflow) = totalLeaves.addingReportingOverflow(count)
            guard !overflow, nextTotal <= limits.maximumTotalLeaves else {
                throw MerklePathError.totalLeafCountExceedsLimit(
                    actual: overflow ? .max : nextTotal,
                    maximum: limits.maximumTotalLeaves
                )
            }
            totalLeaves = nextTotal

            var level: [MerklePathElement] = []
            level.reserveCapacity(representedLevel.count)
            for leaf in representedLevel {
                switch leaf.value {
                case .duplicate:
                    level.append(.duplicate(offset: leaf.offset))
                case .hash(let displayHex, let isTransactionID):
                    do {
                        let transactionID = try TransactionID(displayHex: displayHex)
                        level.append(.hash(
                            offset: leaf.offset,
                            hash: try Hash256(transactionID.wireBytes),
                            isTransactionID: isTransactionID
                        ))
                    } catch {
                        throw MerklePathError.invalidJSON
                    }
                }
            }
            levels.append(level)
        }

        try self.init(blockHeight: representation.blockHeight, levels: levels)
    }

    /// Emits deterministic BRC-74 JSON with hashes in reversed display order.
    public func jsonBytes(limits: MerklePathLimits) throws -> [UInt8] {
        var totalLeaves: UInt64 = 0
        let representedLevels = try levels.enumerated().map { levelIndex, level in
            let count = UInt64(level.count)
            guard count <= limits.maximumLeavesPerLevel else {
                throw MerklePathError.leafCountExceedsLimit(
                    level: levelIndex,
                    actual: count,
                    maximum: limits.maximumLeavesPerLevel
                )
            }
            let (nextTotal, overflow) = totalLeaves.addingReportingOverflow(count)
            guard !overflow, nextTotal <= limits.maximumTotalLeaves else {
                throw MerklePathError.totalLeafCountExceedsLimit(
                    actual: overflow ? .max : nextTotal,
                    maximum: limits.maximumTotalLeaves
                )
            }
            totalLeaves = nextTotal

            return try level.map { element in
                switch element {
                case .duplicate(let offset):
                    return MerklePathJSONLeaf(offset: offset, value: .duplicate)
                case .hash(let offset, let hash, let isTransactionID):
                    let displayHex = try TransactionID(
                        wireBytes: hash.bytes
                    ).displayHex
                    return MerklePathJSONLeaf(
                        offset: offset,
                        value: .hash(
                            displayHex: displayHex,
                            isTransactionID: isTransactionID
                        )
                    )
                }
            }
        }

        let representation = MerklePathJSONRepresentation(
            blockHeight: blockHeight,
            path: representedLevels
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data: Data
        do {
            data = try encoder.encode(representation)
        } catch {
            throw MerklePathError.invalidJSON
        }
        guard data.count <= limits.maximumByteCount else {
            throw MerklePathError.pathTooLarge(
                actual: data.count,
                maximum: limits.maximumByteCount
            )
        }
        return [UInt8](data)
    }
}

private struct MerklePathJSONRepresentation: Codable {
    let blockHeight: UInt32
    let path: [[MerklePathJSONLeaf]]

    init(blockHeight: UInt32, path: [[MerklePathJSONLeaf]]) {
        self.blockHeight = blockHeight
        self.path = path
    }

    init(from decoder: Decoder) throws {
        enum Keys: String, CodingKey, CaseIterable { case blockHeight, path }
        try rejectUnknownMerklePathFields(
            decoder,
            allowed: Set(Keys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(keyedBy: Keys.self)
        blockHeight = try container.decode(UInt32.self, forKey: .blockHeight)
        path = try container.decode([[MerklePathJSONLeaf]].self, forKey: .path)
    }
}

private struct MerklePathJSONLeaf: Codable {
    enum Value {
        case hash(displayHex: String, isTransactionID: Bool)
        case duplicate
    }

    let offset: UInt64
    let value: Value

    init(offset: UInt64, value: Value) {
        self.offset = offset
        self.value = value
    }

    init(from decoder: Decoder) throws {
        enum Keys: String, CodingKey, CaseIterable { case offset, hash, txid, duplicate }
        try rejectUnknownMerklePathFields(
            decoder,
            allowed: Set(Keys.allCases.map(\.rawValue))
        )
        let container = try decoder.container(keyedBy: Keys.self)
        offset = try container.decode(UInt64.self, forKey: .offset)
        let hash = try container.decodeIfPresent(String.self, forKey: .hash)
        let txid = try container.decodeIfPresent(Bool.self, forKey: .txid)
        let duplicate = try container.decodeIfPresent(Bool.self, forKey: .duplicate)

        guard txid != false, duplicate != false else {
            throw DecodingError.dataCorruptedError(
                forKey: txid == false ? .txid : .duplicate,
                in: container,
                debugDescription: "BRC-74 boolean markers may only be present as true"
            )
        }
        switch (hash, duplicate) {
        case (.some(let hash), nil):
            value = .hash(displayHex: hash, isTransactionID: txid == true)
        case (nil, .some(true)) where txid == nil:
            value = .duplicate
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .hash,
                in: container,
                debugDescription: "A BRC-74 leaf contains exactly one hash or duplicate marker"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        enum Keys: String, CodingKey { case offset, hash, txid, duplicate }
        var container = encoder.container(keyedBy: Keys.self)
        try container.encode(offset, forKey: .offset)
        switch value {
        case .duplicate:
            try container.encode(true, forKey: .duplicate)
        case .hash(let displayHex, let isTransactionID):
            try container.encode(displayHex, forKey: .hash)
            if isTransactionID {
                try container.encode(true, forKey: .txid)
            }
        }
    }
}

private struct MerklePathJSONCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

private func rejectUnknownMerklePathFields(
    _ decoder: Decoder,
    allowed: Set<String>
) throws {
    let container = try decoder.container(keyedBy: MerklePathJSONCodingKey.self)
    let unknown = Set(container.allKeys.map(\.stringValue)).subtracting(allowed)
    guard unknown.isEmpty else {
        let key = MerklePathJSONCodingKey(stringValue: unknown.sorted()[0])
        throw DecodingError.dataCorruptedError(
            forKey: key,
            in: container,
            debugDescription: "Unknown BRC-74 field"
        )
    }
}
