import BSVCore
import BSVSPV

/// A validated block header returned by the block-headers service.
public struct BlockHeadersServiceHeader: Hashable, Sendable {
    public let height: UInt32
    public let hash: BlockHash
    public let header: BlockHeader

    /// The header's Merkle root in Bitcoin wire order.
    public var merkleRoot: Hash256 { header.merkleRoot }
    /// The signed Bitcoin block-version field.
    public var version: Int32 { header.version }
    /// The previous block hash in Bitcoin wire order.
    public var previousBlockHash: BlockHash { header.previousBlockHash }
    /// The Unix timestamp.
    public var timestamp: UInt32 { header.timestamp }
    /// The compact proof-of-work target.
    public var bits: UInt32 { header.bits }
    /// The proof-of-work nonce.
    public var nonce: UInt32 { header.nonce }

    public init(height: UInt32, hash: BlockHash, header: BlockHeader) throws {
        guard header.hash == hash else { throw NetworkServiceError.inconsistentResponse }
        self.height = height
        self.hash = hash
        self.header = header
    }
}

/// A validated chain-state record for one block header.
public struct BlockHeadersServiceState: Hashable, Sendable {
    public let header: BlockHeadersServiceHeader
    public let state: String
    public let height: UInt32

    public init(
        header: BlockHeadersServiceHeader,
        state: String,
        height: UInt32
    ) throws {
        guard BlockHeadersServiceState.isValidState(state) else {
            throw NetworkServiceError.malformedResponse
        }
        guard header.height == height else {
            throw NetworkServiceError.inconsistentResponse
        }
        self.header = header
        self.state = state
        self.height = height
    }

    /// Whether the service explicitly identifies this record as best-chain.
    public var isLongestChain: Bool { state == "LONGEST_CHAIN" }

    static func isValidState(_ state: String) -> Bool {
        guard !state.isEmpty, state.utf8.count <= 64 else { return false }
        return state.unicodeScalars.allSatisfy { scalar in
            (65...90).contains(scalar.value) || scalar.value == 95
        }
    }
}

/// One validated Merkle-root record from a paged service response.
public struct BlockHeadersServiceMerkleRoot: Hashable, Sendable {
    /// The Merkle root in Bitcoin wire order.
    public let merkleRoot: Hash256
    public let blockHeight: UInt32

    public init(merkleRoot: Hash256, blockHeight: UInt32) {
        self.merkleRoot = merkleRoot
        self.blockHeight = blockHeight
    }
}

/// A bounded page of Merkle-root records.
public struct BlockHeadersServiceMerkleRootsPage: Hashable, Sendable {
    public let content: [BlockHeadersServiceMerkleRoot]
    public let lastEvaluatedKey: BlockHash?

    public init(
        content: [BlockHeadersServiceMerkleRoot],
        lastEvaluatedKey: BlockHash?
    ) {
        self.content = content
        self.lastEvaluatedKey = lastEvaluatedKey
    }
}
