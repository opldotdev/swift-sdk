import BSVCore

/// The BRC-74 field being decoded when a Merkle path failed structurally.
public enum MerklePathField: Equatable, Sendable {
    case blockHeight
    case treeHeight
    case leafCount(level: Int)
    case offset(level: Int, leaf: Int)
    case flags(level: Int, leaf: Int)
    case hash(level: Int, leaf: Int)
    case trailingBytes
}

/// Typed representation, resource, and proof failures for BRC-74 Merkle paths.
public enum MerklePathError: Error, Equatable, Sendable {
    case invalidMaximumByteCount(Int)
    case invalidMaximumLeavesPerLevel(UInt64)
    case invalidMaximumTotalLeaves(UInt64)
    case pathTooLarge(actual: Int, maximum: Int)
    case blockHeightOutOfRange(UInt64)
    case invalidTreeHeight(Int)
    case leafCountExceedsLimit(level: Int, actual: UInt64, maximum: UInt64)
    case totalLeafCountExceedsLimit(actual: UInt64, maximum: UInt64)
    case countNotRepresentable(UInt64)
    /// Not produced by the parser, which reads flags as a bitmask like
    /// @bsv/sdk and the Go SDK. Retained for source compatibility.
    case invalidFlags(level: Int, leaf: Int, flags: UInt8)
    case duplicateLeafOffset(level: Int, offset: UInt64)
    case duplicateMarkerRequiresOddOffset(level: Int, offset: UInt64)
    case transactionIDMarkerOutsideLevelZero(level: Int, offset: UInt64)
    case offsetOutOfRange(level: Int, offset: UInt64, treeHeight: Int)
    /// A node above level zero that no level-zero hash needs: it is not the
    /// sibling of any level-zero hash's ancestor at that height.
    case illegalOffset(level: Int, offset: UInt64)
    case missingLevelZeroHash
    case malformed(field: MerklePathField, offset: Int, cause: BinaryDecodingError)
    case invalidHex(TextEncodingError)
    case invalidJSON
    case serializedSizeOverflow
    case transactionNotInPath(TransactionID)
    case missingSibling(level: Int, offset: UInt64)
    case blockHeightMismatch(expected: UInt32, actual: UInt32)
    case rootMismatch
    case inconsistentRoot
    case conflictingElement(level: Int, offset: UInt64)
}
