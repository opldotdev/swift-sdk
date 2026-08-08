import BSVKeys

/// A compatibility BIP-32 child number with an explicit derivation mode.
public struct HDChildNumber: Hashable, Sendable, CustomStringConvertible {
    /// The first serialized child number reserved for hardened derivation.
    public static let hardenedOffset: UInt32 = 0x8000_0000

    /// The exact 32-bit value appended to the BIP-32 derivation input.
    public let rawValue: UInt32

    /// Interprets an already serialized BIP-32 child number.
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Creates a child number from a semantic index and explicit hardened state.
    ///
    /// The index must fit in 31 bits, which prevents hardened-offset overflow.
    public init(index: UInt32, hardened: Bool) throws {
        guard index < Self.hardenedOffset else {
            throw ExtendedKeyError.invalidChildIndex(index)
        }
        self.rawValue = hardened ? index | Self.hardenedOffset : index
    }

    /// Creates a normal child number from a 31-bit semantic index.
    public static func normal(_ index: UInt32) throws -> Self {
        try Self(index: index, hardened: false)
    }

    /// Creates a hardened child number from a 31-bit semantic index.
    public static func hardened(_ index: UInt32) throws -> Self {
        try Self(index: index, hardened: true)
    }

    /// The semantic child index in `0...(2^31 - 1)`.
    public var index: UInt32 {
        rawValue & (Self.hardenedOffset - 1)
    }

    /// Whether this is a hardened child number.
    public var isHardened: Bool {
        rawValue >= Self.hardenedOffset
    }

    /// Canonical decimal notation, using `'` for hardened children.
    public var description: String {
        String(index) + (isHardened ? "'" : "")
    }
}
