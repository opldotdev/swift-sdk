import BSVKeys

/// A bounded compatibility BIP-32 derivation path rooted at `m` or `M`.
public struct HDKeyPath: Hashable, Sendable, CustomStringConvertible {
    /// The extended-key kind named by the path's root character.
    public let root: ExtendedKeyKind
    /// The ordered child numbers following the root.
    public let components: [HDChildNumber]

    /// Parses an absolute BIP-32 path.
    ///
    /// Only ASCII decimal components and the canonical hardened suffix `'` are accepted.
    /// At most 255 components and 2,048 UTF-8 bytes are examined.
    public init(_ text: String) throws {
        let bytes = Array(text.utf8.prefix(2_049))
        guard !bytes.isEmpty, bytes.count <= 2_048 else {
            throw ExtendedKeyError.invalidPath
        }

        switch bytes[0] {
        case 0x6d: // m
            root = .privateKey
        case 0x4d: // M
            root = .publicKey
        default:
            throw ExtendedKeyError.invalidPath
        }

        if bytes.count == 1 {
            components = []
            return
        }
        guard bytes[1] == 0x2f, bytes.count > 2 else { // /
            throw ExtendedKeyError.invalidPath
        }

        var parsed: [HDChildNumber] = []
        parsed.reserveCapacity(min(255, bytes.count / 2))
        var position = 2
        while position < bytes.count {
            guard parsed.count < 255 else {
                throw ExtendedKeyError.invalidPath
            }
            var value: UInt32 = 0
            var digitCount = 0
            while position < bytes.count, bytes[position] >= 0x30, bytes[position] <= 0x39 {
                let digit = UInt32(bytes[position] - 0x30)
                guard value <= (HDChildNumber.hardenedOffset - 1 - digit) / 10 else {
                    throw ExtendedKeyError.invalidPath
                }
                value = value * 10 + digit
                digitCount += 1
                position += 1
            }
            guard digitCount > 0 else {
                throw ExtendedKeyError.invalidPath
            }

            var hardened = false
            if position < bytes.count, bytes[position] == 0x27 { // '
                hardened = true
                position += 1
            }
            parsed.append(try HDChildNumber(index: value, hardened: hardened))

            if position == bytes.count {
                break
            }
            guard bytes[position] == 0x2f else {
                throw ExtendedKeyError.invalidPath
            }
            position += 1
            guard position < bytes.count else {
                throw ExtendedKeyError.invalidPath
            }
        }
        components = parsed
    }

    /// Creates an absolute path from validated child-number components.
    public init(root: ExtendedKeyKind, components: [HDChildNumber]) throws {
        guard components.count <= 255 else {
            throw ExtendedKeyError.invalidPath
        }
        self.root = root
        self.components = components
    }

    /// Canonical path notation, using `m`/`M` and `'` hardened suffixes.
    public var description: String {
        let rootText = root == .privateKey ? "m" : "M"
        guard !components.isEmpty else { return rootText }
        return rootText + "/" + components.map(\.description).joined(separator: "/")
    }
}
