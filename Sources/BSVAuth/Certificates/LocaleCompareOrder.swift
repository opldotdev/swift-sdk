/// The order `@bsv/sdk` sorts signed names in: JavaScript
/// `String.prototype.localeCompare` with no arguments, which Node and Bun
/// implement with the ICU root collation (`en-US`, tertiary strength,
/// punctuation not ignored).
///
/// TypeScript uses it for certificate field names in the BRC-52 signing
/// preimage (`certificates/Certificate.ts:290`) and for signed BRC-104 header
/// names (`clients/AuthFetch.ts:740`,
/// `transports/SimplifiedFetchTransport.ts:286`,
/// `auth-express-middleware/src/index.ts:2105`).
///
/// The order is exact for ASCII. Strings compare by primary weight first:
/// whitespace, then punctuation and symbols in ICU order, then digits, then
/// letters with case ignored. Remaining ties are broken by case, lowercase
/// first. ICU ignores the C0 controls other than tab, line feed, vertical tab,
/// form feed and carriage return, and DEL; so does this order.
///
/// Other characters are not collated as ICU collates them. C1 controls and the
/// default-ignorable format characters are ignored; every other non-ASCII
/// scalar sorts after all ASCII, in code point order. Names with such
/// characters can sort differently in TypeScript. Strings ICU treats as equal
/// are ordered by UTF-8 bytes, so the order is total; TypeScript keeps their
/// insertion order instead.
package enum LocaleCompareOrder {
    /// `true` when `lhs` sorts before `rhs`.
    package static func areInIncreasingOrder(_ lhs: String, _ rhs: String) -> Bool {
        compare(lhs, rhs) < 0
    }

    /// A negative, zero or positive value, as `localeCompare` returns, with
    /// collation ties broken by UTF-8 bytes.
    package static func compare(_ lhs: String, _ rhs: String) -> Int {
        let left = key(lhs)
        let right = key(rhs)
        if let order = compareSequences(left.primary, right.primary) { return order }
        if let order = compareSequences(left.tertiary, right.tertiary) { return order }
        return compareSequences(Array(lhs.utf8), Array(rhs.utf8)) ?? 0
    }

    /// The ASCII characters ICU does not ignore, in ICU root order, each
    /// lowercase letter followed by its uppercase form.
    package static let asciiOrder =
        "\t\n\u{0B}\u{0C}\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789"
        + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"

    /// The primary weight of each ASCII scalar, or `nil` when ICU ignores it.
    /// An uppercase letter shares the weight of its lowercase form.
    private static let asciiPrimary: [UInt32?] = {
        var table = [UInt32?](repeating: nil, count: 128)
        var weight: UInt32 = 0
        for scalar in asciiOrder.unicodeScalars {
            let code = Int(scalar.value)
            if (65...90).contains(code) {
                table[code] = table[code + 32]
            } else {
                weight += 1
                table[code] = weight
            }
        }
        return table
    }()

    private struct Key {
        var primary: [UInt32] = []
        var tertiary: [UInt8] = []
    }

    private static func key(_ value: String) -> Key {
        var result = Key()
        for scalar in value.unicodeScalars {
            let code = scalar.value
            if code < 128 {
                guard let primary = asciiPrimary[Int(code)] else { continue }
                result.primary.append(primary)
                result.tertiary.append((65...90).contains(code) ? 1 : 0)
            } else if !ignorable(code) {
                result.primary.append(1_000 + code)
                result.tertiary.append(0)
            }
        }
        return result
    }

    private static func ignorable(_ code: UInt32) -> Bool {
        switch code {
        case 0x80...0x9F, 0xAD, 0x200B...0x200F, 0x2060...0x2064, 0xFEFF: return true
        default: return false
        }
    }

    private static func compareSequences<Element: Comparable>(
        _ lhs: [Element], _ rhs: [Element]
    ) -> Int? {
        for (left, right) in zip(lhs, rhs) where left != right {
            return left < right ? -1 : 1
        }
        return lhs.count == rhs.count ? nil : (lhs.count < rhs.count ? -1 : 1)
    }
}
