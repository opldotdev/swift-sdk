import BSVCore
import BSVCrypto
import Testing

/// `LocaleCompareOrder` against JavaScript `localeCompare`.
///
/// The expected values were produced by Bun 1.4.4 and Node 22.23.4 (both ICU,
/// locale `en-US`) running `collate-vec.ts` and `certorder-vec.ts` in
/// Documentation/Compatibility/TypeScriptAuthVectors.md; both printed the same
/// results.
@Suite("localeCompare order")
struct LocaleCompareOrderTests {
    @Test("printable ASCII sorts as localeCompare does")
    func printableASCII() {
        let printable = (0x20...0x7E).map { String(UnicodeScalar(UInt8($0))) }
        let sorted = printable.sorted(by: LocaleCompareOrder.areInIncreasingOrder)
        #expect(
            sorted.joined()
                == " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789"
                + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ")
        #expect(LocaleCompareOrder.asciiOrder.hasSuffix(sorted.joined()))
    }

    @Test("every pair of printable ASCII characters sorts as localeCompare does")
    func printableASCIIPairs() {
        let printable = (0x20...0x7E).map { String(UnicodeScalar(UInt8($0))) }
        var pairs: [String] = []
        for first in printable { for second in printable { pairs.append(first + second) } }
        #expect(pairs.count == 9_025)
        // localeCompare reports no ties among these 9025 strings, so the order is total.
        #expect(
            sortedDigest(pairs)
                == "486638e314651e755e158382de74daec1be1e94d392ff87e70f48006b14bc4f8")
    }

    @Test("three-character strings over spaces, punctuation, digits and both cases")
    func triples() {
        let alphabet = Array(" !-._09aAzZ").map(String.init)
        var triples: [String] = []
        for a in alphabet { for b in alphabet { for c in alphabet { triples.append(a + b + c) } } }
        #expect(triples.count == 1_331)
        #expect(
            sortedDigest(triples)
                == "a7264e62b832c8d1682eb3222b5dadff4d39138b5c05a7fd517bbc32941eb25f")
    }

    @Test("random printable ASCII strings of one to eight characters")
    func randomStrings() {
        // x = (1103515245 x + 12345) mod 2^31 from x = 1, as in `collate-vec.ts`.
        var state: UInt32 = 1
        func next() -> Int {
            state = (state &* 1_103_515_245 &+ 12_345) & 0x7FFF_FFFF
            return Int(state)
        }
        var strings: [String] = []
        for _ in 0..<4_000 {
            let length = 1 + next() % 8
            var value = ""
            for _ in 0..<length { value.unicodeScalars.append(UnicodeScalar(UInt8(0x20 + next() % 95))) }
            strings.append(value)
        }
        #expect(Array(strings.prefix(3)) == ["/[0QeO/", "1(]D+70", "G^[m>^0"])
        #expect(Set(strings).count == 4_000)
        #expect(
            sortedDigest(strings)
                == "1c2fb4ded5031dfa2cf5cf764b119dcb5477b331e17dd8ce43dc71234585957a")
    }

    @Test("field and header names sort as localeCompare does")
    func names() {
        let names = [
            "Zip", "age", "a_b", "a-b", "ab", "a b", "A", "a", "aB", "Ab", "a1", "a10", "a2",
            "x-bsv-a_b", "x-bsv-ab", "x-bsv-a-b", "x-bsv-Z", "x-bsv-z", "email", "Email",
            "first_name", "firstName", "first-name",
        ]
        #expect(
            names.sorted(by: LocaleCompareOrder.areInIncreasingOrder) == [
                "a", "A", "a b", "a_b", "a-b", "a1", "a10", "a2", "ab", "aB", "Ab", "age", "email",
                "Email", "first_name", "first-name", "firstName", "x-bsv-a_b", "x-bsv-a-b",
                "x-bsv-ab", "x-bsv-z", "x-bsv-Z", "Zip",
            ])
        #expect(LocaleCompareOrder.compare("age", "Zip") < 0)
        #expect(Array("age".utf8).lexicographicallyPrecedes(Array("Zip".utf8)) == false)
    }

    @Test("non-Latin and ignorable characters have a documented total order")
    func nonLatin() {
        // ICU ignores most C0 controls: `'a\u0001b'.localeCompare('ab') === 0`.
        // Such ties fall back to UTF-8 byte order, so the order stays total.
        #expect(LocaleCompareOrder.compare("a\u{01}b", "ab") < 0)
        #expect(LocaleCompareOrder.compare("ab", "a\u{01}b") > 0)
        #expect(LocaleCompareOrder.compare("a\u{AD}b", "abc") < 0)
        // Characters past the Latin letters sort after them in code point
        // order. ICU puts `ø` among the `o`s; this order does not.
        #expect(LocaleCompareOrder.compare("ø", "z") > 0)
        #expect(LocaleCompareOrder.compare("日本", "ø") > 0)
        #expect(LocaleCompareOrder.compare("same", "same") == 0)
        #expect(!LocaleCompareOrder.isExact("ø"))
        #expect(!LocaleCompareOrder.isExact("e\u{301}"))
        #expect(!LocaleCompareOrder.isExact("a\u{01}"))
        #expect(LocaleCompareOrder.isExact("Ångström résumé_2"))
    }

    @Test("accented Latin letters sort among the ASCII letters, as localeCompare puts them")
    func accentedLetters() {
        let letters = Self.latinLetters
        #expect(letters.count == 488)
        #expect(letters.first == "À" && letters.last == "ỹ")
        let printable = (0x20...0x7E).map { String(UnicodeScalar(UInt8($0))) }
        #expect(
            sortedDigest(printable + letters)
                == "07b7a5435f649f665bee10c149883c140afb2fd1063cbdbce1a699417158cf36")

        let alphabet = Array("aAeEzZ_-1 .áÁàâäåéÉèêëǖüűñÑçșţắạ").map(String.init)
        var pairs: [String] = []
        for first in alphabet { for second in alphabet { pairs.append(first + second) } }
        #expect(pairs.count == 1_024)
        #expect(
            sortedDigest(pairs)
                == "57181742c00e7739f0c68888ec3318e869ee62652f93f9851c4ea2f380e2b2cb")

        // Every fourth letter, so the base letter, accents and case all vary.
        let pool = Array("aAbBeEnNoOuUzZ").map(String.init)
            + letters.enumerated().filter { $0.offset % 4 == 0 }.map(\.element)
        var letterPairs: [String] = []
        for first in pool { for second in pool { letterPairs.append(first + second) } }
        #expect(letterPairs.count == 18_496)
        #expect(
            sortedDigest(letterPairs)
                == "715437241639b28e026b8aa2878e19c5ba18803f7ee8383ec90d938f90a1c48f")
        // A decomposed accent weighs as the precomposed letter does.
        #expect(LocaleCompareOrder.compare("e\u{301}", "é") < 0)
        #expect(LocaleCompareOrder.compare("e\u{301}x", "éx") < 0)
        #expect(LocaleCompareOrder.compare("e\u{301}", "ê") < 0)
        #expect(LocaleCompareOrder.compare("e\u{301}", "è") < 0)
        #expect(LocaleCompareOrder.compare("e\u{301}", "e") > 0)
    }

    @Test("random strings of ASCII and accented Latin letters")
    func randomLatinStrings() {
        let printable = (0x20...0x7E).map { String(UnicodeScalar(UInt8($0))) }
        let alphabet = printable + Self.latinLetters
        #expect(alphabet.count == 583)
        // x = (1103515245 x + 12345) mod 2^31 from x = 7, as in `certorder-vec.ts`.
        var state: UInt32 = 7
        func next() -> Int {
            state = (state &* 1_103_515_245 &+ 12_345) & 0x7FFF_FFFF
            return Int(state)
        }
        var strings: [String] = []
        for _ in 0..<6_000 {
            let length = 1 + next() % 8
            var value = ""
            for _ in 0..<length { value += alphabet[next() % alphabet.count] }
            strings.append(value)
        }
        #expect(Array(strings.prefix(3)) == ["ḙǐṯĻŏ", "\\uïḘṚȫỳ", "ẳf_Ṃ.ḿẇ"])
        #expect(Set(strings).count == 6_000)
        #expect(
            sortedDigest(strings)
                == "d7105d7be1cce76633600984066bbc5b571a8efdecf7896446f6248673736608")
    }

    @Test("certificate field names with case, accents, underscores and digits")
    func certificateNames() {
        let names = [
            "Zip", "zip_code", "zip-code", "zip2", "zip10", "Zeta", "email", "eMail", "Email",
            "_id", "id", "ID", "a1", "a_1", "a-1", "aB", "ab", "cafe", "café", "Café", "cafés",
            "émile", "Émile", "naïve", "nausea", "résumé", "resume", "zoë", "Ångström", "angle",
        ]
        #expect(
            names.sorted(by: LocaleCompareOrder.areInIncreasingOrder) == [
                "_id", "a_1", "a-1", "a1", "ab", "aB", "angle", "Ångström", "cafe", "café", "Café",
                "cafés", "email", "eMail", "Email", "émile", "Émile", "id", "ID", "naïve", "nausea",
                "resume", "résumé", "Zeta", "Zip", "zip_code", "zip-code", "zip10", "zip2", "zoë",
            ])
    }

    /// The precomposed Latin letters the order is exact for, in code point order.
    private static let latinLetters: [String] = {
        let scalars = (0x00C0...0x024F).compactMap(Unicode.Scalar.init)
            + (0x1E00...0x1EFF).compactMap(Unicode.Scalar.init)
        return scalars.map(String.init).filter(LocaleCompareOrder.isExact)
    }()

    private func sortedDigest(_ strings: [String]) -> String {
        let sorted = strings.sorted(by: LocaleCompareOrder.areInIncreasingOrder)
        return Hex.encode(BSVHashing.sha256(Array(sorted.joined(separator: "\n").utf8)).bytes)
    }
}
