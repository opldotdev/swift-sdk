/// The order `@bsv/sdk` sorts signed names in: JavaScript
/// `String.prototype.localeCompare` with no arguments, which Node and Bun
/// implement with the ICU root collation (`en-US`, tertiary strength,
/// punctuation not ignored).
///
/// TypeScript uses it for certificate field names in the BRC-52 binary form
/// and its signing preimage (`auth/certificates/Certificate.ts:290`) and for
/// signed BRC-104 header names (`auth/clients/AuthFetch.ts:740`,
/// `auth/transports/SimplifiedFetchTransport.ts:286`,
/// `auth-express-middleware/src/index.ts:2105`).
///
/// Strings compare by primary weight first: whitespace, then punctuation and
/// symbols in ICU order, then digits, then letters with case and accents
/// ignored. Remaining ties are broken by accents (secondary weights), then by
/// case, lowercase first (tertiary weights). ICU ignores the C0 controls other
/// than tab, line feed, vertical tab, form feed and carriage return, and DEL;
/// so does this order.
///
/// The order is exact for printable ASCII and for the 488 precomposed Latin
/// letters in U+00C0-U+024F and U+1E00-U+1EFF whose canonical decomposition is
/// an ASCII letter followed by combining diacritics, such as `é`, `Å`, `ñ`,
/// `ǖ` and `ự`; `isExact(_:)` tells whether a string uses only those. A
/// combining diacritic from that set written separately after a letter weighs
/// as it does inside a precomposed letter.
///
/// Other characters are not collated as ICU collates them. C1 controls and the
/// default-ignorable format characters are ignored; every other scalar sorts
/// after all ASCII and Latin letters, in code point order. Names with such
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
        if let order = compareSequences(left.secondary, right.secondary) { return order }
        if let order = compareSequences(left.tertiary, right.tertiary) { return order }
        return compareSequences(Array(lhs.utf8), Array(rhs.utf8)) ?? 0
    }

    /// `true` when every scalar of `value` is printable ASCII (U+0020-U+007E)
    /// or one of the precomposed Latin letters this order collates as ICU
    /// does, so `localeCompare` sorts it exactly as this order does.
    package static func isExact(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { scalar in
            (0x20...0x7E).contains(scalar.value) || latinLetters[scalar.value] != nil
        }
    }

    /// The ASCII characters ICU does not ignore, in ICU root order, each
    /// lowercase letter followed by its uppercase form.
    package static let asciiOrder =
        "\t\n\u{0B}\u{0C}\r _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789"
        + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"

    /// The combining diacritics that occur in `latinLetters`, in ICU secondary
    /// order: acute sorts first, macron below last.
    private static let diacriticOrder: [UInt32] = [
        0x0301, 0x0300, 0x0306, 0x0302, 0x030C, 0x030A, 0x0308, 0x030B, 0x0303, 0x0307,
        0x0327, 0x0328, 0x0304, 0x0309, 0x030F, 0x0311, 0x031B, 0x0323, 0x0324, 0x0325,
        0x0326, 0x032D, 0x032E, 0x0330, 0x0331,
    ]

    /// The secondary weight of each diacritic, from 1; 0 is the weight of a
    /// character with no diacritic.
    private static let diacriticWeight: [UInt32: UInt8] = {
        var table: [UInt32: UInt8] = [:]
        for (index, scalar) in diacriticOrder.enumerated() { table[scalar] = UInt8(index + 1) }
        return table
    }()

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

    /// A precomposed Latin letter: its ASCII base letter and the secondary
    /// weights of its diacritics in canonical order.
    private struct LatinLetter {
        let base: UInt8
        let diacritics: [UInt8]
    }

    /// Each entry is the code point in hex, the base letter, and one letter
    /// per diacritic: `a` for the first in `diacriticOrder`, `b` for the
    /// second, and so on. Generated from `String.prototype.normalize("NFD")`
    /// and checked against `localeCompare` by `certorder-vec.ts`
    /// (Documentation/Compatibility/TypeScriptAuthVectors.md).
    private static let latinLetterTable = """
        00C0Ab 00C1Aa 00C2Ad 00C3Ai 00C4Ag 00C5Af 00C7Ck 00C8Eb 00C9Ea 00CAEd
        00CBEg 00CCIb 00CDIa 00CEId 00CFIg 00D1Ni 00D2Ob 00D3Oa 00D4Od 00D5Oi
        00D6Og 00D9Ub 00DAUa 00DBUd 00DCUg 00DDYa 00E0ab 00E1aa 00E2ad 00E3ai
        00E4ag 00E5af 00E7ck 00E8eb 00E9ea 00EAed 00EBeg 00ECib 00EDia 00EEid
        00EFig 00F1ni 00F2ob 00F3oa 00F4od 00F5oi 00F6og 00F9ub 00FAua 00FBud
        00FCug 00FDya 00FFyg 0100Am 0101am 0102Ac 0103ac 0104Al 0105al 0106Ca
        0107ca 0108Cd 0109cd 010ACj 010Bcj 010CCe 010Dce 010EDe 010Fde 0112Em
        0113em 0114Ec 0115ec 0116Ej 0117ej 0118El 0119el 011AEe 011Bee 011CGd
        011Dgd 011EGc 011Fgc 0120Gj 0121gj 0122Gk 0123gk 0124Hd 0125hd 0128Ii
        0129ii 012AIm 012Bim 012CIc 012Dic 012EIl 012Fil 0130Ij 0134Jd 0135jd
        0136Kk 0137kk 0139La 013Ala 013BLk 013Clk 013DLe 013Ele 0143Na 0144na
        0145Nk 0146nk 0147Ne 0148ne 014COm 014Dom 014EOc 014Foc 0150Oh 0151oh
        0154Ra 0155ra 0156Rk 0157rk 0158Re 0159re 015ASa 015Bsa 015CSd 015Dsd
        015ESk 015Fsk 0160Se 0161se 0162Tk 0163tk 0164Te 0165te 0168Ui 0169ui
        016AUm 016Bum 016CUc 016Duc 016EUf 016Fuf 0170Uh 0171uh 0172Ul 0173ul
        0174Wd 0175wd 0176Yd 0177yd 0178Yg 0179Za 017Aza 017BZj 017Czj 017DZe
        017Eze 01A0Oq 01A1oq 01AFUq 01B0uq 01CDAe 01CEae 01CFIe 01D0ie 01D1Oe
        01D2oe 01D3Ue 01D4ue 01D5Ugm 01D6ugm 01D7Uga 01D8uga 01D9Uge 01DAuge 01DBUgb
        01DCugb 01DEAgm 01DFagm 01E0Ajm 01E1ajm 01E6Ge 01E7ge 01E8Ke 01E9ke 01EAOl
        01EBol 01ECOlm 01EDolm 01F0je 01F4Ga 01F5ga 01F8Nb 01F9nb 01FAAfa 01FBafa
        0200Ao 0201ao 0202Ap 0203ap 0204Eo 0205eo 0206Ep 0207ep 0208Io 0209io
        020AIp 020Bip 020COo 020Doo 020EOp 020Fop 0210Ro 0211ro 0212Rp 0213rp
        0214Uo 0215uo 0216Up 0217up 0218Su 0219su 021ATu 021Btu 021EHe 021Fhe
        0226Aj 0227aj 0228Ek 0229ek 022AOgm 022Bogm 022COim 022Doim 022EOj 022Foj
        0230Ojm 0231ojm 0232Ym 0233ym 1E00At 1E01at 1E02Bj 1E03bj 1E04Br 1E05br
        1E06By 1E07by 1E08Cka 1E09cka 1E0ADj 1E0Bdj 1E0CDr 1E0Ddr 1E0EDy 1E0Fdy
        1E10Dk 1E11dk 1E12Dv 1E13dv 1E14Emb 1E15emb 1E16Ema 1E17ema 1E18Ev 1E19ev
        1E1AEx 1E1Bex 1E1CEkc 1E1Dekc 1E1EFj 1E1Ffj 1E20Gm 1E21gm 1E22Hj 1E23hj
        1E24Hr 1E25hr 1E26Hg 1E27hg 1E28Hk 1E29hk 1E2AHw 1E2Bhw 1E2CIx 1E2Dix
        1E2EIga 1E2Figa 1E30Ka 1E31ka 1E32Kr 1E33kr 1E34Ky 1E35ky 1E36Lr 1E37lr
        1E38Lrm 1E39lrm 1E3ALy 1E3Bly 1E3CLv 1E3Dlv 1E3EMa 1E3Fma 1E40Mj 1E41mj
        1E42Mr 1E43mr 1E44Nj 1E45nj 1E46Nr 1E47nr 1E48Ny 1E49ny 1E4ANv 1E4Bnv
        1E4COia 1E4Doia 1E4EOig 1E4Foig 1E50Omb 1E51omb 1E52Oma 1E53oma 1E54Pa 1E55pa
        1E56Pj 1E57pj 1E58Rj 1E59rj 1E5ARr 1E5Brr 1E5CRrm 1E5Drrm 1E5ERy 1E5Fry
        1E60Sj 1E61sj 1E62Sr 1E63sr 1E64Saj 1E65saj 1E66Sej 1E67sej 1E68Srj 1E69srj
        1E6ATj 1E6Btj 1E6CTr 1E6Dtr 1E6ETy 1E6Fty 1E70Tv 1E71tv 1E72Us 1E73us
        1E74Ux 1E75ux 1E76Uv 1E77uv 1E78Uia 1E79uia 1E7AUmg 1E7Bumg 1E7CVi 1E7Dvi
        1E7EVr 1E7Fvr 1E80Wb 1E81wb 1E82Wa 1E83wa 1E84Wg 1E85wg 1E86Wj 1E87wj
        1E88Wr 1E89wr 1E8AXj 1E8Bxj 1E8CXg 1E8Dxg 1E8EYj 1E8Fyj 1E90Zd 1E91zd
        1E92Zr 1E93zr 1E94Zy 1E95zy 1E96hy 1E97tg 1E98wf 1E99yf 1EA0Ar 1EA1ar
        1EA2An 1EA3an 1EA4Ada 1EA5ada 1EA6Adb 1EA7adb 1EA8Adn 1EA9adn 1EAAAdi 1EABadi
        1EACArd 1EADard 1EAEAca 1EAFaca 1EB0Acb 1EB1acb 1EB2Acn 1EB3acn 1EB4Aci 1EB5aci
        1EB6Arc 1EB7arc 1EB8Er 1EB9er 1EBAEn 1EBBen 1EBCEi 1EBDei 1EBEEda 1EBFeda
        1EC0Edb 1EC1edb 1EC2Edn 1EC3edn 1EC4Edi 1EC5edi 1EC6Erd 1EC7erd 1EC8In 1EC9in
        1ECAIr 1ECBir 1ECCOr 1ECDor 1ECEOn 1ECFon 1ED0Oda 1ED1oda 1ED2Odb 1ED3odb
        1ED4Odn 1ED5odn 1ED6Odi 1ED7odi 1ED8Ord 1ED9ord 1EDAOqa 1EDBoqa 1EDCOqb 1EDDoqb
        1EDEOqn 1EDFoqn 1EE0Oqi 1EE1oqi 1EE2Oqr 1EE3oqr 1EE4Ur 1EE5ur 1EE6Un 1EE7un
        1EE8Uqa 1EE9uqa 1EEAUqb 1EEBuqb 1EECUqn 1EEDuqn 1EEEUqi 1EEFuqi 1EF0Uqr 1EF1uqr
        1EF2Yb 1EF3yb 1EF4Yr 1EF5yr 1EF6Yn 1EF7yn 1EF8Yi 1EF9yi
        """

    private static let latinLetters: [UInt32: LatinLetter] = {
        var table: [UInt32: LatinLetter] = [:]
        for entry in latinLetterTable.split(whereSeparator: { $0 == " " || $0 == "\n" }) {
            let bytes = Array(entry.utf8)
            guard bytes.count >= 6,
                  let code = UInt32(String(decoding: bytes[0..<4], as: UTF8.self), radix: 16)
            else { preconditionFailure("malformed Latin letter table entry") }
            table[code] = LatinLetter(
                base: bytes[4],
                diacritics: bytes[5...].map { $0 - UInt8(ascii: "a") + 1 }
            )
        }
        return table
    }()

    private struct Key {
        var primary: [UInt32] = []
        var secondary: [UInt8] = []
        var tertiary: [UInt8] = []

        mutating func appendASCII(_ code: UInt32) {
            guard let primary = asciiPrimary[Int(code)] else { return }
            self.primary.append(primary)
            secondary.append(0)
            tertiary.append((65...90).contains(code) ? 1 : 0)
        }
    }

    private static func key(_ value: String) -> Key {
        var result = Key()
        for scalar in value.unicodeScalars {
            let code = scalar.value
            if code < 128 {
                result.appendASCII(code)
            } else if let letter = latinLetters[code] {
                result.appendASCII(UInt32(letter.base))
                result.secondary += letter.diacritics
            } else if let weight = diacriticWeight[code] {
                // A diacritic has no primary weight; it only adds a secondary one.
                result.secondary.append(weight)
            } else if !ignorable(code) {
                result.primary.append(1_000 + code)
                result.secondary.append(0)
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
