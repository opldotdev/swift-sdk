/// The URI rules `@bsv/sdk` applies to the host field of a SHIP or SLAP
/// advertisement (`overlay-tools/OverlayAdminTokenTemplate.ts:30-158`).
///
/// `@bsv/sdk` parses these URIs with the WHATWG URL parser. This port parses
/// hosts the same way: domains are lowercased, IPv4 hosts in any WHATWG form
/// (`2130706433`, `0x7f.1`, `1.2.3`) are read as numbers and written as a
/// dotted quad, IPv6 hosts are validated and written in canonical form, and a
/// host that ends in a number but is not a valid IPv4 address is rejected. The
/// default port is dropped.
///
/// It accepts nothing `@bsv/sdk` rejects. It rejects a few forms that the
/// WHATWG parser accepts or repairs and no advertisement writer emits:
/// percent-encoded or non-ASCII host text, host characters outside letters,
/// digits, `-`, `.` and `_` (such as `! $ & ' ( ) * + , ; = ~`), any `@` in
/// the authority, a backslash, dot segments or other text in a path that must
/// be `/`, extra slashes after the scheme, and leading or trailing spaces.
enum OverlayAdvertisementURI {
    static let maximumByteCount = 4_096

    private static let httpsPrefixes = [
        "https://",
        "https+bsvauth://",
        "https+bsvauth+smf://",
        "https+bsvauth+scrypt-offchain://",
        "https+rtt://",
    ]
    private static let js8Prefix = "js8c+bsvauth+smf:"

    /// Whether `value` is an advertisement URI that `@bsv/sdk` accepts.
    static func isValid(_ value: String) -> Bool {
        guard !value.isEmpty,
            value.utf8.count <= maximumByteCount,
            !value.unicodeScalars.contains(where: isControl)
        else { return false }
        if let prefix = httpsPrefixes.first(where: { value.utf8.starts(with: $0.utf8) }) {
            guard let url = AuthorityURL(afterScheme: suffix(of: value, after: prefix)) else {
                return false
            }
            return url.isAllowedPublicHost && !url.hasFragment && url.path == "/"
        }
        if value.utf8.starts(with: "wss://".utf8) {
            guard let url = AuthorityURL(afterScheme: suffix(of: value, after: "wss://")) else {
                return false
            }
            return url.isAllowedPublicHost && !url.hasFragment
        }
        if value.utf8.starts(with: js8Prefix.utf8) {
            return isValidJS8(value)
        }
        return false
    }

    /// The `https://` origin an advertised URI names, as `@bsv/sdk` sends
    /// requests to it (`SHIPBroadcaster.ts:102-125`, `LookupResolver.ts:518-549`):
    /// canonical host, no default port, no trailing slash. Returns nil for a
    /// URI that is not an `https://` origin with path `""` or `"/"`.
    static func httpsOrigin(_ value: String) -> String? {
        httpsAuthority(value)?.origin
    }

    /// Whether `value` is an `https://` origin whose host may be a public
    /// network endpoint, as `createPublicNetworkFetch` in `@bsv/sdk` decides
    /// for an address literal (`storage/PublicHTTPSFetch.ts:61-158`).
    ///
    /// An IPv4 or IPv6 host must be a public unicast address. A domain may
    /// not have an empty label other than one trailing dot, may not be only
    /// digits and dots (`PublicHTTPSFetch.ts:201-204`), and, after its
    /// trailing dot is removed, may not be `localhost` or end in
    /// `.localhost`, `.local`, `.internal` or `.home.arpa`.
    ///
    /// Not checked: what a domain resolves to. On Node, `@bsv/sdk` resolves
    /// each name, refuses one that resolves to a private address and connects
    /// to the address it checked (`PublicHTTPSFetch.ts:262-271`). The
    /// `URLSession` transport resolves names itself and cannot be pinned to a
    /// checked address, so an advertised domain that resolves to a private
    /// address is still contacted. TLS limits that to a connection attempt
    /// whose certificate must match the advertised name.
    static func isPublicHTTPSOrigin(_ value: String) -> Bool {
        guard let url = httpsAuthority(value) else { return false }
        switch url.hostKind {
        case .ipv4(let address):
            return isPublicIPv4(address)
        case .ipv6(let pieces):
            return isPublicIPv6(pieces)
        case .domain:
            var name = url.host
            if name.hasSuffix(".") { name.removeLast() }
            let labels = name.split(separator: ".", omittingEmptySubsequences: false)
            guard !name.isEmpty, !labels.contains(where: \.isEmpty),
                !name.allSatisfy({ $0 == "." || ("0"..."9").contains($0) })
            else { return false }
            let privateSuffixes = [".localhost", ".local", ".internal", ".home.arpa"]
            return name != "localhost"
                && !privateSuffixes.contains(where: { name.hasSuffix($0) })
        }
    }

    private static func httpsAuthority(_ value: String) -> AuthorityURL? {
        guard isValid(value),
            value.utf8.starts(with: "https://".utf8),
            let url = AuthorityURL(afterScheme: suffix(of: value, after: "https://")),
            !url.hasQuery,
            !url.hasFragment,
            url.path == "/"
        else { return nil }
        return url
    }

    /// `isPublicNetworkAddress` for IPv4 (`PublicHTTPSFetch.ts:114-132`).
    static func isPublicIPv4(_ address: UInt32) -> Bool {
        let a = address >> 24
        let b = (address >> 16) & 0xff
        return !(a == 0 || a == 10 || a == 127
            || (a == 100 && (64...127).contains(b))
            || (a == 169 && b == 254)
            || (a == 172 && (16...31).contains(b))
            || (a == 192 && (b == 0 || b == 168))
            || (a == 198 && (b == 18 || b == 19 || b == 51))
            || (a == 203 && b == 0)
            || a >= 224)
    }

    /// `isPublicNetworkAddress` for IPv6, including the IPv4 address that a
    /// mapped, compatible, NAT64 or 6to4 address embeds
    /// (`PublicHTTPSFetch.ts:100-112,134-157`).
    static func isPublicIPv6(_ pieces: [UInt16]) -> Bool {
        guard pieces.count == 8 else { return false }
        let p = pieces.map(UInt32.init)
        let firstFiveZero = p[0..<5].allSatisfy { $0 == 0 }
        let compatibleOrMapped = firstFiveZero && (p[5] == 0 || p[5] == 0xffff)
        let nat64 = p[0] == 0x0064 && p[1] == 0xff9b && p[2..<6].allSatisfy { $0 == 0 }
        let sixToFour = p[0] == 0x2002
        if compatibleOrMapped || nat64 || sixToFour {
            let start = sixToFour ? 1 : 6
            if !isPublicIPv4(p[start] << 16 | p[start + 1]) { return false }
        }
        let allZero = p.allSatisfy { $0 == 0 }
        let loopback = p[0..<7].allSatisfy { $0 == 0 } && p[7] == 1
        let globalUnicast = p[0] & 0xe000 == 0x2000
        let special2001 = p[0] == 0x2001 && p[1] < 0x0200
        let documentation = (p[0] == 0x2001 && p[1] == 0x0db8) || p[0] & 0xfff0 == 0x3ff0
        return !(allZero || loopback || !globalUnicast || special2001 || documentation
            || p[0] & 0xfe00 == 0xfc00
            || p[0] & 0xffc0 == 0xfe80
            || p[0] & 0xffc0 == 0xfec0
            || p[0] & 0xff00 == 0xff00)
    }

    private static func suffix(of value: String, after prefix: String) -> Substring {
        let bytes = value.utf8
        let start = bytes.index(bytes.startIndex, offsetBy: prefix.utf8.count)
        return value[start...]
    }

    /// `\p{Cc}`: C0 controls, DEL, and C1 controls.
    private static func isControl(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < 0x20 || (0x7f...0x9f).contains(scalar.value)
    }

    // MARK: js8c+bsvauth+smf

    private static let coordinateNames: Set<String> = ["lat", "long", "freq", "radius"]

    /// `validateJs8URI` in `OverlayAdminTokenTemplate.ts:111-140`.
    private static func isValidJS8(_ value: String) -> Bool {
        guard let questionMark = value.firstIndex(of: "?"),
            value[..<questionMark] == js8Prefix
        else { return false }
        var parameters: [String: [String]] = [:]
        let query = value[value.index(after: questionMark)...]
        for pair in query.split(separator: "&", omittingEmptySubsequences: true) {
            let name: Substring
            let text: Substring
            if let equals = pair.firstIndex(of: "=") {
                name = pair[..<equals]
                text = pair[pair.index(after: equals)...]
            } else {
                name = pair
                text = ""
            }
            parameters[formDecoded(name), default: []].append(formDecoded(text))
        }
        guard Set(parameters.keys).isSubset(of: coordinateNames),
            coordinateNames.allSatisfy({ parameters[$0]?.count == 1 }),
            let latitudeText = parameters["lat"]?.first,
            let longitudeText = parameters["long"]?.first,
            let frequency = parameters["freq"]?.first,
            let radius = parameters["radius"]?.first,
            isExactCoordinate(latitudeText),
            isExactCoordinate(longitudeText),
            let latitude = Double(latitudeText),
            let longitude = Double(longitudeText)
        else { return false }
        return latitude.isFinite && (-90...90).contains(latitude)
            && longitude.isFinite && (-180...180).contains(longitude)
            && positiveMeasurement(frequency) != nil
            && positiveMeasurement(radius) != nil
    }

    /// `^-?(?:0|[1-9]\d*)(?:\.\d+)?$`
    private static func isExactCoordinate(_ text: String) -> Bool {
        var bytes = Array(text.utf8)[...]
        if bytes.first == 0x2d { bytes = bytes.dropFirst() }
        let integer = bytes.prefix(while: isDigit)
        guard !integer.isEmpty, integer.count == 1 || integer.first != 0x30 else { return false }
        let rest = bytes.dropFirst(integer.count)
        if rest.isEmpty { return true }
        guard rest.first == 0x2e else { return false }
        let fraction = rest.dropFirst()
        return !fraction.isEmpty && fraction.allSatisfy(isDigit)
    }

    /// `parsePositiveMeasurement`: `^(\d+(?:\.\d+)?)(?:[a-zA-Z][a-zA-Z0-9/_-]*)?$`
    /// after trimming, with a finite positive number.
    private static func positiveMeasurement(_ text: String) -> Double? {
        let bytes = Array(trimmedJS(text).utf8)[...]
        let integer = bytes.prefix(while: isDigit)
        guard !integer.isEmpty else { return nil }
        var number = Array(integer)
        var rest = bytes.dropFirst(integer.count)
        if rest.first == 0x2e {
            let fraction = rest.dropFirst().prefix(while: isDigit)
            if !fraction.isEmpty {
                number.append(0x2e)
                number.append(contentsOf: fraction)
                rest = rest.dropFirst(1 + fraction.count)
            }
        }
        if let unitStart = rest.first {
            guard isLetter(unitStart),
                rest.dropFirst().allSatisfy({
                    isLetter($0) || isDigit($0) || $0 == 0x2f || $0 == 0x5f || $0 == 0x2d
                })
            else { return nil }
        }
        guard let value = Double(String(decoding: number, as: UTF8.self)),
            value.isFinite, value > 0
        else { return nil }
        return value
    }

    /// `String.prototype.trim`, for the ASCII and Unicode space separators
    /// that can reach it here (controls are already rejected).
    private static func trimmedJS(_ text: String) -> String {
        let scalars = text.unicodeScalars
        let isSpace: (Unicode.Scalar) -> Bool = { $0.properties.isWhitespace || $0 == "\u{FEFF}" }
        guard let first = scalars.firstIndex(where: { !isSpace($0) }),
            let last = scalars.lastIndex(where: { !isSpace($0) })
        else { return "" }
        return String(scalars[first...last])
    }

    /// `application/x-www-form-urlencoded` decoding, as `URLSearchParams` does it.
    private static func formDecoded(_ text: Substring) -> String {
        let input = Array(text.utf8)
        var output: [UInt8] = []
        output.reserveCapacity(input.count)
        var index = 0
        while index < input.count {
            let byte = input[index]
            if byte == 0x2b {
                output.append(0x20)
            } else if byte == 0x25, index + 2 < input.count,
                let high = hexValue(input[index + 1]),
                let low = hexValue(input[index + 2])
            {
                output.append(high << 4 | low)
                index += 2
            } else {
                output.append(byte)
            }
            index += 1
        }
        return String(decoding: output, as: UTF8.self)
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x41...0x46: byte - 0x41 + 10
        case 0x61...0x66: byte - 0x61 + 10
        default: nil
        }
    }

    fileprivate static func isDigit(_ byte: UInt8) -> Bool { (0x30...0x39).contains(byte) }

    fileprivate static func isLetter(_ byte: UInt8) -> Bool {
        (0x41...0x5a).contains(byte) || (0x61...0x7a).contains(byte)
    }
}

/// The parts of a `scheme://authority/path?query#fragment` URI that the
/// advertisement rules read.
private struct AuthorityURL {
    enum HostKind {
        case domain
        case ipv4(UInt32)
        case ipv6([UInt16])
    }

    /// The host as the WHATWG URL parser serializes it: a lowercased domain,
    /// a dotted-quad IPv4 address, or a bracketed canonical IPv6 address.
    let host: String
    let hostKind: HostKind
    let port: Int?
    /// `"/"` when the URI has no path, as for WHATWG special schemes.
    let path: Substring
    /// True when a non-empty query follows `?`.
    let hasQuery: Bool
    /// True when a non-empty fragment follows `#`. WHATWG reports `#` alone
    /// as an empty fragment, which `@bsv/sdk` accepts.
    let hasFragment: Bool

    init?(afterScheme rest: Substring) {
        guard !rest.contains("\\") else { return nil }
        var remainder = rest
        var fragment: Substring = ""
        if let hash = remainder.firstIndex(of: "#") {
            fragment = remainder[remainder.index(after: hash)...]
            remainder = remainder[..<hash]
        }
        var query: Substring = ""
        if let question = remainder.firstIndex(of: "?") {
            query = remainder[remainder.index(after: question)...]
            remainder = remainder[..<question]
        }
        let authority: Substring
        let path: Substring
        if let slash = remainder.firstIndex(of: "/") {
            authority = remainder[..<slash]
            path = remainder[slash...]
        } else {
            authority = remainder
            path = "/"
        }
        guard !authority.isEmpty, !authority.contains("@") else { return nil }

        let hostText: Substring
        let portText: Substring?
        if authority.first == "[" {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            hostText = authority[...close]
            let after = authority[authority.index(after: close)...]
            if after.isEmpty {
                portText = nil
            } else {
                guard after.first == ":" else { return nil }
                portText = after.dropFirst()
            }
            guard let pieces = IPAddressText.ipv6(hostText.dropFirst().dropLast()) else {
                return nil
            }
            self.host = "[" + IPAddressText.serialize(ipv6: pieces) + "]"
            self.hostKind = .ipv6(pieces)
        } else {
            if let colon = authority.firstIndex(of: ":") {
                hostText = authority[..<colon]
                portText = authority[authority.index(after: colon)...]
            } else {
                hostText = authority
                portText = nil
            }
            guard !hostText.isEmpty,
                hostText.utf8.allSatisfy({
                    OverlayAdvertisementURI.isLetter($0) || OverlayAdvertisementURI.isDigit($0)
                        || $0 == 0x2d || $0 == 0x2e || $0 == 0x5f
                })
            else { return nil }
            let domain = hostText.lowercased()
            if IPAddressText.endsInNumber(domain) {
                guard let address = IPAddressText.ipv4(domain) else { return nil }
                self.host = IPAddressText.serialize(ipv4: address)
                self.hostKind = .ipv4(address)
            } else {
                self.host = domain
                self.hostKind = .domain
            }
        }

        var port: Int?
        if let portText, !portText.isEmpty {
            guard portText.utf8.allSatisfy(OverlayAdvertisementURI.isDigit) else { return nil }
            let digits = portText.drop(while: { $0 == "0" })
            guard digits.count <= 5, let value = Int(digits.isEmpty ? "0" : digits),
                value <= 65_535
            else { return nil }
            port = value
        }

        self.port = port
        self.path = path
        self.hasQuery = !query.isEmpty
        self.hasFragment = !fragment.isEmpty
    }

    /// The origin `URL.origin` gives: scheme, host and any non-default port.
    var origin: String {
        if let port, port != 443 {
            return "https://\(host):\(port)"
        }
        return "https://\(host)"
    }

    /// `isAllowedPublicHostname` in `OverlayAdminTokenTemplate.ts:75-79`,
    /// applied to the serialized host as `URL.hostname` gives it.
    var isAllowedPublicHost: Bool {
        host != "localhost"
            && !host.split(separator: ".", omittingEmptySubsequences: false)
                .contains(where: { $0.hasPrefix("xn--") })
    }
}

/// The WHATWG URL Standard's IPv4 and IPv6 host parsers and serializers
/// (sections 3.5 and 3.6), for ASCII host text.
enum IPAddressText {
    /// "Ends in a number": the last non-empty label is all digits or parses
    /// as an IPv4 number. Such a host must then be a valid IPv4 address.
    static func endsInNumber(_ host: String) -> Bool {
        var parts = host.split(separator: ".", omittingEmptySubsequences: false)
        if parts.last == "" {
            guard parts.count > 1 else { return false }
            parts.removeLast()
        }
        guard let last = parts.last else { return false }
        if !last.isEmpty, last.utf8.allSatisfy(OverlayAdvertisementURI.isDigit) { return true }
        return ipv4Number(last) != nil
    }

    /// The IPv4 parser: up to four numbers in decimal, octal (leading `0`)
    /// or hexadecimal (`0x`); the last fills the remaining bytes.
    static func ipv4(_ host: String) -> UInt32? {
        var parts = host.split(separator: ".", omittingEmptySubsequences: false)
        if parts.last == "", parts.count > 1 { parts.removeLast() }
        guard (1...4).contains(parts.count) else { return nil }
        var numbers: [UInt64] = []
        for part in parts {
            guard let number = ipv4Number(part) else { return nil }
            numbers.append(number)
        }
        guard numbers.dropLast().allSatisfy({ $0 <= 255 }) else { return nil }
        let last = numbers[numbers.count - 1]
        guard last < UInt64(1) << (8 * (5 - numbers.count)) else { return nil }
        var address = last
        for (index, number) in numbers.dropLast().enumerated() {
            address += number << (8 * (3 - index))
        }
        return UInt32(address)
    }

    /// The IPv4 number parser. Values that cannot fit in 32 bits are capped
    /// above `UInt32.max`, which the caller then rejects.
    private static func ipv4Number(_ text: Substring) -> UInt64? {
        guard !text.isEmpty else { return nil }
        var digits = text.utf8[...]
        var radix: UInt64 = 10
        if digits.count >= 2, digits.first == 0x30,
            digits[digits.index(after: digits.startIndex)] | 0x20 == 0x78
        {
            digits = digits.dropFirst(2)
            radix = 16
        } else if digits.count >= 2, digits.first == 0x30 {
            digits = digits.dropFirst()
            radix = 8
        }
        var value: UInt64 = 0
        for byte in digits {
            let digit: UInt64
            switch byte {
            case 0x30...0x39: digit = UInt64(byte - 0x30)
            case 0x61...0x66: digit = UInt64(byte - 0x61 + 10)
            case 0x41...0x46: digit = UInt64(byte - 0x41 + 10)
            default: return nil
            }
            guard digit < radix else { return nil }
            value = min(value * radix + digit, UInt64(UInt32.max) + 1)
        }
        return value
    }

    static func serialize(ipv4 address: UInt32) -> String {
        [24, 16, 8, 0].map { String((address >> $0) & 0xff) }.joined(separator: ".")
    }

    /// The IPv6 parser, including a trailing embedded IPv4 address.
    static func ipv6(_ text: Substring) -> [UInt16]? {
        let input = Array(text.utf8)
        var address = [UInt16](repeating: 0, count: 8)
        var pieceIndex = 0
        var compress: Int?
        var pointer = 0
        func at(_ index: Int) -> UInt8? { index < input.count ? input[index] : nil }

        if at(pointer) == 0x3a {
            guard at(pointer + 1) == 0x3a else { return nil }
            pointer += 2
            pieceIndex += 1
            compress = pieceIndex
        }
        while let current = at(pointer) {
            guard pieceIndex < 8 else { return nil }
            if current == 0x3a {
                guard compress == nil else { return nil }
                pointer += 1
                pieceIndex += 1
                compress = pieceIndex
                continue
            }
            var value: UInt32 = 0
            var length = 0
            while length < 4, let byte = at(pointer), let digit = hexDigit(byte) {
                value = value * 16 + UInt32(digit)
                pointer += 1
                length += 1
            }
            if at(pointer) == 0x2e {
                guard length > 0, pieceIndex <= 6 else { return nil }
                pointer -= length
                var numbersSeen = 0
                while at(pointer) != nil {
                    var piece: UInt32?
                    if numbersSeen > 0 {
                        guard at(pointer) == 0x2e, numbersSeen < 4 else { return nil }
                        pointer += 1
                    }
                    guard let first = at(pointer), OverlayAdvertisementURI.isDigit(first) else {
                        return nil
                    }
                    while let byte = at(pointer), OverlayAdvertisementURI.isDigit(byte) {
                        let number = UInt32(byte - 0x30)
                        if let existing = piece {
                            guard existing != 0 else { return nil }
                            piece = existing * 10 + number
                        } else {
                            piece = number
                        }
                        guard piece! <= 255 else { return nil }
                        pointer += 1
                    }
                    address[pieceIndex] = address[pieceIndex] &* 0x100 &+ UInt16(piece!)
                    numbersSeen += 1
                    if numbersSeen == 2 || numbersSeen == 4 { pieceIndex += 1 }
                }
                guard numbersSeen == 4 else { return nil }
                break
            } else if at(pointer) == 0x3a {
                pointer += 1
                guard at(pointer) != nil else { return nil }
            } else if at(pointer) != nil {
                return nil
            }
            address[pieceIndex] = UInt16(value)
            pieceIndex += 1
        }
        if let compress {
            var swaps = pieceIndex - compress
            pieceIndex = 7
            while pieceIndex != 0, swaps > 0 {
                address.swapAt(pieceIndex, compress + swaps - 1)
                pieceIndex -= 1
                swaps -= 1
            }
        } else if pieceIndex != 8 {
            return nil
        }
        return address
    }

    /// The IPv6 serializer: lowercase hex, the first longest run of two or
    /// more zero pieces written as `::`.
    static func serialize(ipv6 address: [UInt16]) -> String {
        var compress: Int?
        var bestLength = 1
        var index = 0
        while index < 8 {
            guard address[index] == 0 else {
                index += 1
                continue
            }
            var end = index
            while end < 8, address[end] == 0 { end += 1 }
            if end - index > bestLength {
                bestLength = end - index
                compress = index
            }
            index = end
        }
        var output = ""
        var ignoreZero = false
        for pieceIndex in 0..<8 {
            if ignoreZero, address[pieceIndex] == 0 { continue }
            ignoreZero = false
            if compress == pieceIndex {
                output += pieceIndex == 0 ? "::" : ":"
                ignoreZero = true
                continue
            }
            output += String(address[pieceIndex], radix: 16)
            if pieceIndex != 7 { output += ":" }
        }
        return output
    }

    private static func hexDigit(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x61...0x66: byte - 0x61 + 10
        case 0x41...0x46: byte - 0x41 + 10
        default: nil
        }
    }
}
