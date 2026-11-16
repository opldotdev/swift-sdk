/// The URI rules `@bsv/sdk` applies to the host field of a SHIP or SLAP
/// advertisement (`overlay-tools/OverlayAdminTokenTemplate.ts:30-158`).
///
/// `@bsv/sdk` parses these URIs with the WHATWG URL parser. This port reads
/// the same ASCII forms and normalizes the host the same way (lowercase, no
/// default port). It is stricter only on forms no advertisement writer emits:
/// any `@` in the authority, a backslash, non-ASCII host text, dot segments,
/// and extra slashes after the scheme.
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
    /// lowercase host, no default port, no trailing slash. Returns nil for a
    /// URI that is not an `https://` origin with path `""` or `"/"`.
    static func httpsOrigin(_ value: String) -> String? {
        guard isValid(value),
            value.utf8.starts(with: "https://".utf8),
            let url = AuthorityURL(afterScheme: suffix(of: value, after: "https://")),
            !url.hasQuery,
            !url.hasFragment,
            url.path == "/"
        else { return nil }
        if let port = url.port, port != 443 {
            return "https://\(url.host):\(port)"
        }
        return "https://\(url.host)"
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
    /// Lowercased host, with brackets for IPv6.
    let host: String
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
            let inner = hostText.dropFirst().dropLast()
            guard !inner.isEmpty,
                inner.utf8.allSatisfy({
                    OverlayAdvertisementURI.isDigit($0) || (0x61...0x66).contains($0)
                        || (0x41...0x46).contains($0) || $0 == 0x3a || $0 == 0x2e
                })
            else { return nil }
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

        self.host = hostText.lowercased()
        self.port = port
        self.path = path
        self.hasQuery = !query.isEmpty
        self.hasFragment = !fragment.isEmpty
    }

    /// `isAllowedPublicHostname` in `OverlayAdminTokenTemplate.ts:75-79`.
    var isAllowedPublicHost: Bool {
        host != "localhost"
            && !host.split(separator: ".", omittingEmptySubsequences: false)
                .contains(where: { $0.hasPrefix("xn--") })
    }
}
