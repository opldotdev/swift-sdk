import Foundation

/// Produces a bounded diagnostic excerpt from untrusted provider bytes.
package func sanitizedProviderText(
    _ body: Data,
    redacting secrets: [String] = [],
    redactingFieldNames fieldNames: [String] = [],
    redactingLongHexRuns shouldRedactLongHexRuns: Bool = true,
    maximumUTF8ByteCount: Int = 1_024
) -> String? {
    sanitizedProviderText(
        String(decoding: body, as: UTF8.self),
        redacting: secrets,
        redactingFieldNames: fieldNames,
        redactingLongHexRuns: shouldRedactLongHexRuns,
        maximumUTF8ByteCount: maximumUTF8ByteCount
    )
}

/// Produces bounded display text from an untrusted provider string.
package func sanitizedProviderText(
    _ text: String,
    redacting secrets: [String] = [],
    redactingFieldNames fieldNames: [String] = [],
    redactingLongHexRuns shouldRedactLongHexRuns: Bool = true,
    maximumUTF8ByteCount: Int = 1_024
) -> String? {
    guard maximumUTF8ByteCount > 0 else { return nil }

    var sanitized = ""
    for scalar in text.unicodeScalars {
        let category = scalar.properties.generalCategory
        guard category != .control, category != .format else { continue }
        sanitized.unicodeScalars.append(scalar)
    }
    guard !sanitized.isEmpty else { return nil }

    for fieldName in fieldNames where !fieldName.isEmpty {
        sanitized = sanitized.replacingOccurrences(
            of: fieldName,
            with: "[redacted-field]",
            options: .caseInsensitive
        )
    }
    for secret in secrets where !secret.isEmpty {
        sanitized = sanitized.replacingOccurrences(
            of: secret,
            with: "[redacted]",
            options: .caseInsensitive
        )
    }

    let redacted = shouldRedactLongHexRuns
        ? redactingLongHexRuns(sanitized)
        : sanitized
    return boundedProviderText(
        redacted,
        maximumUTF8ByteCount: maximumUTF8ByteCount
    )
}

private func redactingLongHexRuns(_ text: String) -> String {
    var result = ""
    var hexRun = ""

    func appendHexRun() {
        result += hexRun.utf8.count >= 8 ? "[redacted]" : hexRun
        hexRun.removeAll(keepingCapacity: true)
    }

    for scalar in text.unicodeScalars {
        if isASCIIHex(scalar.value) {
            hexRun.unicodeScalars.append(scalar)
        } else {
            appendHexRun()
            result.unicodeScalars.append(scalar)
        }
    }
    appendHexRun()
    return result
}

private func isASCIIHex(_ value: UInt32) -> Bool {
    (48...57).contains(value)
        || (65...70).contains(value)
        || (97...102).contains(value)
}

private func boundedProviderText(
    _ text: String,
    maximumUTF8ByteCount: Int
) -> String? {
    var result = ""
    var byteCount = 0
    for scalar in text.unicodeScalars {
        let scalarByteCount = scalar.utf8.count
        guard byteCount + scalarByteCount <= maximumUTF8ByteCount else { break }
        result.unicodeScalars.append(scalar)
        byteCount += scalarByteCount
    }
    return result.isEmpty ? nil : result
}
