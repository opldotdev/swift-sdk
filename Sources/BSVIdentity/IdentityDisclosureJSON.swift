import BSVCore
import BSVWallet

enum IdentityDisclosureJSON {
    static func encode(
        certificate: Certificate,
        keyring: [CertificateFieldName: CertificateCiphertext],
        limits: IdentityLimits
    ) throws -> [UInt8] {
        guard let signature = certificate.signature else {
            throw IdentityError.certificateVerificationFailed
        }
        var writer = IdentityJSONWriter(maximumByteCount: limits.maximumDisclosureJSONByteCount)
        try writer.appendASCII("{\"certifier\":")
        try writer.appendString(Hex.encode(certificate.certifier.compressedBytes))
        try writer.appendASCII(",\"fields\":")
        try writer.appendMap(certificate.fields)
        try writer.appendASCII(",\"keyring\":")
        try writer.appendMap(keyring)
        try writer.appendASCII(",\"revocationOutpoint\":")
        try writer.appendString(certificate.revocationOutpoint.description)
        try writer.appendASCII(",\"serialNumber\":")
        try writer.appendString(certificate.serialNumber.base64)
        try writer.appendASCII(",\"signature\":")
        try writer.appendString(Hex.encode(signature.derBytes))
        try writer.appendASCII(",\"subject\":")
        try writer.appendString(Hex.encode(certificate.subject.compressedBytes))
        try writer.appendASCII(",\"type\":")
        try writer.appendString(certificate.type.base64)
        try writer.appendByte(0x7d)
        return writer.bytes
    }
}

private struct IdentityJSONWriter {
    private(set) var bytes: [UInt8] = []
    private let maximumByteCount: Int

    init(maximumByteCount: Int) {
        self.maximumByteCount = maximumByteCount
        bytes.reserveCapacity(min(maximumByteCount, 4_096))
    }

    mutating func appendMap(
        _ values: [CertificateFieldName: CertificateCiphertext]
    ) throws {
        try appendByte(0x7b)
        for (index, name) in values.keys.sorted().enumerated() {
            if index != 0 { try appendByte(0x2c) }
            try appendString(name.value)
            try appendByte(0x3a)
            guard let value = values[name] else { throw IdentityError.requestedFieldIsAbsent }
            try appendBase64(value.bytes)
        }
        try appendByte(0x7d)
    }

    mutating func appendString(_ value: String) throws {
        try appendByte(0x22)
        let source = value.utf8
        var index = source.startIndex
        while index != source.endIndex {
            let byte = source[index]
            switch byte {
            case 0x22: try appendASCII("\\\"")
            case 0x5c: try appendASCII("\\\\")
            case 0x08: try appendASCII("\\b")
            case 0x0c: try appendASCII("\\f")
            case 0x0a: try appendASCII("\\n")
            case 0x0d: try appendASCII("\\r")
            case 0x09: try appendASCII("\\t")
            case 0x00...0x1f:
                try appendASCII("\\u00")
                try appendByte(Self.hex[Int(byte >> 4)])
                try appendByte(Self.hex[Int(byte & 0x0f)])
            case 0x3c: try appendASCII("\\u003c")
            case 0x3e: try appendASCII("\\u003e")
            case 0x26: try appendASCII("\\u0026")
            case 0xe2:
                let next = source.index(after: index)
                if next != source.endIndex {
                    let last = source.index(after: next)
                    if last != source.endIndex,
                       source[next] == 0x80,
                       source[last] == 0xa8 || source[last] == 0xa9 {
                        try appendASCII(source[last] == 0xa8 ? "\\u2028" : "\\u2029")
                        index = last
                    } else {
                        try appendByte(byte)
                    }
                } else {
                    try appendByte(byte)
                }
            default: try appendByte(byte)
            }
            index = source.index(after: index)
        }
        try appendByte(0x22)
    }

    mutating func appendBase64(_ source: [UInt8]) throws {
        let (withPadding, additionOverflow) = source.count.addingReportingOverflow(2)
        let groups = withPadding / 3
        let (encodedCount, multiplicationOverflow) = groups.multipliedReportingOverflow(by: 4)
        guard !additionOverflow, !multiplicationOverflow else {
            throw IdentityError.sizeOverflow
        }
        let (quotedCount, quoteOverflow) = encodedCount.addingReportingOverflow(2)
        guard !quoteOverflow else { throw IdentityError.sizeOverflow }
        try requireSpace(quotedCount)
        bytes.append(0x22)
        var index = 0
        while index + 3 <= source.count {
            let value = UInt32(source[index]) << 16
                | UInt32(source[index + 1]) << 8
                | UInt32(source[index + 2])
            bytes.append(Self.base64[Int((value >> 18) & 0x3f)])
            bytes.append(Self.base64[Int((value >> 12) & 0x3f)])
            bytes.append(Self.base64[Int((value >> 6) & 0x3f)])
            bytes.append(Self.base64[Int(value & 0x3f)])
            index += 3
        }
        let remaining = source.count - index
        if remaining == 1 {
            let value = UInt32(source[index]) << 16
            bytes.append(Self.base64[Int((value >> 18) & 0x3f)])
            bytes.append(Self.base64[Int((value >> 12) & 0x3f)])
            bytes.append(0x3d)
            bytes.append(0x3d)
        } else if remaining == 2 {
            let value = UInt32(source[index]) << 16 | UInt32(source[index + 1]) << 8
            bytes.append(Self.base64[Int((value >> 18) & 0x3f)])
            bytes.append(Self.base64[Int((value >> 12) & 0x3f)])
            bytes.append(Self.base64[Int((value >> 6) & 0x3f)])
            bytes.append(0x3d)
        }
        bytes.append(0x22)
    }

    mutating func appendASCII(_ value: StaticString) throws {
        let count = value.utf8CodeUnitCount
        try requireSpace(count)
        value.withUTF8Buffer { bytes.append(contentsOf: $0) }
    }

    mutating func appendByte(_ byte: UInt8) throws {
        try requireSpace(1)
        bytes.append(byte)
    }

    private func requireSpace(_ additional: Int) throws {
        let (actual, overflow) = bytes.count.addingReportingOverflow(additional)
        guard !overflow else { throw IdentityError.sizeOverflow }
        guard actual <= maximumByteCount else {
            throw IdentityError.disclosureJSONTooLarge(
                actual: actual,
                maximum: maximumByteCount
            )
        }
    }

    private static let hex = Array("0123456789abcdef".utf8)
    private static let base64 = Array(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8
    )
}
