import BSVCore
import BSVWallet

enum AuthCertificateJSON {
    static func request(
        _ request: AuthRequestedCertificateSet,
        limits: AuthLimits
    ) throws -> [UInt8] {
        _ = try AuthRequestedCertificateSet(
            certifiers: request.certifiers,
            certificateTypes: request.certificateTypes,
            limits: limits
        )
        var writer = AuthCertificateJSONWriter(maximumByteCount: maximumJSONBytes(limits))
        try writer.append(#"{"certifiers":["#)
        for index in request.certifiers.indices {
            if index > 0 { try writer.append(",") }
            try writer.appendJSONString(Hex.encode(request.certifiers[index].compressedBytes))
        }
        try writer.append(#"],"types":{"#)
        let types = request.certificateTypes.keys.sorted {
            $0.base64.utf8.lexicographicallyPrecedes($1.base64.utf8)
        }
        for index in types.indices {
            if index > 0 { try writer.append(",") }
            let type = types[index]
            try writer.appendJSONString(type.base64)
            try writer.append(":[")
            guard let fields = request.certificateTypes[type] else {
                throw AuthError.invalidCertificateRequest
            }
            for fieldIndex in fields.indices {
                if fieldIndex > 0 { try writer.append(",") }
                try writer.appendJSONString(fields[fieldIndex].value)
            }
            try writer.append("]")
        }
        try writer.append("}}")
        return writer.bytes
    }

    static func response(
        _ certificates: [VerifiableCertificate],
        limits: AuthLimits
    ) throws -> [UInt8] {
        guard !certificates.isEmpty,
            certificates.count <= limits.maximumCertificateCount
        else { throw AuthError.certificateValidationFailed }

        var aggregate = 0
        for verifiable in certificates {
            let count = try verifiable.binary(limits: limits.certificateLimits).count
            let (next, overflow) = aggregate.addingReportingOverflow(count)
            guard !overflow, next <= limits.maximumCertificateAggregateBytes else {
                throw AuthError.resourceLimit
            }
            aggregate = next
        }

        var writer = AuthCertificateJSONWriter(maximumByteCount: maximumJSONBytes(limits))
        try writer.append("[")
        for index in certificates.indices {
            if index > 0 { try writer.append(",") }
            try append(certificates[index], to: &writer, limits: limits)
        }
        try writer.append("]")
        return writer.bytes
    }

    private static func append(
        _ verifiable: VerifiableCertificate,
        to writer: inout AuthCertificateJSONWriter,
        limits: AuthLimits
    ) throws {
        let certificate = verifiable.certificate
        guard let signature = certificate.signature,
            !verifiable.keyring.entries.isEmpty,
            verifiable.keyring.entries.count <= limits.maximumCertificateFieldCount
        else { throw AuthError.certificateValidationFailed }

        try writer.append(#"{"type":"#)
        try writer.appendJSONString(certificate.type.base64)
        try writer.append(#","serialNumber":"#)
        try writer.appendJSONString(certificate.serialNumber.base64)
        try writer.append(#","subject":"#)
        try writer.appendJSONString(Hex.encode(certificate.subject.compressedBytes))
        try writer.append(#","certifier":"#)
        try writer.appendJSONString(Hex.encode(certificate.certifier.compressedBytes))
        try writer.append(#","revocationOutpoint":"#)
        try writer.appendJSONString(certificate.revocationOutpoint.description)
        try writer.append(#","fields":{"#)
        try appendMap(certificate.fields, to: &writer) { $0.base64 }
        try writer.append(#"},"signature":"#)
        try writer.appendJSONString(Hex.encode(signature.derBytes))
        try writer.append(#","keyring":{"#)
        try appendMap(verifiable.keyring.entries, to: &writer) { $0.base64 }
        try writer.append("}}")
    }

    private static func appendMap<Value>(
        _ values: [CertificateFieldName: Value],
        to writer: inout AuthCertificateJSONWriter,
        value: (Value) -> String
    ) throws {
        let names = values.keys.sorted()
        for index in names.indices {
            if index > 0 { try writer.append(",") }
            let name = names[index]
            guard let item = values[name] else { throw AuthError.invalidMessage }
            try writer.appendJSONString(name.value)
            try writer.append(":")
            try writer.appendJSONString(value(item))
        }
    }

    private static func maximumJSONBytes(_ limits: AuthLimits) -> Int {
        min(limits.maximumJSONBytes, limits.maximumCertificateAggregateBytes)
    }
}

private struct AuthCertificateJSONWriter {
    private(set) var bytes: [UInt8] = []
    private let maximumByteCount: Int

    init(maximumByteCount: Int) {
        self.maximumByteCount = maximumByteCount
        bytes.reserveCapacity(min(maximumByteCount, 4_096))
    }

    mutating func append(_ text: String) throws {
        try append(Array(text.utf8))
    }

    mutating func appendJSONString(_ text: String) throws {
        try append([0x22])
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 0x08: try append(#"\b"#)
            case 0x09: try append(#"\t"#)
            case 0x0a: try append(#"\n"#)
            case 0x0c: try append(#"\f"#)
            case 0x0d: try append(#"\r"#)
            case 0x22: try append(#"\""#)
            case 0x5c: try append(#"\\"#)
            case 0x00...0x07, 0x0b, 0x0e...0x1f, 0x26, 0x3c, 0x3e, 0x2028, 0x2029:
                try appendUnicodeEscape(scalar.value)
            default:
                try append(Array(String(scalar).utf8))
            }
        }
        try append([0x22])
    }

    private mutating func appendUnicodeEscape(_ value: UInt32) throws {
        let digits = Array("0123456789abcdef".utf8)
        guard value <= 0xffff else { throw AuthError.invalidMessage }
        try append([
            0x5c, 0x75,
            digits[Int((value >> 12) & 0x0f)],
            digits[Int((value >> 8) & 0x0f)],
            digits[Int((value >> 4) & 0x0f)],
            digits[Int(value & 0x0f)],
        ])
    }

    private mutating func append(_ value: [UInt8]) throws {
        let (next, overflow) = bytes.count.addingReportingOverflow(value.count)
        guard !overflow, next <= maximumByteCount else { throw AuthError.resourceLimit }
        bytes.append(contentsOf: value)
    }
}
