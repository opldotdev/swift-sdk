import BSVCore
import BSVWallet

/// The JSON text that BRC-103 certificate messages sign.
///
/// `@bsv/sdk` 4.1.1 signs `JSON.stringify(requestedCertificates)` and
/// `JSON.stringify(certificates)` (`Peer.ts:453`, `Peer.ts:1142`) and verifies
/// `JSON.stringify` of the received objects (`Peer.ts:1070`, `Peer.ts:1205`).
/// The signed text therefore follows the sender's member order and
/// `JSON.stringify` escaping. This SDK writes the wire JSON from the same bytes
/// it signs, so a TypeScript verifier reproduces them exactly.
enum AuthCertificateJSON {
    /// Member order of a certificate rebuilt by `Peer.ts:341-357`.
    static let certificateMemberOrder = [
        "type", "serialNumber", "subject", "certifier", "revocationOutpoint", "fields",
        "signature", "keyring",
    ]

    static func request(
        _ request: AuthRequestedCertificateSet,
        limits: AuthLimits
    ) throws -> [UInt8] {
        _ = try AuthRequestedCertificateSet(
            certifiers: request.certifiers,
            certificateTypes: request.certificateTypes,
            limits: limits
        )
        var writer = AuthJSONWriter(maximumByteCount: maximumJSONBytes(limits))
        try writer.append(#"{"certifiers":["#)
        for index in request.certifiers.indices {
            if index > 0 { try writer.append(",") }
            try writer.appendString(Hex.encode(request.certifiers[index].compressedBytes))
        }
        try writer.append(#"],"types":{"#)
        var typesByText: [String: [CertificateFieldName]] = [:]
        for (type, fields) in request.certificateTypes { typesByText[type.base64] = fields }
        let names = AuthJSONWriter.canonicalOrder(Array(typesByText.keys))
        for index in names.indices {
            if index > 0 { try writer.append(",") }
            try writer.appendString(names[index])
            try writer.append(":[")
            guard let fields = typesByText[names[index]] else {
                throw AuthError.invalidCertificateRequest
            }
            for fieldIndex in fields.indices {
                if fieldIndex > 0 { try writer.append(",") }
                try writer.appendString(fields[fieldIndex].value)
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
        guard certificates.count <= limits.maximumCertificateCount else {
            throw AuthError.certificateValidationFailed
        }

        var aggregate = 0
        for verifiable in certificates {
            let count = try verifiable.binary(limits: limits.certificateLimits).count
            let (next, overflow) = aggregate.addingReportingOverflow(count)
            guard !overflow, next <= limits.maximumCertificateAggregateBytes else {
                throw AuthError.resourceLimit
            }
            aggregate = next
        }

        var writer = AuthJSONWriter(maximumByteCount: maximumJSONBytes(limits))
        try writer.append("[")
        for index in certificates.indices {
            if index > 0 { try writer.append(",") }
            try append(certificates[index], to: &writer, limits: limits)
        }
        try writer.append("]")
        return writer.bytes
    }

    /// `JSON.stringify` of a received `requestedCertificates` value, as
    /// `Peer.ts:1070` computes it.
    static func receivedRequest(_ value: AuthJSONValue, limits: AuthLimits) throws -> [UInt8] {
        var writer = AuthJSONWriter(maximumByteCount: maximumJSONBytes(limits))
        try writer.appendValue(value)
        return writer.bytes
    }

    /// `JSON.stringify` of received certificates after `Peer.ts:341-357`
    /// rebuilds each one in `certificateMemberOrder`. `fields` and `keyring`
    /// keep their received member order.
    static func receivedResponse(_ value: AuthJSONValue, limits: AuthLimits) throws -> [UInt8] {
        guard case .array(let certificates) = value else {
            throw AuthError.certificateValidationFailed
        }
        var writer = AuthJSONWriter(maximumByteCount: maximumJSONBytes(limits))
        try writer.append("[")
        for index in certificates.indices {
            if index > 0 { try writer.append(",") }
            guard case .object(let members) = certificates[index] else {
                throw AuthError.certificateValidationFailed
            }
            try writer.append("{")
            var written = 0
            for name in certificateMemberOrder {
                guard let member = members.first(where: { $0.key == name }) else { continue }
                if written > 0 { try writer.append(",") }
                try writer.appendString(name)
                try writer.append(":")
                try writer.appendValue(member.value)
                written += 1
            }
            try writer.append("}")
        }
        try writer.append("]")
        return writer.bytes
    }

    private static func append(
        _ verifiable: VerifiableCertificate,
        to writer: inout AuthJSONWriter,
        limits: AuthLimits
    ) throws {
        let certificate = verifiable.certificate
        guard let signature = certificate.signature,
            !verifiable.keyring.entries.isEmpty,
            verifiable.keyring.entries.count <= limits.maximumCertificateFieldCount
        else { throw AuthError.certificateValidationFailed }

        try writer.append(#"{"type":"#)
        try writer.appendString(certificate.type.base64)
        try writer.append(#","serialNumber":"#)
        try writer.appendString(certificate.serialNumber.base64)
        try writer.append(#","subject":"#)
        try writer.appendString(Hex.encode(certificate.subject.compressedBytes))
        try writer.append(#","certifier":"#)
        try writer.appendString(Hex.encode(certificate.certifier.compressedBytes))
        try writer.append(#","revocationOutpoint":"#)
        try writer.appendString(certificate.revocationOutpoint.description)
        try writer.append(#","fields":{"#)
        try appendMap(certificate.fields, to: &writer) { $0.base64 }
        try writer.append(#"},"signature":"#)
        try writer.appendString(Hex.encode(signature.derBytes))
        try writer.append(#","keyring":{"#)
        try appendMap(verifiable.keyring.entries, to: &writer) { $0.base64 }
        try writer.append("}}")
    }

    private static func appendMap<Value>(
        _ values: [CertificateFieldName: Value],
        to writer: inout AuthJSONWriter,
        value: (Value) -> String
    ) throws {
        var byText: [String: Value] = [:]
        for (name, item) in values { byText[name.value] = item }
        guard byText.count == values.count else { throw AuthError.invalidMessage }
        let names = AuthJSONWriter.canonicalOrder(Array(byText.keys))
        for index in names.indices {
            if index > 0 { try writer.append(",") }
            guard let item = byText[names[index]] else { throw AuthError.invalidMessage }
            try writer.appendString(names[index])
            try writer.append(":")
            try writer.appendString(value(item))
        }
    }

    private static func maximumJSONBytes(_ limits: AuthLimits) -> Int {
        min(limits.maximumJSONBytes, limits.maximumCertificateAggregateBytes)
    }
}
