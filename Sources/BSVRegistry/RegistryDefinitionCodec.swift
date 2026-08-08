import BSVCore
import BSVKeys
import BSVScript
import BSVWallet
import Foundation

/// Strict codec for the pinned Go registry's `beforeCompatibility` PushDrop fields.
///
/// All decoded text is bounded and UTF-8 validated before it is indexed or parsed.
/// Embedded JSON must be the codec's canonical byte representation, preventing duplicate
/// keys, ambiguous whitespace, and map-order-dependent registry records.
public enum RegistryDefinitionCodec: Sendable {
    public static func fields(
        for definition: RegistryDefinition,
        limits: RegistryLimits = .standard
    ) throws -> [[UInt8]] {
        let fields: [String]
        switch definition {
        case .basket(let basket):
            fields = [
                basket.basketID,
                basket.metadata.name,
                basket.metadata.iconURL,
                basket.metadata.description,
                basket.metadata.documentationURL,
                basket.registryOperator.compressedHex,
            ]
        case .protocolDefinition(let protocolDefinition):
            fields = [
                canonicalProtocolID(protocolDefinition.protocolID),
                protocolDefinition.metadata.name,
                protocolDefinition.metadata.iconURL,
                protocolDefinition.metadata.description,
                protocolDefinition.metadata.documentationURL,
                protocolDefinition.registryOperator.compressedHex,
            ]
        case .certificate(let certificate):
            fields = [
                certificate.type,
                certificate.metadata.name,
                certificate.metadata.iconURL,
                certificate.metadata.description,
                certificate.metadata.documentationURL,
                canonicalCertificateFields(certificate.fields),
                certificate.registryOperator.compressedHex,
            ]
        }
        return try checkedFields(fields, limits: limits)
    }

    public static func lockingScript(
        for definition: RegistryDefinition,
        publicKey: PublicKey,
        limits: RegistryLimits = .standard
    ) throws -> Script {
        let encodedFields = try fields(for: definition, limits: limits)
        do {
            return try PushDrop.lockingScript(
                fields: encodedFields,
                publicKey: publicKey,
                lockPosition: .beforeCompatibility,
                limits: limits.pushDropLimits
            )
        } catch {
            throw RegistryError.pushDropFailure
        }
    }

    public static func decode(
        _ script: Script,
        kind: RegistryDefinitionKind,
        limits: RegistryLimits = .standard
    ) throws -> RegistryDefinition {
        let decoded: PushDropDecoded
        do {
            decoded = try PushDrop.decode(
                script,
                lockPosition: .beforeCompatibility,
                limits: limits.pushDropLimits
            )
        } catch {
            throw RegistryError.pushDropFailure
        }
        return try definition(kind: kind, fields: decoded.fields, limits: limits)
    }

    public static func definition(
        kind: RegistryDefinitionKind,
        fields: [[UInt8]],
        limits: RegistryLimits = .standard
    ) throws -> RegistryDefinition {
        let expectedCount = kind == .certificate ? 7 : 6
        guard fields.count == expectedCount else {
            throw RegistryError.unexpectedFieldCount(
                kind: kind, actual: fields.count, expected: expectedCount)
        }
        let text = try checkedTextFields(fields, limits: limits)
        switch kind {
        case .basket:
            return .basket(
                try RegistryBasketDefinition(
                    basketID: text[0],
                    metadata: try RegistryMetadata(
                        name: text[1], iconURL: text[2], description: text[3],
                        documentationURL: text[4],
                        limits: limits),
                    registryOperator: try RegistryOperator(compressedHex: text[5]),
                    limits: limits
                ))
        case .protocol:
            let protocolID = try decodedProtocolID(text[0], limits: limits)
            return .protocolDefinition(
                try RegistryProtocolDefinition(
                    protocolID: protocolID,
                    metadata: try RegistryMetadata(
                        name: text[1], iconURL: text[2], description: text[3],
                        documentationURL: text[4],
                        limits: limits),
                    registryOperator: try RegistryOperator(compressedHex: text[5]),
                    limits: limits
                ))
        case .certificate:
            return .certificate(
                try RegistryCertificateDefinition(
                    type: text[0],
                    metadata: try RegistryMetadata(
                        name: text[1], iconURL: text[2], description: text[3],
                        documentationURL: text[4],
                        limits: limits),
                    fields: try decodedCertificateFields(text[5], limits: limits),
                    registryOperator: try RegistryOperator(compressedHex: text[6]),
                    limits: limits
                ))
        }
    }

    private static func checkedFields(_ fields: [String], limits: RegistryLimits) throws
        -> [[UInt8]]
    {
        guard fields.count <= limits.pushDropLimits.maximumFieldCount else {
            throw RegistryError.pushDropFailure
        }
        var total = 0
        var result: [[UInt8]] = []
        result.reserveCapacity(fields.count)
        for field in fields {
            try registryText(field, field: "definitionField", limits: limits)
            let bytes = Array(field.utf8)
            let (next, overflow) = total.addingReportingOverflow(bytes.count)
            guard !overflow else {
                throw RegistryError.aggregateTooLarge(
                    actual: .max, maximum: limits.maximumDefinitionAggregateUTF8ByteCount)
            }
            total = next
            guard total <= limits.maximumDefinitionAggregateUTF8ByteCount else {
                throw RegistryError.aggregateTooLarge(
                    actual: total, maximum: limits.maximumDefinitionAggregateUTF8ByteCount)
            }
            result.append(bytes)
        }
        return result
    }

    private static func checkedTextFields(_ fields: [[UInt8]], limits: RegistryLimits) throws
        -> [String]
    {
        var total = 0
        var text: [String] = []
        text.reserveCapacity(fields.count)
        for field in fields {
            let canonicalField = field == [0] ? [] : field
            guard canonicalField.count <= limits.maximumDefinitionTextUTF8ByteCount else {
                throw RegistryError.textTooLong(
                    field: "definitionField", actual: canonicalField.count,
                    maximum: limits.maximumDefinitionTextUTF8ByteCount)
            }
            let (next, overflow) = total.addingReportingOverflow(canonicalField.count)
            guard !overflow else {
                throw RegistryError.aggregateTooLarge(
                    actual: .max, maximum: limits.maximumDefinitionAggregateUTF8ByteCount)
            }
            total = next
            guard total <= limits.maximumDefinitionAggregateUTF8ByteCount else {
                throw RegistryError.aggregateTooLarge(
                    actual: total, maximum: limits.maximumDefinitionAggregateUTF8ByteCount)
            }
            guard let value = String(bytes: canonicalField, encoding: .utf8) else {
                throw RegistryError.invalidText(field: "definitionField")
            }
            text.append(value)
        }
        return text
    }

    private static func canonicalProtocolID(_ value: WalletProtocolID) -> String {
        "[\(value.securityLevel.rawValue),\(jsonString(value.name))]"
    }

    private static func decodedProtocolID(
        _ source: String,
        limits: RegistryLimits
    ) throws -> WalletProtocolID {
        guard let data = source.data(using: .utf8),
            data.count <= limits.maximumDefinitionTextUTF8ByteCount
        else {
            throw RegistryError.malformedEmbeddedJSON(field: "protocolID")
        }
        let value: WalletProtocolID
        do {
            value = try JSONDecoder().decode(WalletProtocolID.self, from: data)
        } catch {
            throw RegistryError.malformedEmbeddedJSON(field: "protocolID")
        }
        guard canonicalProtocolID(value) == source else {
            throw RegistryError.nonCanonicalEmbeddedJSON(field: "protocolID")
        }
        return value
    }

    private static func canonicalCertificateFields(
        _ fields: [String: RegistryCertificateFieldDescriptor]
    ) -> String {
        let names = fields.keys.sorted(by: registryUTF8LessThan)
        let body = names.compactMap { name -> String? in
            guard let descriptor = fields[name] else { return nil }
            return
                "\(jsonString(name)):{\"friendlyName\":\(jsonString(descriptor.friendlyName)),\"description\":\(jsonString(descriptor.description)),\"type\":\(jsonString(descriptor.type.rawValue)),\"fieldIcon\":\(jsonString(descriptor.fieldIcon))}"
        }.joined(separator: ",")
        return "{\(body)}"
    }

    private static func decodedCertificateFields(
        _ source: String,
        limits: RegistryLimits
    ) throws -> [String: RegistryCertificateFieldDescriptor] {
        guard let data = source.data(using: .utf8),
            data.count <= limits.maximumDefinitionTextUTF8ByteCount
        else {
            throw RegistryError.malformedEmbeddedJSON(field: "certificateFields")
        }
        let wire: [String: CertificateFieldWire]
        do {
            wire = try JSONDecoder().decode([String: CertificateFieldWire].self, from: data)
        } catch {
            throw RegistryError.malformedEmbeddedJSON(field: "certificateFields")
        }
        guard wire.count <= limits.maximumCertificateFieldCount else {
            throw RegistryError.collectionCountExceedsLimit(
                collection: "certificateFields", actual: wire.count,
                maximum: limits.maximumCertificateFieldCount)
        }
        var fields: [String: RegistryCertificateFieldDescriptor] = [:]
        fields.reserveCapacity(wire.count)
        for (name, descriptor) in wire {
            guard let type = RegistryCertificateFieldType(rawValue: descriptor.type) else {
                throw RegistryError.invalidCertificateFieldType
            }
            try registryFieldName(name, limits: limits)
            fields[name] = try RegistryCertificateFieldDescriptor(
                friendlyName: descriptor.friendlyName,
                description: descriptor.description,
                type: type,
                fieldIcon: descriptor.fieldIcon,
                limits: limits
            )
        }
        guard canonicalCertificateFields(fields) == source else {
            throw RegistryError.nonCanonicalEmbeddedJSON(field: "certificateFields")
        }
        return fields
    }

    private static func registryUTF8LessThan(_ lhs: String, _ rhs: String) -> Bool {
        let left = lhs.utf8
        let right = rhs.utf8
        var leftIndex = left.startIndex
        var rightIndex = right.startIndex
        while leftIndex != left.endIndex, rightIndex != right.endIndex {
            if left[leftIndex] != right[rightIndex] { return left[leftIndex] < right[rightIndex] }
            left.formIndex(after: &leftIndex)
            right.formIndex(after: &rightIndex)
        }
        return leftIndex == left.endIndex && rightIndex != right.endIndex
    }

    private static func jsonString(_ value: String) -> String {
        var result = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: result += "\\\""
            case 0x5C: result += "\\\\"
            case 0x08: result += "\\b"
            case 0x0C: result += "\\f"
            case 0x0A: result += "\\n"
            case 0x0D: result += "\\r"
            case 0x09: result += "\\t"
            case 0...0x1F:
                let hex = String(scalar.value, radix: 16, uppercase: false)
                result += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            default: result.unicodeScalars.append(scalar)
            }
        }
        result += "\""
        return result
    }
}

private struct CertificateFieldWire: Decodable {
    let friendlyName: String
    let description: String
    let type: String
    let fieldIcon: String
}
