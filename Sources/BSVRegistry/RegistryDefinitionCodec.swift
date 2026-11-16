import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVWallet
import Foundation

/// Codec for registry tokens as `@bsv/sdk` 4.1.1 writes and the TypeScript
/// `tm_basketmap`, `tm_protomap` and `tm_certmap` topic managers admit them.
///
/// A token is a lock-before PushDrop script with the definition's data fields
/// (6 for a basket or protocol, 7 for a certificate, the operator key last)
/// followed by one operator signature over the data fields concatenated. The
/// locking key and the signing key are the operator's BRC-42 child for the
/// kind's protocol (`[1, "basketmap"]`, `[1, "protomap"]`, `[1, "certmap"]`),
/// key ID `"1"`, with the "anyone" key as the other party
/// (`registry/registryTokenValidation.ts`, `registry/RegistryClient.ts`).
///
/// All decoded text is bounded and UTF-8 validated before it is indexed or
/// parsed. Encoding writes canonical embedded JSON. Decoding accepts any
/// valid certificate-field JSON object, as TypeScript `JSON.parse` does.
public enum RegistryDefinitionCodec: Sendable {
    /// The registry key ID used by every token.
    public static let keyID = "1"
    /// The largest token field, signature included, that TypeScript decodes
    /// (`registry/registryTokenValidation.ts:10`, `MAX_REGISTRY_FIELD_BYTES`).
    public static let maximumTokenFieldByteCount = 16 * 1_024
    /// The largest total of all token fields, signature included, that
    /// TypeScript decodes (`registryTokenValidation.ts:11`, `MAX_REGISTRY_TOKEN_BYTES`).
    public static let maximumTokenPayloadByteCount = 64 * 1_024

    /// The names of a kind's data fields in token order, as used in errors.
    public static func fieldNames(for kind: RegistryDefinitionKind) -> [String] {
        switch kind {
        case .basket:
            ["basketID", "name", "iconURL", "description", "documentationURL", "registryOperator"]
        case .protocol:
            ["protocolID", "name", "iconURL", "description", "documentationURL", "registryOperator"]
        case .certificate:
            [
                "type", "name", "iconURL", "description", "documentationURL",
                "certificateFields", "registryOperator",
            ]
        }
    }

    /// The data fields of a definition, without the trailing signature.
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

    /// Builds a signed registry token with the operator's wallet, as
    /// TypeScript `pushdrop.lock(fields, protocol, "1", "anyone", true)` does.
    ///
    /// The wallet's identity key must be the definition's registry operator,
    /// and no data field may be empty (see below).
    /// The finished script is decoded and verified before it is returned.
    public static func lockingScript(
        for definition: RegistryDefinition,
        using wallet: any WalletPublicKeyProviding & WalletSignatureOperations,
        limits: RegistryLimits = .standard
    ) async throws -> Script {
        let encodedFields = try fields(for: definition, limits: limits)
        let names = fieldNames(for: definition.kind)
        // PushDrop writes an empty field as OP_0, which TypeScript and Swift
        // both read back as [0]. The signature covers the empty bytes, so the
        // token could never verify. TypeScript has the same limit.
        if let index = encodedFields.firstIndex(where: \.isEmpty) {
            throw RegistryError.emptyField(name: names[index])
        }
        // Refuse before signing a token no TypeScript host would decode. The
        // exact payload, signature included, is checked by `decode` below.
        try checkTypeScriptBounds(encodedFields, names: names)
        let protocolID = try definition.kind.walletProtocolID()
        let walletKeyID = try WalletKeyID(Self.keyID)

        try Task.checkCancellation()
        let identityKey = try await wallet.getPublicKey(.init(selection: .identity)).publicKey
        guard identityKey == definition.registryOperator.publicKey else {
            throw RegistryError.walletIdentityIsNotRegistryOperator
        }

        let script: Script
        do {
            script = try await PushDrop.lockingScript(
                fields: encodedFields,
                using: wallet,
                protocolID: protocolID,
                keyID: walletKeyID,
                counterparty: .anyone,
                forSelf: true,
                includeSignature: true,
                lockPosition: .beforeCompatibility,
                limits: limits.pushDropLimits
            )
        } catch let error as PushDropError {
            throw RegistryError.pushDropFailure(error)
        }
        guard try decode(script, kind: definition.kind, limits: limits) == definition else {
            throw RegistryError.roundTripMismatch
        }
        return script
    }

    /// Decodes a registry token and authenticates it as TypeScript does: the
    /// field count, the TypeScript size bounds, the operator key linkage, and
    /// the operator signature. A field written as `OP_0` is refused, because
    /// TypeScript reads it as `"\u{0}"`, which its text rules reject.
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
        } catch let error as PushDropError {
            throw RegistryError.pushDropFailure(error)
        }
        let expectedCount = kind.dataFieldCount + 1
        guard decoded.fields.count == expectedCount else {
            throw RegistryError.unexpectedFieldCount(
                kind: kind, actual: decoded.fields.count, expected: expectedCount)
        }
        let names = fieldNames(for: kind)
        try checkTypeScriptBounds(decoded.fields, names: names + ["signature"])
        let dataFields = Array(decoded.fields.dropLast())
        if let index = dataFields.firstIndex(of: [0]) {
            throw RegistryError.emptyField(name: names[index])
        }
        let definition = try definition(kind: kind, fields: dataFields, limits: limits)

        guard let signatureField = decoded.fields.last,
            let signature = try? ECDSASignature(derBytes: signatureField),
            signature.derBytes == signatureField
        else {
            throw RegistryError.invalidSignatureEncoding
        }
        let operatorKey = definition.registryOperator.publicKey
        let expectedLockingKey: PublicKey
        do {
            expectedLockingKey = try WalletKeyDeriver.anyone().derivePublicKey(
                protocolID: try kind.walletProtocolID(),
                keyID: try WalletKeyID(Self.keyID),
                counterparty: .publicKey(operatorKey),
                forSelf: false
            )
        } catch {
            throw RegistryError.lockingKeyNotLinkedToOperator
        }
        guard expectedLockingKey == decoded.publicKey else {
            throw RegistryError.lockingKeyNotLinkedToOperator
        }
        let digest = BSVHashing.sha256(Array(dataFields.joined()))
        // TypeScript verification has no low-S rule, so a high-S signature
        // from another wallet is accepted here too.
        guard signature.verifiesInScript(publicKey: expectedLockingKey, digest: digest) else {
            throw RegistryError.invalidSignature
        }
        return definition
    }

    /// Parses a definition from its data fields only. It does not check a
    /// signature; use `decode(_:kind:limits:)` for on-chain tokens.
    public static func definition(
        kind: RegistryDefinitionKind,
        fields: [[UInt8]],
        limits: RegistryLimits = .standard
    ) throws -> RegistryDefinition {
        let expectedCount = kind.dataFieldCount
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
            throw RegistryError.pushDropFailure(
                .fieldCountExceedsLimit(
                    actual: fields.count,
                    maximum: limits.pushDropLimits.maximumFieldCount
                ))
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

    /// TypeScript `decodeCanonicalPushDrop` bounds for registry tokens.
    private static func checkTypeScriptBounds(_ fields: [[UInt8]], names: [String]) throws {
        var total = 0
        for (index, field) in fields.enumerated() {
            guard field.count <= maximumTokenFieldByteCount else {
                throw RegistryError.textTooLong(
                    field: index < names.count ? names[index] : "field\(index)",
                    actual: field.count,
                    maximum: maximumTokenFieldByteCount)
            }
            total += field.count
        }
        guard total <= maximumTokenPayloadByteCount else {
            throw RegistryError.aggregateTooLarge(
                actual: total, maximum: maximumTokenPayloadByteCount)
        }
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

    private static let certificateDescriptorKeys: Set<String> = [
        "friendlyName", "description", "type", "fieldIcon",
    ]

    /// Parses certificate field descriptors in any key order or spacing, as
    /// TypeScript `JSON.parse` does (`registry/RegistryClient.ts`). Each
    /// descriptor must have exactly the four string keys TypeScript allows.
    private static func decodedCertificateFields(
        _ source: String,
        limits: RegistryLimits
    ) throws -> [String: RegistryCertificateFieldDescriptor] {
        guard let data = source.data(using: .utf8),
            data.count <= limits.maximumDefinitionTextUTF8ByteCount
        else {
            throw RegistryError.malformedEmbeddedJSON(field: "certificateFields")
        }
        let wire: [String: [String: String]]
        do {
            wire = try JSONDecoder().decode([String: [String: String]].self, from: data)
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
            guard Set(descriptor.keys) == certificateDescriptorKeys,
                let friendlyName = descriptor["friendlyName"],
                let description = descriptor["description"],
                let typeText = descriptor["type"],
                let fieldIcon = descriptor["fieldIcon"]
            else {
                throw RegistryError.malformedEmbeddedJSON(field: "certificateFields")
            }
            guard let type = RegistryCertificateFieldType(rawValue: typeText) else {
                throw RegistryError.invalidCertificateFieldType
            }
            try registryFieldName(name, limits: limits)
            fields[name] = try RegistryCertificateFieldDescriptor(
                friendlyName: friendlyName,
                description: description,
                type: type,
                fieldIcon: fieldIcon,
                limits: limits
            )
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
