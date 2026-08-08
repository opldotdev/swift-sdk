import BSVCore
import BSVKeys
import BSVOverlay
import BSVScript
import BSVTransaction
import BSVWallet

/// Caller-selected bounds for the transport-neutral registry value and codec APIs.
public struct RegistryLimits: Hashable, Sendable {
    public let maximumDefinitionTextUTF8ByteCount: Int
    public let maximumDefinitionAggregateUTF8ByteCount: Int
    public let maximumCertificateFieldCount: Int
    public let maximumCertificateFieldNameUTF8ByteCount: Int
    public let maximumCertificateFieldTextUTF8ByteCount: Int
    public let maximumQueryOperatorCount: Int
    public let maximumRecordCount: Int
    public let maximumTokenBEEFByteCount: Int
    public let maximumTokenLockingScriptByteCount: Int
    public let pushDropLimits: PushDropLimits

    public init(
        maximumDefinitionTextUTF8ByteCount: Int,
        maximumDefinitionAggregateUTF8ByteCount: Int,
        maximumCertificateFieldCount: Int,
        maximumCertificateFieldNameUTF8ByteCount: Int,
        maximumCertificateFieldTextUTF8ByteCount: Int,
        maximumQueryOperatorCount: Int,
        maximumRecordCount: Int,
        maximumTokenBEEFByteCount: Int,
        maximumTokenLockingScriptByteCount: Int,
        pushDropLimits: PushDropLimits
    ) throws {
        let values = [
            ("maximumDefinitionTextUTF8ByteCount", maximumDefinitionTextUTF8ByteCount),
            ("maximumDefinitionAggregateUTF8ByteCount", maximumDefinitionAggregateUTF8ByteCount),
            ("maximumCertificateFieldCount", maximumCertificateFieldCount),
            ("maximumCertificateFieldNameUTF8ByteCount", maximumCertificateFieldNameUTF8ByteCount),
            ("maximumCertificateFieldTextUTF8ByteCount", maximumCertificateFieldTextUTF8ByteCount),
            ("maximumQueryOperatorCount", maximumQueryOperatorCount),
            ("maximumRecordCount", maximumRecordCount),
            ("maximumTokenBEEFByteCount", maximumTokenBEEFByteCount),
            ("maximumTokenLockingScriptByteCount", maximumTokenLockingScriptByteCount),
        ]
        if let invalid = values.first(where: { $0.1 <= 0 }) {
            throw RegistryError.nonPositiveLimit(name: invalid.0, value: invalid.1)
        }
        guard maximumDefinitionTextUTF8ByteCount <= pushDropLimits.maximumFieldByteCount else {
            throw RegistryError.inconsistentLimit(name: "maximumDefinitionTextUTF8ByteCount")
        }
        guard pushDropLimits.maximumFieldCount >= 7 else {
            throw RegistryError.inconsistentLimit(name: "pushDropLimits.maximumFieldCount")
        }
        self.maximumDefinitionTextUTF8ByteCount = maximumDefinitionTextUTF8ByteCount
        self.maximumDefinitionAggregateUTF8ByteCount = maximumDefinitionAggregateUTF8ByteCount
        self.maximumCertificateFieldCount = maximumCertificateFieldCount
        self.maximumCertificateFieldNameUTF8ByteCount = maximumCertificateFieldNameUTF8ByteCount
        self.maximumCertificateFieldTextUTF8ByteCount = maximumCertificateFieldTextUTF8ByteCount
        self.maximumQueryOperatorCount = maximumQueryOperatorCount
        self.maximumRecordCount = maximumRecordCount
        self.maximumTokenBEEFByteCount = maximumTokenBEEFByteCount
        self.maximumTokenLockingScriptByteCount = maximumTokenLockingScriptByteCount
        self.pushDropLimits = pushDropLimits
    }

    private init(standard: Void) {
        maximumDefinitionTextUTF8ByteCount = 1 * 1_024 * 1_024
        maximumDefinitionAggregateUTF8ByteCount = 4 * 1_024 * 1_024
        maximumCertificateFieldCount = 256
        maximumCertificateFieldNameUTF8ByteCount = 256
        maximumCertificateFieldTextUTF8ByteCount = 4 * 1_024
        maximumQueryOperatorCount = 256
        maximumRecordCount = 10_000
        maximumTokenBEEFByteCount = 32 * 1_024 * 1_024
        maximumTokenLockingScriptByteCount = 1 * 1_024 * 1_024
        pushDropLimits = .standard
    }

    public static let standard = Self(standard: ())
}

/// Registry validation and codec errors. Cases intentionally exclude field contents.
public enum RegistryError: Error, Equatable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible
{
    case nonPositiveLimit(name: String, value: Int)
    case inconsistentLimit(name: String)
    case textTooLong(field: String, actual: Int, maximum: Int)
    case collectionCountExceedsLimit(collection: String, actual: Int, maximum: Int)
    case aggregateTooLarge(actual: Int, maximum: Int)
    case emptyField(name: String)
    case invalidText(field: String)
    case invalidRegistryOperator
    case unexpectedFieldCount(kind: RegistryDefinitionKind, actual: Int, expected: Int)
    case malformedEmbeddedJSON(field: String)
    case nonCanonicalEmbeddedJSON(field: String)
    case invalidCertificateFieldType
    case pushDropFailure

    public var description: String {
        switch self {
        case .nonPositiveLimit(let name, let value):
            "registry limit \(name) must be positive (received \(value))"
        case .inconsistentLimit(let name):
            "registry limit \(name) exceeds its enclosing limit"
        case .textTooLong(let field, let actual, let maximum):
            "registry \(field) exceeds its byte limit (\(actual) > \(maximum))"
        case .collectionCountExceedsLimit(let collection, let actual, let maximum):
            "registry \(collection) count exceeds its limit (\(actual) > \(maximum))"
        case .aggregateTooLarge(let actual, let maximum):
            "registry fields exceed their aggregate byte limit (\(actual) > \(maximum))"
        case .emptyField(let name): "registry \(name) must not be empty"
        case .invalidText(let field): "registry \(field) is invalid"
        case .invalidRegistryOperator: "registry operator is not a canonical compressed public key"
        case .unexpectedFieldCount(let kind, let actual, let expected):
            "registry \(kind.rawValue) field count is invalid (\(actual), expected \(expected))"
        case .malformedEmbeddedJSON(let field): "registry \(field) JSON is malformed"
        case .nonCanonicalEmbeddedJSON(let field): "registry \(field) JSON is not canonical"
        case .invalidCertificateFieldType: "registry certificate field type is invalid"
        case .pushDropFailure: "registry PushDrop script is invalid"
        }
    }

    public var debugDescription: String { description }
}

/// The closed set of on-chain registry definition categories.
public enum RegistryDefinitionKind: String, CaseIterable, Hashable, Sendable {
    case basket
    case `protocol` = "protocol"
    case certificate

    public func walletProtocolID() throws -> WalletProtocolID {
        switch self {
        case .basket:
            try WalletProtocolID(
                securityLevel: .everyAppAndCounterparty, name: "basketmap")
        case .protocol:
            try WalletProtocolID(
                securityLevel: .everyAppAndCounterparty, name: "protomap")
        case .certificate:
            try WalletProtocolID(
                securityLevel: .everyAppAndCounterparty, name: "certmap")
        }
    }

    public var basketName: String {
        switch self {
        case .basket: "basketmap"
        case .protocol: "protomap"
        case .certificate: "certmap"
        }
    }

    public func topic(limits: OverlayLimits = .standard) throws -> OverlayTopic {
        switch self {
        case .basket: try OverlayTopic(rawValue: "tm_basketmap", limits: limits)
        case .protocol: try OverlayTopic(rawValue: "tm_protomap", limits: limits)
        case .certificate: try OverlayTopic(rawValue: "tm_certmap", limits: limits)
        }
    }

    public func service(limits: OverlayLimits = .standard) throws -> OverlayService {
        switch self {
        case .basket: try OverlayService(rawValue: "ls_basketmap", limits: limits)
        case .protocol: try OverlayService(rawValue: "ls_protomap", limits: limits)
        case .certificate: try OverlayService(rawValue: "ls_certmap", limits: limits)
        }
    }
}

/// A validated registry operator identity. Diagnostics never reveal the key text.
public struct RegistryOperator: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let publicKey: PublicKey

    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }

    public init(compressedHex: String) throws {
        guard compressedHex.utf8.count == 66,
            let bytes = try? Hex.decode(compressedHex, maximumDecodedByteCount: 33),
            Hex.encode(bytes) == compressedHex,
            let publicKey = try? PublicKey(bytes),
            publicKey.compressedBytes == bytes
        else {
            throw RegistryError.invalidRegistryOperator
        }
        self.publicKey = publicKey
    }

    /// Explicit serialization for PushDrop fields and wire protocols.
    public var compressedHex: String { Hex.encode(publicKey.compressedBytes) }

    public var description: String { "<redacted registry operator>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// Human-readable metadata carried by every registry definition.
public struct RegistryMetadata: Hashable, Sendable {
    public let name: String
    public let iconURL: String
    public let description: String
    public let documentationURL: String

    public init(
        name: String,
        iconURL: String,
        description: String,
        documentationURL: String,
        limits: RegistryLimits = .standard
    ) throws {
        try registryMetadataText(
            name: name,
            iconURL: iconURL,
            description: description,
            documentationURL: documentationURL,
            limits: limits)
        self.name = name
        self.iconURL = iconURL
        self.description = description
        self.documentationURL = documentationURL
    }
}

/// The closed semantic type of a certificate descriptor field.
public enum RegistryCertificateFieldType: String, CaseIterable, Hashable, Sendable {
    case text
    case imageURL
    case other
}

/// A bounded certificate field descriptor.
public struct RegistryCertificateFieldDescriptor: Hashable, Sendable {
    public let friendlyName: String
    public let description: String
    public let type: RegistryCertificateFieldType
    public let fieldIcon: String

    public init(
        friendlyName: String,
        description: String,
        type: RegistryCertificateFieldType,
        fieldIcon: String,
        limits: RegistryLimits = .standard
    ) throws {
        try registryDescriptorText(friendlyName, field: "friendlyName", limits: limits)
        try registryDescriptorText(description, field: "description", limits: limits)
        try registryDescriptorText(fieldIcon, field: "fieldIcon", limits: limits)
        self.friendlyName = friendlyName
        self.description = description
        self.type = type
        self.fieldIcon = fieldIcon
    }
}

public struct RegistryBasketDefinition: Hashable, Sendable {
    public let basketID: String
    public let metadata: RegistryMetadata
    public let registryOperator: RegistryOperator

    public init(
        basketID: String,
        metadata: RegistryMetadata,
        registryOperator: RegistryOperator,
        limits: RegistryLimits = .standard
    ) throws {
        try registryRequiredText(basketID, field: "basketID", limits: limits)
        try registryMetadataText(
            name: metadata.name,
            iconURL: metadata.iconURL,
            description: metadata.description,
            documentationURL: metadata.documentationURL,
            limits: limits)
        try registryText(registryOperator.compressedHex, field: "registryOperator", limits: limits)
        try registryAggregate(
            [
                basketID, metadata.name,
                metadata.iconURL, metadata.description, metadata.documentationURL,
                registryOperator.compressedHex,
            ],
            limits: limits)
        self.basketID = basketID
        self.metadata = metadata
        self.registryOperator = registryOperator
    }
}

public struct RegistryProtocolDefinition: Hashable, Sendable {
    public let protocolID: WalletProtocolID
    public let metadata: RegistryMetadata
    public let registryOperator: RegistryOperator

    public init(
        protocolID: WalletProtocolID,
        metadata: RegistryMetadata,
        registryOperator: RegistryOperator,
        limits: RegistryLimits = .standard
    ) throws {
        try registryMetadataText(
            name: metadata.name,
            iconURL: metadata.iconURL,
            description: metadata.description,
            documentationURL: metadata.documentationURL,
            limits: limits)
        let protocolText = "[\(protocolID.securityLevel.rawValue),\"\(protocolID.name)\"]"
        try registryText(protocolText, field: "protocolID", limits: limits)
        try registryText(registryOperator.compressedHex, field: "registryOperator", limits: limits)
        try registryAggregate(
            [
                protocolText, metadata.name, metadata.iconURL, metadata.description,
                metadata.documentationURL, registryOperator.compressedHex,
            ],
            limits: limits)
        self.protocolID = protocolID
        self.metadata = metadata
        self.registryOperator = registryOperator
    }
}

public struct RegistryCertificateDefinition: Hashable, Sendable {
    public let type: String
    public let metadata: RegistryMetadata
    public let fields: [String: RegistryCertificateFieldDescriptor]
    public let registryOperator: RegistryOperator

    public init(
        type: String,
        metadata: RegistryMetadata,
        fields: [String: RegistryCertificateFieldDescriptor],
        registryOperator: RegistryOperator,
        limits: RegistryLimits = .standard
    ) throws {
        try registryRequiredText(type, field: "certificateType", limits: limits)
        try registryMetadataText(
            name: metadata.name,
            iconURL: metadata.iconURL,
            description: metadata.description,
            documentationURL: metadata.documentationURL,
            limits: limits)
        guard fields.count <= limits.maximumCertificateFieldCount else {
            throw RegistryError.collectionCountExceedsLimit(
                collection: "certificateFields", actual: fields.count,
                maximum: limits.maximumCertificateFieldCount)
        }
        for name in fields.keys {
            try registryFieldName(name, limits: limits)
            guard let descriptor = fields[name] else {
                throw RegistryError.invalidText(field: "certificateFields")
            }
            try registryDescriptorText(
                descriptor.friendlyName, field: "friendlyName", limits: limits)
            try registryDescriptorText(descriptor.description, field: "description", limits: limits)
            try registryDescriptorText(descriptor.fieldIcon, field: "fieldIcon", limits: limits)
        }
        let fieldsJSON = registryCanonicalCertificateFields(fields)
        try registryText(fieldsJSON, field: "certificateFields", limits: limits)
        try registryText(registryOperator.compressedHex, field: "registryOperator", limits: limits)
        try registryAggregate(
            [
                type, metadata.name, metadata.iconURL, metadata.description,
                metadata.documentationURL, fieldsJSON,
                registryOperator.compressedHex,
            ],
            limits: limits)
        self.type = type
        self.metadata = metadata
        self.fields = fields
        self.registryOperator = registryOperator
    }
}

/// The strongly typed Swift replacement for Go's open `DefinitionData` interface.
public enum RegistryDefinition: Hashable, Sendable {
    case basket(RegistryBasketDefinition)
    case protocolDefinition(RegistryProtocolDefinition)
    case certificate(RegistryCertificateDefinition)

    public var kind: RegistryDefinitionKind {
        switch self {
        case .basket: .basket
        case .protocolDefinition: .protocol
        case .certificate: .certificate
        }
    }

    public var registryOperator: RegistryOperator {
        switch self {
        case .basket(let definition): definition.registryOperator
        case .protocolDefinition(let definition): definition.registryOperator
        case .certificate(let definition): definition.registryOperator
        }
    }
}

/// Shared bounded query criteria; no lookup transport is implied by this value.
public struct RegistryQueryOperators: Hashable, Sendable {
    public let values: [RegistryOperator]

    public static let empty = Self(unchecked: [])

    public init(_ values: [RegistryOperator], limits: RegistryLimits = .standard) throws {
        guard values.count <= limits.maximumQueryOperatorCount else {
            throw RegistryError.collectionCountExceedsLimit(
                collection: "registryOperators", actual: values.count,
                maximum: limits.maximumQueryOperatorCount)
        }
        self.values = values
    }

    private init(unchecked values: [RegistryOperator]) {
        self.values = values
    }
}

/// Bounded token data corresponding to one registry UTXO. The BEEF payload is
/// retained as opaque bytes so transport-neutral callers can choose validation
/// policy before parsing it as a transaction envelope.
public struct RegistryToken: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let outpoint: Outpoint
    public let satoshis: UInt64
    public let lockingScript: Script
    public let beef: [UInt8]

    public init(
        outpoint: Outpoint,
        satoshis: UInt64,
        lockingScript: Script,
        beef: [UInt8],
        limits: RegistryLimits = .standard
    ) throws {
        guard lockingScript.bytes.count <= limits.maximumTokenLockingScriptByteCount else {
            throw RegistryError.textTooLong(
                field: "tokenLockingScript", actual: lockingScript.bytes.count,
                maximum: limits.maximumTokenLockingScriptByteCount)
        }
        guard beef.count <= limits.maximumTokenBEEFByteCount else {
            throw RegistryError.textTooLong(
                field: "tokenBEEF", actual: beef.count, maximum: limits.maximumTokenBEEFByteCount)
        }
        self.outpoint = outpoint
        self.satoshis = satoshis
        self.lockingScript = lockingScript
        self.beef = beef
    }

    public var description: String { "<redacted registry token>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// An immutable registry definition and its bounded on-chain token data.
public struct RegistryRecord: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let definition: RegistryDefinition
    public let token: RegistryToken

    public init(definition: RegistryDefinition, token: RegistryToken) {
        self.definition = definition
        self.token = token
    }

    public var description: String { "<redacted registry record>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// A count-bounded lookup result collection.
public struct RegistryRecords: Hashable, Sendable {
    public let values: [RegistryRecord]

    public init(_ values: [RegistryRecord], limits: RegistryLimits = .standard) throws {
        guard values.count <= limits.maximumRecordCount else {
            throw RegistryError.collectionCountExceedsLimit(
                collection: "registryRecords", actual: values.count,
                maximum: limits.maximumRecordCount)
        }
        self.values = values
    }
}

/// Typed, transport-neutral basket lookup criteria.
public struct RegistryBasketQuery: Hashable, Sendable {
    public let basketID: String?
    public let name: String?
    public let registryOperators: RegistryQueryOperators

    public init(
        basketID: String? = nil,
        name: String? = nil,
        registryOperators: RegistryQueryOperators = .empty,
        limits: RegistryLimits = .standard
    ) throws {
        if let basketID { try registryRequiredText(basketID, field: "basketID", limits: limits) }
        if let name { try registryRequiredText(name, field: "name", limits: limits) }
        _ = try RegistryQueryOperators(registryOperators.values, limits: limits)
        self.basketID = basketID
        self.name = name
        self.registryOperators = registryOperators
    }
}

/// Typed, transport-neutral protocol lookup criteria.
public struct RegistryProtocolQuery: Hashable, Sendable {
    public let protocolID: WalletProtocolID?
    public let name: String?
    public let registryOperators: RegistryQueryOperators

    public init(
        protocolID: WalletProtocolID? = nil,
        name: String? = nil,
        registryOperators: RegistryQueryOperators = .empty,
        limits: RegistryLimits = .standard
    ) throws {
        if let name { try registryRequiredText(name, field: "name", limits: limits) }
        _ = try RegistryQueryOperators(registryOperators.values, limits: limits)
        self.protocolID = protocolID
        self.name = name
        self.registryOperators = registryOperators
    }
}

/// Typed, transport-neutral certificate lookup criteria.
public struct RegistryCertificateQuery: Hashable, Sendable {
    public let type: String?
    public let name: String?
    public let registryOperators: RegistryQueryOperators

    public init(
        type: String? = nil,
        name: String? = nil,
        registryOperators: RegistryQueryOperators = .empty,
        limits: RegistryLimits = .standard
    ) throws {
        if let type { try registryRequiredText(type, field: "certificateType", limits: limits) }
        if let name { try registryRequiredText(name, field: "name", limits: limits) }
        _ = try RegistryQueryOperators(registryOperators.values, limits: limits)
        self.type = type
        self.name = name
        self.registryOperators = registryOperators
    }
}

/// Narrow asynchronous registry lookup boundary. Implementations own transport,
/// cancellation, and endpoint policy; this package supplies no default client.
public protocol RegistryLookup: Sendable {
    func baskets(matching query: RegistryBasketQuery) async throws -> RegistryRecords
    func protocols(matching query: RegistryProtocolQuery) async throws -> RegistryRecords
    func certificates(matching query: RegistryCertificateQuery) async throws -> RegistryRecords
}

/// Narrow publication boundary. No wallet or transaction orchestration is provided.
public protocol RegistryPublisher: Sendable {
    func publish(_ definition: RegistryDefinition) async throws -> RegistryToken
}

func registryText(_ text: String, field: String, limits: RegistryLimits) throws {
    let bytes = text.utf8
    guard !bytes.contains(0) else { throw RegistryError.invalidText(field: field) }
    guard bytes.count <= limits.maximumDefinitionTextUTF8ByteCount else {
        throw RegistryError.textTooLong(
            field: field, actual: bytes.count, maximum: limits.maximumDefinitionTextUTF8ByteCount)
    }
}

func registryRequiredText(_ text: String, field: String, limits: RegistryLimits) throws {
    guard !text.isEmpty else { throw RegistryError.emptyField(name: field) }
    try registryText(text, field: field, limits: limits)
}

func registryMetadataText(
    name: String,
    iconURL: String,
    description: String,
    documentationURL: String,
    limits: RegistryLimits
) throws {
    try registryRequiredText(name, field: "name", limits: limits)
    try registryText(iconURL, field: "iconURL", limits: limits)
    try registryText(description, field: "description", limits: limits)
    try registryText(documentationURL, field: "documentationURL", limits: limits)
}

func registryDescriptorText(_ text: String, field: String, limits: RegistryLimits) throws {
    let bytes = text.utf8
    guard !bytes.contains(0) else { throw RegistryError.invalidText(field: field) }
    guard bytes.count <= limits.maximumCertificateFieldTextUTF8ByteCount else {
        throw RegistryError.textTooLong(
            field: field, actual: bytes.count,
            maximum: limits.maximumCertificateFieldTextUTF8ByteCount)
    }
}

func registryFieldName(_ text: String, limits: RegistryLimits) throws {
    guard !text.isEmpty else { throw RegistryError.emptyField(name: "certificateFieldName") }
    let bytes = text.utf8
    guard !bytes.contains(0) else { throw RegistryError.invalidText(field: "certificateFieldName") }
    guard bytes.count <= limits.maximumCertificateFieldNameUTF8ByteCount else {
        throw RegistryError.textTooLong(
            field: "certificateFieldName", actual: bytes.count,
            maximum: limits.maximumCertificateFieldNameUTF8ByteCount)
    }
}

func registryAggregate(_ values: [String], limits: RegistryLimits) throws {
    var byteCount = 0
    for value in values {
        let (next, overflow) = byteCount.addingReportingOverflow(value.utf8.count)
        guard !overflow else {
            throw RegistryError.aggregateTooLarge(
                actual: .max, maximum: limits.maximumDefinitionAggregateUTF8ByteCount)
        }
        byteCount = next
        guard byteCount <= limits.maximumDefinitionAggregateUTF8ByteCount else {
            throw RegistryError.aggregateTooLarge(
                actual: byteCount, maximum: limits.maximumDefinitionAggregateUTF8ByteCount)
        }
    }
}

func registryCanonicalCertificateFields(
    _ fields: [String: RegistryCertificateFieldDescriptor]
) -> String {
    let names = fields.keys.sorted(by: registryUTF8LessThan)
    let body = names.compactMap { name -> String? in
        guard let descriptor = fields[name] else { return nil }
        return
            "\(registryJSONString(name)):{\"friendlyName\":\(registryJSONString(descriptor.friendlyName)),\"description\":\(registryJSONString(descriptor.description)),\"type\":\(registryJSONString(descriptor.type.rawValue)),\"fieldIcon\":\(registryJSONString(descriptor.fieldIcon))}"
    }.joined(separator: ",")
    return "{\(body)}"
}

func registryUTF8LessThan(_ lhs: String, _ rhs: String) -> Bool {
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

func registryJSONString(_ value: String) -> String {
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
