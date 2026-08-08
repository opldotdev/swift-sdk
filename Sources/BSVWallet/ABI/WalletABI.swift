import BSVCore
import BSVKeys
import BSVTransaction

/// Resource bounds for in-memory BRC-100 wallet ABI values.
public struct WalletABILimits: Hashable, Sendable {
    public static let maximumProtocolPageSize: UInt32 = 10_000
    public static let defaultPageSize: UInt32 = 10

    public static let standard = WalletABILimits(
        validatedText: 2_000,
        collection: 10_000,
        tags: 1_000,
        labels: 1_000,
        payload: 8_388_608,
        aggregate: 16_777_216
    )

    public let maximumTextUTF8ByteCount: Int
    public let maximumCollectionCount: Int
    public let maximumTagCount: Int
    public let maximumLabelCount: Int
    public let maximumBytePayloadCount: Int
    public let maximumAggregatePayloadByteCount: Int

    public init(
        maximumTextUTF8ByteCount: Int = 2_000,
        maximumCollectionCount: Int = 10_000,
        maximumTagCount: Int = 1_000,
        maximumLabelCount: Int = 1_000,
        maximumBytePayloadCount: Int = 8_388_608,
        maximumAggregatePayloadByteCount: Int = 16_777_216
    ) throws {
        let values = [
            maximumTextUTF8ByteCount, maximumCollectionCount, maximumTagCount,
            maximumLabelCount, maximumBytePayloadCount, maximumAggregatePayloadByteCount,
        ]
        guard values.allSatisfy({ $0 >= 0 }),
              maximumTagCount <= maximumCollectionCount,
              maximumLabelCount <= maximumCollectionCount,
              maximumBytePayloadCount <= maximumAggregatePayloadByteCount else {
            throw WalletABIError.invalidLimits
        }
        self.init(
            validatedText: maximumTextUTF8ByteCount,
            collection: maximumCollectionCount,
            tags: maximumTagCount,
            labels: maximumLabelCount,
            payload: maximumBytePayloadCount,
            aggregate: maximumAggregatePayloadByteCount
        )
    }

    private init(
        validatedText: Int,
        collection: Int,
        tags: Int,
        labels: Int,
        payload: Int,
        aggregate: Int
    ) {
        maximumTextUTF8ByteCount = validatedText
        maximumCollectionCount = collection
        maximumTagCount = tags
        maximumLabelCount = labels
        maximumBytePayloadCount = payload
        maximumAggregatePayloadByteCount = aggregate
    }
}

/// Validation failures raised while constructing bounded wallet ABI values.
public enum WalletABIError: Error, Equatable, Sendable {
    case invalidLimits
    case invalidEnumText(type: String, value: String)
    case conflictingUnionMembers(String)
    case countLimitExceeded(kind: String, actual: Int, maximum: Int)
    case byteLimitExceeded(kind: String, actual: Int, maximum: Int)
    case aggregatePayloadTooLarge(actual: Int, maximum: Int)
    case invalidFieldRelation(String)
    case invalidPaginationLimit(UInt32)
    case invalidCanonicalBase64
    case sizeOverflow
}

/// The exact BRC-100 wallet-wire operation discriminator.
public enum WalletCall: UInt8, CaseIterable, Codable, Sendable {
    case createAction = 1
    case signAction = 2
    case abortAction = 3
    case listActions = 4
    case internalizeAction = 5
    case listOutputs = 6
    case relinquishOutput = 7
    case getPublicKey = 8
    case revealCounterpartyKeyLinkage = 9
    case revealSpecificKeyLinkage = 10
    case encrypt = 11
    case decrypt = 12
    case createHMAC = 13
    case verifyHMAC = 14
    case createSignature = 15
    case verifySignature = 16
    case acquireCertificate = 17
    case listCertificates = 18
    case proveCertificate = 19
    case relinquishCertificate = 20
    case discoverByIdentityKey = 21
    case discoverByAttributes = 22
    case isAuthenticated = 23
    case waitForAuthentication = 24
    case getHeight = 25
    case getHeaderForHeight = 26
    case getNetwork = 27
    case getVersion = 28
}

/// Pagination preserving the ABI's absent/default distinction.
public struct WalletPagination: Equatable, Sendable {
    public static let standard = WalletPagination(validatedLimit: nil, offset: nil)
    public let limit: UInt32?
    public let offset: UInt32?
    public var effectiveLimit: UInt32 { limit ?? WalletABILimits.defaultPageSize }
    public var effectiveOffset: UInt32 { offset ?? 0 }

    public init(limit: UInt32? = nil, offset: UInt32? = nil) throws {
        if let limit, !(1...WalletABILimits.maximumProtocolPageSize).contains(limit) {
            throw WalletABIError.invalidPaginationLimit(limit)
        }
        self.limit = limit
        self.offset = offset
    }

    private init(validatedLimit: UInt32?, offset: UInt32?) {
        self.limit = validatedLimit
        self.offset = offset
    }
}

/// Canonical padded Base64 data used by BRC-100 reference and remittance fields.
public struct WalletBase64Data:
    Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8], limits: WalletABILimits = .standard) throws {
        try walletABIRequireBytes(bytes.count, kind: "base64 data", limits: limits)
        self.bytes = bytes
    }

    public init(base64: String, limits: WalletABILimits = .standard) throws {
        guard base64.utf8.count <= walletABIBase64Size(for: limits.maximumBytePayloadCount),
              let decoded = try? Base64Encoding.decode(
                base64,
                maximumDecodedByteCount: limits.maximumBytePayloadCount
              ),
              Base64Encoding.encode(decoded) == base64 else {
            throw WalletABIError.invalidCanonicalBase64
        }
        try self.init(decoded, limits: limits)
    }

    public var base64: String { Base64Encoding.encode(bytes) }
    public var description: String { "<redacted wallet Base64 data>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

/// Privileged-operation metadata. It expresses no permission policy or UI behavior.
public struct WalletPrivilege: Equatable, Sendable {
    public static let standard = WalletPrivilege(validatedPrivileged: nil, reason: nil)
    public let privileged: Bool?
    public let privilegedReason: String?

    public init(
        privileged: Bool? = nil,
        privilegedReason: String? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        if let privilegedReason {
            try walletABIRequireText(privilegedReason, kind: "privileged reason", limits: limits)
        }
        self.privileged = privileged
        self.privilegedReason = privilegedReason
    }

    private init(validatedPrivileged: Bool?, reason: String?) {
        self.privileged = validatedPrivileged
        self.privilegedReason = reason
    }
}

public enum WalletQueryMode: String, CaseIterable, Codable, Sendable {
    case any
    case all
    public init(_ text: String) throws {
        guard let value = Self(rawValue: text) else {
            throw WalletABIError.invalidEnumText(type: "WalletQueryMode", value: text)
        }
        self = value
    }
}

public enum WalletOutputInclude: String, CaseIterable, Codable, Sendable {
    case lockingScripts = "locking scripts"
    case entireTransactions = "entire transactions"
    public init(_ text: String) throws {
        guard let value = Self(rawValue: text) else {
            throw WalletABIError.invalidEnumText(type: "WalletOutputInclude", value: text)
        }
        self = value
    }
}

public enum WalletNetwork: String, CaseIterable, Codable, Sendable {
    case mainnet
    case testnet
    public init(_ text: String) throws {
        guard let value = Self(rawValue: text) else {
            throw WalletABIError.invalidEnumText(type: "WalletNetwork", value: text)
        }
        self = value
    }
}

package func walletABIRequireText(
    _ text: String,
    kind: String,
    limits: WalletABILimits
) throws {
    let count = text.utf8.count
    guard count <= limits.maximumTextUTF8ByteCount else {
        throw WalletABIError.byteLimitExceeded(
            kind: kind, actual: count, maximum: limits.maximumTextUTF8ByteCount
        )
    }
}

package func walletABIRequireCount(
    _ count: Int,
    kind: String,
    maximum: Int
) throws {
    guard count <= maximum else {
        throw WalletABIError.countLimitExceeded(kind: kind, actual: count, maximum: maximum)
    }
}

package func walletABIRequireBytes(
    _ count: Int,
    kind: String,
    limits: WalletABILimits
) throws {
    guard count <= limits.maximumBytePayloadCount else {
        throw WalletABIError.byteLimitExceeded(
            kind: kind, actual: count, maximum: limits.maximumBytePayloadCount
        )
    }
}

package func walletABIRequireAggregate(_ counts: [Int], limits: WalletABILimits) throws {
    var total = 0
    for count in counts {
        let (sum, overflow) = total.addingReportingOverflow(count)
        guard count >= 0, !overflow else { throw WalletABIError.sizeOverflow }
        total = sum
    }
    guard total <= limits.maximumAggregatePayloadByteCount else {
        throw WalletABIError.aggregatePayloadTooLarge(
            actual: total, maximum: limits.maximumAggregatePayloadByteCount
        )
    }
}

package func walletABIValidateTexts(
    _ values: [String],
    kind: String,
    countLimit: Int,
    limits: WalletABILimits
) throws {
    try walletABIRequireCount(values.count, kind: kind, maximum: countLimit)
    var total = 0
    for value in values {
        try walletABIRequireText(value, kind: kind, limits: limits)
        let (sum, overflow) = total.addingReportingOverflow(value.utf8.count)
        guard !overflow else { throw WalletABIError.sizeOverflow }
        total = sum
    }
    try walletABIRequireAggregate([total], limits: limits)
}

private func walletABIBase64Size(for byteCount: Int) -> Int {
    let (plusTwo, overflow) = byteCount.addingReportingOverflow(2)
    guard !overflow else { return .max }
    let (result, multiplyOverflow) = (plusTwo / 3).multipliedReportingOverflow(by: 4)
    return multiplyOverflow ? .max : result
}
