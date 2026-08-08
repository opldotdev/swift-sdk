import BSVCore
import BSVKeys

public enum WalletSignaturePayload:
    Equatable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    case data([UInt8])
    case digest(Hash256)

    public var description: String { "<redacted wallet signature payload>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public enum WalletPublicKeySelection:
    Equatable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    case identity
    case derived(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty,
        forSelf: Bool
    )

    public var description: String { "<redacted wallet public-key selection>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

private enum WalletRequestCodingKeys: String, CodingKey {
    case identityKey
    case protocolID
    case keyID
    case counterparty
    case forSelf
    case plaintext
    case ciphertext
    case data
    case hmac
    case signature
    case hashToDirectlySign
    case hashToDirectlyVerify
    case privileged
    case privilegedReason
    case seekPermission
}

private func decodeAccess(
    _ container: KeyedDecodingContainer<WalletRequestCodingKeys>
) throws -> WalletKeyAccess {
    let privileged = container.contains(.privileged)
        ? try container.decode(Bool.self, forKey: .privileged)
        : false
    let reason = container.contains(.privilegedReason)
        ? try container.decode(String.self, forKey: .privilegedReason)
        : nil
    let seek = container.contains(.seekPermission)
        ? try container.decode(Bool.self, forKey: .seekPermission)
        : false
    return try WalletKeyAccess(
        privileged: privileged,
        privilegedReason: reason,
        seekPermission: seek
    )
}

private func decodeDefaultBool(
    _ container: KeyedDecodingContainer<WalletRequestCodingKeys>,
    forKey key: WalletRequestCodingKeys
) throws -> Bool {
    container.contains(key) ? try container.decode(Bool.self, forKey: key) : false
}

private func encodeAccess(
    _ access: WalletKeyAccess,
    to container: inout KeyedEncodingContainer<WalletRequestCodingKeys>
) throws {
    if access.privileged { try container.encode(true, forKey: .privileged) }
    try container.encodeIfPresent(access.privilegedReason, forKey: .privilegedReason)
    if access.seekPermission { try container.encode(true, forKey: .seekPermission) }
}

private func decodeCounterparty(
    _ container: KeyedDecodingContainer<WalletRequestCodingKeys>,
    default defaultValue: WalletCounterparty
) throws -> WalletCounterparty {
    guard container.contains(.counterparty) else { return defaultValue }
    if try container.decodeNil(forKey: .counterparty) { return defaultValue }
    return try container.decode(WalletCounterparty.self, forKey: .counterparty)
}

private struct GoZeroProtocolID: Decodable {
    init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        guard container.count == 2,
              try container.decode(Int.self) == 0,
              try container.decode(String.self).isEmpty,
              container.isAtEnd else {
            throw WalletCryptoError.invalidJSON
        }
    }
}

private func decodeExactBytes(
    _ container: KeyedDecodingContainer<WalletRequestCodingKeys>,
    forKey key: WalletRequestCodingKeys,
    count expected: Int
) throws -> [UInt8] {
    let bytes = try container.decodeWalletBytes(
        forKey: key,
        maximum: expected + 1,
        limitKind: .invalidJSON
    )
    guard bytes.count == expected else {
        throw DecodingError.dataCorruptedError(
            forKey: key,
            in: container,
            debugDescription: "byte array has an invalid length"
        )
    }
    return bytes
}

public struct WalletGetPublicKeyRequest:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let selection: WalletPublicKeySelection
    public let access: WalletKeyAccess

    public init(selection: WalletPublicKeySelection, access: WalletKeyAccess = .standard) {
        self.selection = selection
        self.access = access
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: WalletRequestCodingKeys.self)
        let identity = try decodeDefaultBool(container, forKey: .identityKey)
        if identity {
            let contradictoryKeys: [WalletRequestCodingKeys] = [.keyID, .counterparty, .forSelf]
            guard !contradictoryKeys.contains(where: container.contains) else {
                throw WalletCryptoError.invalidJSON
            }
            if container.contains(.protocolID) {
                _ = try container.decode(GoZeroProtocolID.self, forKey: .protocolID)
            }
            self.selection = .identity
        } else {
            self.selection = .derived(
                protocolID: try container.decode(WalletProtocolID.self, forKey: .protocolID),
                keyID: try container.decode(WalletKeyID.self, forKey: .keyID),
                counterparty: try decodeCounterparty(container, default: .self),
                forSelf: try decodeDefaultBool(container, forKey: .forSelf)
            )
        }
        self.access = try decodeAccess(container)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WalletRequestCodingKeys.self)
        switch selection {
        case .identity:
            try container.encode(true, forKey: .identityKey)
        case .derived(let protocolID, let keyID, let counterparty, let forSelf):
            try container.encode(protocolID, forKey: .protocolID)
            try container.encode(keyID, forKey: .keyID)
            try container.encode(counterparty, forKey: .counterparty)
            if forSelf { try container.encode(true, forKey: .forSelf) }
        }
        try encodeAccess(access, to: &container)
    }

    public var description: String { "<redacted wallet get-public-key request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletEncryptRequest:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let counterparty: WalletCounterparty
    public let plaintext: [UInt8]
    public let access: WalletKeyAccess

    public init(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty = .self,
        plaintext: [UInt8],
        access: WalletKeyAccess = .standard
    ) {
        self.protocolID = protocolID
        self.keyID = keyID
        self.counterparty = counterparty
        self.plaintext = plaintext
        self.access = access
    }

    public init(from decoder: Decoder) throws {
        let limits = WalletCodingContext.limits(from: decoder)
        let container = try decoder.container(keyedBy: WalletRequestCodingKeys.self)
        self.protocolID = try container.decode(WalletProtocolID.self, forKey: .protocolID)
        self.keyID = try container.decode(WalletKeyID.self, forKey: .keyID)
        self.counterparty = try decodeCounterparty(container, default: .self)
        self.plaintext = try container.decodeWalletBytes(
            forKey: .plaintext,
            maximum: limits.maximumPayloadByteCount
        )
        self.access = try decodeAccess(container)
    }

    public func encode(to encoder: Encoder) throws {
        try walletRequirePayloadLimit(plaintext.count, limits: WalletCodingContext.limits(from: encoder))
        var container = encoder.container(keyedBy: WalletRequestCodingKeys.self)
        try container.encode(protocolID, forKey: .protocolID)
        try container.encode(keyID, forKey: .keyID)
        try container.encode(counterparty, forKey: .counterparty)
        try container.encodeWalletBytes(plaintext, forKey: .plaintext)
        try encodeAccess(access, to: &container)
    }

    public var description: String { "<redacted wallet encrypt request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletDecryptRequest:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let counterparty: WalletCounterparty
    public let ciphertext: [UInt8]
    public let access: WalletKeyAccess

    public init(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty = .self,
        ciphertext: [UInt8],
        access: WalletKeyAccess = .standard
    ) {
        self.protocolID = protocolID
        self.keyID = keyID
        self.counterparty = counterparty
        self.ciphertext = ciphertext
        self.access = access
    }

    public init(from decoder: Decoder) throws {
        let limits = WalletCodingContext.limits(from: decoder)
        let container = try decoder.container(keyedBy: WalletRequestCodingKeys.self)
        self.protocolID = try container.decode(WalletProtocolID.self, forKey: .protocolID)
        self.keyID = try container.decode(WalletKeyID.self, forKey: .keyID)
        self.counterparty = try decodeCounterparty(container, default: .self)
        self.ciphertext = try container.decodeWalletBytes(
            forKey: .ciphertext,
            maximum: limits.maximumCiphertextByteCount,
            limitKind: .ciphertext
        )
        try walletRequireCiphertextLimit(ciphertext.count, limits: limits)
        self.access = try decodeAccess(container)
    }

    public func encode(to encoder: Encoder) throws {
        try walletRequireCiphertextLimit(ciphertext.count, limits: WalletCodingContext.limits(from: encoder))
        var container = encoder.container(keyedBy: WalletRequestCodingKeys.self)
        try container.encode(protocolID, forKey: .protocolID)
        try container.encode(keyID, forKey: .keyID)
        try container.encode(counterparty, forKey: .counterparty)
        try container.encodeWalletBytes(ciphertext, forKey: .ciphertext)
        try encodeAccess(access, to: &container)
    }

    public var description: String { "<redacted wallet decrypt request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletCreateHMACRequest:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let counterparty: WalletCounterparty
    public let data: [UInt8]
    public let access: WalletKeyAccess

    public init(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty = .self,
        data: [UInt8],
        access: WalletKeyAccess = .standard
    ) {
        self.protocolID = protocolID
        self.keyID = keyID
        self.counterparty = counterparty
        self.data = data
        self.access = access
    }

    public init(from decoder: Decoder) throws {
        let limits = WalletCodingContext.limits(from: decoder)
        let container = try decoder.container(keyedBy: WalletRequestCodingKeys.self)
        self.protocolID = try container.decode(WalletProtocolID.self, forKey: .protocolID)
        self.keyID = try container.decode(WalletKeyID.self, forKey: .keyID)
        self.counterparty = try decodeCounterparty(container, default: .self)
        self.data = try container.decodeWalletBytes(forKey: .data, maximum: limits.maximumPayloadByteCount)
        self.access = try decodeAccess(container)
    }

    public func encode(to encoder: Encoder) throws {
        try walletRequirePayloadLimit(data.count, limits: WalletCodingContext.limits(from: encoder))
        var container = encoder.container(keyedBy: WalletRequestCodingKeys.self)
        try container.encode(protocolID, forKey: .protocolID)
        try container.encode(keyID, forKey: .keyID)
        try container.encode(counterparty, forKey: .counterparty)
        try container.encodeWalletBytes(data, forKey: .data)
        try encodeAccess(access, to: &container)
    }

    public var description: String { "<redacted wallet create-HMAC request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletVerifyHMACRequest:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let counterparty: WalletCounterparty
    public let data: [UInt8]
    public let hmac: WalletHMAC
    public let access: WalletKeyAccess

    public init(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty = .self,
        data: [UInt8],
        hmac: WalletHMAC,
        access: WalletKeyAccess = .standard
    ) {
        self.protocolID = protocolID
        self.keyID = keyID
        self.counterparty = counterparty
        self.data = data
        self.hmac = hmac
        self.access = access
    }

    public init(from decoder: Decoder) throws {
        let limits = WalletCodingContext.limits(from: decoder)
        let container = try decoder.container(keyedBy: WalletRequestCodingKeys.self)
        self.protocolID = try container.decode(WalletProtocolID.self, forKey: .protocolID)
        self.keyID = try container.decode(WalletKeyID.self, forKey: .keyID)
        self.counterparty = try decodeCounterparty(container, default: .self)
        self.data = try container.decodeWalletBytes(forKey: .data, maximum: limits.maximumPayloadByteCount)
        self.hmac = try container.decode(WalletHMAC.self, forKey: .hmac)
        self.access = try decodeAccess(container)
    }

    public func encode(to encoder: Encoder) throws {
        try walletRequirePayloadLimit(data.count, limits: WalletCodingContext.limits(from: encoder))
        var container = encoder.container(keyedBy: WalletRequestCodingKeys.self)
        try container.encode(protocolID, forKey: .protocolID)
        try container.encode(keyID, forKey: .keyID)
        try container.encode(counterparty, forKey: .counterparty)
        try container.encodeWalletBytes(data, forKey: .data)
        try container.encode(hmac, forKey: .hmac)
        try encodeAccess(access, to: &container)
    }

    public var description: String { "<redacted wallet verify-HMAC request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletCreateSignatureRequest:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let counterparty: WalletCounterparty
    public let payload: WalletSignaturePayload
    public let access: WalletKeyAccess

    public init(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty = .anyone,
        payload: WalletSignaturePayload,
        access: WalletKeyAccess = .standard
    ) {
        self.protocolID = protocolID
        self.keyID = keyID
        self.counterparty = counterparty
        self.payload = payload
        self.access = access
    }

    public init(from decoder: Decoder) throws {
        let limits = WalletCodingContext.limits(from: decoder)
        let container = try decoder.container(keyedBy: WalletRequestCodingKeys.self)
        self.protocolID = try container.decode(WalletProtocolID.self, forKey: .protocolID)
        self.keyID = try container.decode(WalletKeyID.self, forKey: .keyID)
        self.counterparty = try decodeCounterparty(container, default: .anyone)
        let hasData = container.contains(.data)
        let hasDigest = container.contains(.hashToDirectlySign)
        guard hasData != hasDigest else { throw WalletCryptoError.invalidJSON }
        if hasData {
            self.payload = .data(try container.decodeWalletBytes(
                forKey: .data,
                maximum: limits.maximumPayloadByteCount
            ))
        } else {
            self.payload = .digest(try Hash256(decodeExactBytes(
                container,
                forKey: .hashToDirectlySign,
                count: 32
            )))
        }
        self.access = try decodeAccess(container)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WalletRequestCodingKeys.self)
        try container.encode(protocolID, forKey: .protocolID)
        try container.encode(keyID, forKey: .keyID)
        try container.encode(counterparty, forKey: .counterparty)
        switch payload {
        case .data(let bytes):
            try walletRequirePayloadLimit(bytes.count, limits: WalletCodingContext.limits(from: encoder))
            try container.encodeWalletBytes(bytes, forKey: .data)
        case .digest(let digest):
            try container.encodeWalletBytes(digest.bytes, forKey: .hashToDirectlySign)
        }
        try encodeAccess(access, to: &container)
    }

    public var description: String { "<redacted wallet create-signature request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletVerifySignatureRequest:
    Codable,
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let counterparty: WalletCounterparty
    public let payload: WalletSignaturePayload
    public let signature: ECDSASignature
    public let forSelf: Bool
    public let access: WalletKeyAccess

    public init(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty = .self,
        payload: WalletSignaturePayload,
        signature: ECDSASignature,
        forSelf: Bool = false,
        access: WalletKeyAccess = .standard
    ) {
        self.protocolID = protocolID
        self.keyID = keyID
        self.counterparty = counterparty
        self.payload = payload
        self.signature = signature
        self.forSelf = forSelf
        self.access = access
    }

    public init(from decoder: Decoder) throws {
        let limits = WalletCodingContext.limits(from: decoder)
        let container = try decoder.container(keyedBy: WalletRequestCodingKeys.self)
        self.protocolID = try container.decode(WalletProtocolID.self, forKey: .protocolID)
        self.keyID = try container.decode(WalletKeyID.self, forKey: .keyID)
        self.counterparty = try decodeCounterparty(container, default: .self)
        let hasData = container.contains(.data)
        let hasDigest = container.contains(.hashToDirectlyVerify)
        guard hasData != hasDigest else { throw WalletCryptoError.invalidJSON }
        if hasData {
            self.payload = .data(try container.decodeWalletBytes(
                forKey: .data,
                maximum: limits.maximumPayloadByteCount
            ))
        } else {
            self.payload = .digest(try Hash256(decodeExactBytes(
                container,
                forKey: .hashToDirectlyVerify,
                count: 32
            )))
        }
        let signatureBytes = try container.decodeWalletBytes(
            forKey: .signature,
            maximum: 72,
            limitKind: .invalidJSON
        )
        do {
            self.signature = try ECDSASignature(derBytes: signatureBytes)
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: .signature,
                in: container,
                debugDescription: "signature must use strict DER"
            )
        }
        self.forSelf = try decodeDefaultBool(container, forKey: .forSelf)
        self.access = try decodeAccess(container)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: WalletRequestCodingKeys.self)
        try container.encode(protocolID, forKey: .protocolID)
        try container.encode(keyID, forKey: .keyID)
        try container.encode(counterparty, forKey: .counterparty)
        switch payload {
        case .data(let bytes):
            try walletRequirePayloadLimit(bytes.count, limits: WalletCodingContext.limits(from: encoder))
            try container.encodeWalletBytes(bytes, forKey: .data)
        case .digest(let digest):
            try container.encodeWalletBytes(digest.bytes, forKey: .hashToDirectlyVerify)
        }
        try container.encodeWalletBytes(signature.derBytes, forKey: .signature)
        if forSelf { try container.encode(true, forKey: .forSelf) }
        try encodeAccess(access, to: &container)
    }

    public var description: String { "<redacted wallet verify-signature request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}
