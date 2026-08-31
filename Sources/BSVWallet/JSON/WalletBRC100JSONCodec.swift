import Foundation
import BSVCore
import BSVKeys
import BSVTransaction

/// Canonical method metadata for the BRC-5 JSON wallet substrate.
public struct WalletJSONRoute: Hashable, Sendable {
    public let call: WalletCall
    public let methodName: String
    public var path: String { "/\(methodName)" }

    public init?(methodName: String) {
        guard let call = WalletCall.allCases.first(where: { $0.jsonMethodName == methodName }) else {
            return nil
        }
        self.call = call
        self.methodName = methodName
    }

    public init(call: WalletCall) {
        self.call = call
        self.methodName = call.jsonMethodName
    }

    /// Accepts exactly one unversioned `/<methodName>` route.
    public init?(path: String) {
        guard path.first == "/", path.dropFirst().contains("/") == false else { return nil }
        self.init(methodName: String(path.dropFirst()))
    }

    public static let all = WalletCall.allCases.map(Self.init(call:))
}

public extension WalletCall {
    var jsonMethodName: String {
        switch self {
        case .createAction: "createAction"
        case .signAction: "signAction"
        case .abortAction: "abortAction"
        case .listActions: "listActions"
        case .internalizeAction: "internalizeAction"
        case .listOutputs: "listOutputs"
        case .relinquishOutput: "relinquishOutput"
        case .getPublicKey: "getPublicKey"
        case .revealCounterpartyKeyLinkage: "revealCounterpartyKeyLinkage"
        case .revealSpecificKeyLinkage: "revealSpecificKeyLinkage"
        case .encrypt: "encrypt"
        case .decrypt: "decrypt"
        case .createHMAC: "createHmac"
        case .verifyHMAC: "verifyHmac"
        case .createSignature: "createSignature"
        case .verifySignature: "verifySignature"
        case .acquireCertificate: "acquireCertificate"
        case .listCertificates: "listCertificates"
        case .proveCertificate: "proveCertificate"
        case .relinquishCertificate: "relinquishCertificate"
        case .discoverByIdentityKey: "discoverByIdentityKey"
        case .discoverByAttributes: "discoverByAttributes"
        case .isAuthenticated: "isAuthenticated"
        case .waitForAuthentication: "waitForAuthentication"
        case .getHeight: "getHeight"
        case .getHeaderForHeight: "getHeaderForHeight"
        case .getNetwork: "getNetwork"
        case .getVersion: "getVersion"
        }
    }
}

public enum WalletJSONCodecError: Error, Equatable, Sendable {
    case unknownRoute(String)
    case requestCallMismatch(expected: WalletCall, actual: WalletCall)
    case resultCallMismatch(expected: WalletCall, actual: WalletCall)
    case invalidJSON
    case jsonTooLarge(actual: Int, maximum: Int)
    case encodedJSONTooLarge(actual: Int, maximum: Int)
}

/// The JSON error object consumed by the live TypeScript `HTTPWalletJSON`
/// substrate. Extra fields carry typed WERR details without losing their JSON
/// shape (for example `parameter` or `moreSatoshisNeeded`).
public struct WalletJSONErrorPayload: Equatable, Codable, Sendable {
    public let name: String
    public let message: String
    public let isError: Bool
    public let code: UInt8?
    public let details: [String: WalletJSONValue]

    public init(
        name: String,
        message: String,
        code: UInt8? = nil,
        details: [String: WalletJSONValue] = [:]
    ) {
        self.name = name
        self.message = message
        self.isError = true
        self.code = code
        self.details = details
    }

    private enum FixedKeys: String, CodingKey { case name, message, isError, code }

    public init(from decoder: Decoder) throws {
        let fixed = try decoder.container(keyedBy: FixedKeys.self)
        name = try fixed.decode(String.self, forKey: .name)
        message = try fixed.decode(String.self, forKey: .message)
        isError = try fixed.decode(Bool.self, forKey: .isError)
        guard isError else { throw WalletJSONCodecError.invalidJSON }
        code = try fixed.decodeIfPresent(UInt8.self, forKey: .code)
        let dynamic = try decoder.container(keyedBy: WalletJSONDynamicKey.self)
        var values: [String: WalletJSONValue] = [:]
        for key in dynamic.allKeys where FixedKeys(stringValue: key.stringValue) == nil {
            values[key.stringValue] = try dynamic.decode(WalletJSONValue.self, forKey: key)
        }
        details = values
    }

    public func encode(to encoder: Encoder) throws {
        var fixed = encoder.container(keyedBy: FixedKeys.self)
        try fixed.encode(name, forKey: .name)
        try fixed.encode(message, forKey: .message)
        try fixed.encode(true, forKey: .isError)
        try fixed.encodeIfPresent(code, forKey: .code)
        var dynamic = encoder.container(keyedBy: WalletJSONDynamicKey.self)
        for (name, value) in details {
            guard FixedKeys(stringValue: name) == nil else { continue }
            try dynamic.encode(value, forKey: WalletJSONDynamicKey(name))
        }
    }
}

public indirect enum WalletJSONValue: Equatable, Codable, Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([WalletJSONValue])
    case object([String: WalletJSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([WalletJSONValue].self) { self = .array(value) }
        else if let value = try? container.decode([String: WalletJSONValue].self) { self = .object(value) }
        else { throw WalletJSONCodecError.invalidJSON }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

/// A transport-neutral outcome suitable for an HTTP, XDM, or native host.
/// The host decides how these cases map to status codes or transport frames.
public enum WalletJSONProcessingOutcome: Equatable, Sendable {
    case success(call: WalletCall, body: [UInt8])
    case unknownRoute(path: String)
    case invalidRequest(call: WalletCall)
    case walletFailure(call: WalletCall, body: [UInt8])
}

public protocol WalletJSONFailureMapping: Sendable {
    func payload(for error: any Error, call: WalletCall) -> WalletJSONErrorPayload
}

/// A conservative mapper that does not expose arbitrary error descriptions.
public struct WalletJSONRedactingFailureMapper: WalletJSONFailureMapping, Sendable {
    public init() {}
    public func payload(for error: any Error, call: WalletCall) -> WalletJSONErrorPayload {
        WalletJSONErrorPayload(name: "WERR_UNKNOWN", message: "Wallet request failed")
    }
}

/// Decodes, dispatches, and encodes one JSON wallet request without owning a
/// socket, HTTP status policy, CORS policy, or origin trust policy.
public struct WalletBRC100JSONProcessor: Sendable {
    public let codec: WalletBRC100JSONCodec
    private let handler: any WalletRequestHandling
    private let failureMapper: any WalletJSONFailureMapping

    public init(
        codec: WalletBRC100JSONCodec,
        handler: any WalletRequestHandling,
        failureMapper: any WalletJSONFailureMapping = WalletJSONRedactingFailureMapper()
    ) {
        self.codec = codec
        self.handler = handler
        self.failureMapper = failureMapper
    }

    public func process(
        path: String,
        body: [UInt8],
        context: WalletRequestContext
    ) async -> WalletJSONProcessingOutcome {
        guard let route = WalletJSONRoute(path: path) else { return .unknownRoute(path: path) }
        let request: WalletRequest
        do { request = try codec.decodeRequest(route: route, from: body) }
        catch { return .invalidRequest(call: route.call) }
        do {
            let result = try await handler.handle(request, context: context)
            guard result.call == route.call else {
                return .walletFailure(
                    call: route.call,
                    body: (try? codec.encodeError(.init(
                        name: "WERR_UNKNOWN",
                        message: "Wallet returned a mismatched result"
                    ))) ?? []
                )
            }
            return .success(call: route.call, body: try codec.encodeResult(result))
        } catch {
            let payload = failureMapper.payload(for: error, call: route.call)
            return .walletFailure(
                call: route.call,
                body: (try? codec.encodeError(payload)) ?? []
            )
        }
    }
}

/// Transport-neutral codec for the BRC-5 JSON substrate. It performs no HTTP,
/// origin, authorization, or wallet work.
public struct WalletBRC100JSONCodec: Sendable {
    public let maximumJSONByteCount: Int
    public let abiLimits: WalletABILimits
    public let cryptoLimits: WalletCryptoLimits
    public let certificateLimits: CertificateLimits
    public let beefLimits: BEEFLimits

    public init(
        beefLimits: BEEFLimits,
        maximumJSONByteCount: Int = 8_388_608,
        abiLimits: WalletABILimits = .standard,
        cryptoLimits: WalletCryptoLimits = .standard,
        certificateLimits: CertificateLimits = .standard
    ) throws {
        guard maximumJSONByteCount >= 0 else {
            throw WalletJSONCodecError.jsonTooLarge(actual: 0, maximum: maximumJSONByteCount)
        }
        self.maximumJSONByteCount = maximumJSONByteCount
        self.abiLimits = abiLimits
        self.cryptoLimits = cryptoLimits
        self.certificateLimits = certificateLimits
        self.beefLimits = beefLimits
    }

    public func decodeRequest(route: WalletJSONRoute, from bytes: [UInt8]) throws -> WalletRequest {
        switch route.call {
        case .createAction, .signAction, .abortAction, .listActions,
             .internalizeAction, .listOutputs, .relinquishOutput:
            return .action(try decodeActionRequest(call: route.call, bytes: bytes))
        case .revealCounterpartyKeyLinkage, .revealSpecificKeyLinkage,
             .acquireCertificate, .listCertificates, .proveCertificate,
             .relinquishCertificate, .discoverByIdentityKey, .discoverByAttributes:
            return .certificate(try decodeCertificateRequest(call: route.call, bytes: bytes))
        case .getPublicKey:
            return .keyQuery(.getPublicKey(try decode(WalletGetPublicKeyRequest.self, bytes)))
        case .encrypt:
            return .keyQuery(.encrypt(try decode(WalletEncryptRequest.self, bytes)))
        case .decrypt:
            return .keyQuery(.decrypt(try decode(WalletDecryptRequest.self, bytes)))
        case .createHMAC:
            return .keyQuery(.createHMAC(try decode(WalletCreateHMACRequest.self, bytes)))
        case .verifyHMAC:
            return .keyQuery(.verifyHMAC(try decode(WalletVerifyHMACRequest.self, bytes)))
        case .createSignature:
            return .keyQuery(.createSignature(try decode(WalletCreateSignatureRequest.self, bytes)))
        case .verifySignature:
            return .keyQuery(.verifySignature(try decode(WalletVerifySignatureRequest.self, bytes)))
        case .isAuthenticated:
            try decodeEmpty(bytes); return .keyQuery(.isAuthenticated(.init()))
        case .waitForAuthentication:
            try decodeEmpty(bytes); return .keyQuery(.waitForAuthentication(.init()))
        case .getHeight:
            try decodeEmpty(bytes); return .keyQuery(.getHeight(.init()))
        case .getHeaderForHeight:
            let dto = try decode(HeaderRequestDTO.self, bytes)
            return .keyQuery(.getHeaderForHeight(.init(height: dto.height)))
        case .getNetwork:
            try decodeEmpty(bytes); return .keyQuery(.getNetwork(.init()))
        case .getVersion:
            try decodeEmpty(bytes); return .keyQuery(.getVersion(.init()))
        }
    }

    public func encodeRequest(_ request: WalletRequest) throws -> [UInt8] {
        switch request {
        case .action(let value): return try encodeActionRequest(value)
        case .certificate(let value): return try encodeCertificateRequest(value)
        case .keyQuery(let value):
            switch value {
            case .getPublicKey(let dto): return try encode(dto)
            case .encrypt(let dto): return try encode(dto)
            case .decrypt(let dto): return try encode(dto)
            case .createHMAC(let dto): return try encode(dto)
            case .verifyHMAC(let dto): return try encode(dto)
            case .createSignature(let dto): return try encode(dto)
            case .verifySignature(let dto): return try encode(dto)
            case .isAuthenticated, .waitForAuthentication, .getHeight, .getNetwork, .getVersion:
                return try encode(EmptyDTO())
            case .getHeaderForHeight(let dto): return try encode(HeaderRequestDTO(height: dto.height))
            }
        }
    }

    public func decodeResult(route: WalletJSONRoute, from bytes: [UInt8]) throws -> WalletResult {
        switch route.call {
        case .createAction, .signAction, .abortAction, .listActions,
             .internalizeAction, .listOutputs, .relinquishOutput:
            return .action(try decodeActionResult(call: route.call, bytes: bytes))
        case .revealCounterpartyKeyLinkage, .revealSpecificKeyLinkage,
             .acquireCertificate, .listCertificates, .proveCertificate,
             .relinquishCertificate, .discoverByIdentityKey, .discoverByAttributes:
            return .certificate(try decodeCertificateResult(call: route.call, bytes: bytes))
        case .getPublicKey: return .keyQuery(.getPublicKey(try decode(WalletGetPublicKeyResult.self, bytes)))
        case .encrypt: return .keyQuery(.encrypt(try decode(WalletEncryptResult.self, bytes)))
        case .decrypt: return .keyQuery(.decrypt(try decode(WalletDecryptResult.self, bytes)))
        case .createHMAC: return .keyQuery(.createHMAC(try decode(WalletCreateHMACResult.self, bytes)))
        case .verifyHMAC: return .keyQuery(.verifyHMAC(try decode(WalletVerifyHMACResult.self, bytes)))
        case .createSignature: return .keyQuery(.createSignature(try decode(WalletCreateSignatureResult.self, bytes)))
        case .verifySignature: return .keyQuery(.verifySignature(try decode(WalletVerifySignatureResult.self, bytes)))
        case .isAuthenticated: return .keyQuery(.isAuthenticated(try authenticatedResult(bytes)))
        case .waitForAuthentication: return .keyQuery(.waitForAuthentication(try authenticatedResult(bytes)))
        case .getHeight:
            return .keyQuery(.getHeight(.init(height: try decode(HeightResultDTO.self, bytes).height)))
        case .getHeaderForHeight:
            let value = try decode(HeaderResultDTO.self, bytes)
            let header = try decodeCanonicalHex(value.header, maximum: WalletGetHeaderResult.byteCount)
            return .keyQuery(.getHeaderForHeight(try .init(header: header)))
        case .getNetwork:
            return .keyQuery(.getNetwork(.init(network: try decode(NetworkResultDTO.self, bytes).network)))
        case .getVersion:
            return .keyQuery(.getVersion(try .init(version: decode(VersionResultDTO.self, bytes).version, limits: abiLimits)))
        }
    }

    public func encodeResult(_ result: WalletResult) throws -> [UInt8] {
        switch result {
        case .action(let value): return try encodeActionResult(value)
        case .certificate(let value): return try encodeCertificateResult(value)
        case .keyQuery(let value):
            switch value {
            case .getPublicKey(let dto): return try encode(dto)
            case .encrypt(let dto): return try encode(dto)
            case .decrypt(let dto): return try encode(dto)
            case .createHMAC(let dto): return try encode(dto)
            case .verifyHMAC(let dto): return try encode(dto)
            case .createSignature(let dto): return try encode(dto)
            case .verifySignature(let dto): return try encode(dto)
            case .isAuthenticated(let dto), .waitForAuthentication(let dto):
                return try encode(AuthenticatedResultDTO(authenticated: dto.authenticated))
            case .getHeight(let dto): return try encode(HeightResultDTO(height: dto.height))
            case .getHeaderForHeight(let dto): return try encode(HeaderResultDTO(header: Hex.encode(dto.header)))
            case .getNetwork(let dto): return try encode(NetworkResultDTO(network: dto.network))
            case .getVersion(let dto): return try encode(VersionResultDTO(version: dto.version))
            }
        }
    }

    public func decodeError(from bytes: [UInt8]) throws -> WalletJSONErrorPayload {
        try decode(WalletJSONErrorPayload.self, bytes)
    }

    public func encodeError(_ error: WalletJSONErrorPayload) throws -> [UInt8] {
        try encode(error)
    }

    private func authenticatedResult(_ bytes: [UInt8]) throws -> WalletAuthenticatedResult {
        .init(authenticated: try decode(AuthenticatedResultDTO.self, bytes).authenticated)
    }

    func decode<T: Decodable>(_ type: T.Type, _ bytes: [UInt8]) throws -> T {
        guard bytes.count <= maximumJSONByteCount else {
            throw WalletJSONCodecError.jsonTooLarge(actual: bytes.count, maximum: maximumJSONByteCount)
        }
        let decoder = JSONDecoder()
        decoder.userInfo[.walletJSONABILimits] = abiLimits
        decoder.userInfo[.walletJSONCryptoLimits] = cryptoLimits
        decoder.userInfo[.walletJSONCertificateLimits] = certificateLimits
        decoder.userInfo[.walletJSONBEEFLimits] = beefLimits
        if let key = WalletCodingContext.limitsKey { decoder.userInfo[key] = cryptoLimits }
        do { return try decoder.decode(type, from: Data(bytes)) }
        catch let error as WalletJSONCodecError { throw error }
        catch let error as WalletABIError { throw error }
        catch let error as WalletCryptoError { throw error }
        catch let error as CertificateError { throw error }
        catch let error as BEEFError { throw error }
        catch { throw WalletJSONCodecError.invalidJSON }
    }

    func encode<T: Encodable>(_ value: T) throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.userInfo[.walletJSONABILimits] = abiLimits
        encoder.userInfo[.walletJSONCryptoLimits] = cryptoLimits
        encoder.userInfo[.walletJSONCertificateLimits] = certificateLimits
        encoder.userInfo[.walletJSONBEEFLimits] = beefLimits
        if let key = WalletCodingContext.limitsKey { encoder.userInfo[key] = cryptoLimits }
        let data: Data
        do { data = try encoder.encode(value) }
        catch let error as WalletJSONCodecError { throw error }
        catch let error as WalletABIError { throw error }
        catch let error as WalletCryptoError { throw error }
        catch let error as CertificateError { throw error }
        catch let error as BEEFError { throw error }
        catch { throw WalletJSONCodecError.invalidJSON }
        guard data.count <= maximumJSONByteCount else {
            throw WalletJSONCodecError.encodedJSONTooLarge(actual: data.count, maximum: maximumJSONByteCount)
        }
        return [UInt8](data)
    }

    private func decodeEmpty(_ bytes: [UInt8]) throws { _ = try decode(EmptyDTO.self, bytes) }
}

extension CodingUserInfoKey {
    static let walletJSONABILimits = CodingUserInfoKey(rawValue: "org.bsv.swift-sdk.wallet.json.abi")!
    static let walletJSONCryptoLimits = CodingUserInfoKey(rawValue: "org.bsv.swift-sdk.wallet.json.crypto")!
    static let walletJSONCertificateLimits = CodingUserInfoKey(rawValue: "org.bsv.swift-sdk.wallet.json.certificate")!
    static let walletJSONBEEFLimits = CodingUserInfoKey(rawValue: "org.bsv.swift-sdk.wallet.json.beef")!
}

struct WalletJSONDynamicKey: CodingKey {
    let stringValue: String
    let intValue: Int?
    init(_ value: String) { stringValue = value; intValue = nil }
    init?(stringValue: String) { self.init(stringValue) }
    init?(intValue: Int) { stringValue = String(intValue); self.intValue = intValue }
}

private struct EmptyDTO: Codable {
    init() {}
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: WalletJSONDynamicKey.self)
        guard values.allKeys.isEmpty else { throw WalletJSONCodecError.invalidJSON }
    }
}
private struct HeaderRequestDTO: Codable { let height: UInt32 }
private struct AuthenticatedResultDTO: Codable { let authenticated: Bool }
private struct HeightResultDTO: Codable { let height: UInt32 }
private struct HeaderResultDTO: Codable { let header: String }
private struct NetworkResultDTO: Codable { let network: WalletNetwork }
private struct VersionResultDTO: Codable { let version: String }

func decodeCanonicalHex(_ value: String, maximum: Int) throws -> [UInt8] {
    do {
        let bytes = try Hex.decode(value, maximumDecodedByteCount: maximum)
        guard Hex.encode(bytes) == value else { throw WalletJSONCodecError.invalidJSON }
        return bytes
    } catch { throw WalletJSONCodecError.invalidJSON }
}

func decodeWalletJSONPublicKey(_ value: String) throws -> PublicKey {
    let bytes = try decodeCanonicalHex(value, maximum: 33)
    guard bytes.count == 33,
          let key = try? PublicKey(bytes),
          key.compressedBytes == bytes else { throw WalletJSONCodecError.invalidJSON }
    return key
}
