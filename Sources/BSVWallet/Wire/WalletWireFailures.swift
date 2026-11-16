import Foundation

/// A result the wallet wire answers with an error frame, as `@bsv/sdk` 4.1.1 does.
///
/// The codecs throw this when a wallet result has no success encoding (for
/// example a page longer than its declared total). A processor sends `code` and
/// `message` in-band so the remote caller sees the same frame a TypeScript
/// processor would send.
public struct WalletWireResultRejection: Error, Equatable, Sendable, CustomStringConvertible {
    public let code: UInt8
    public let message: String

    public init(code: UInt8 = 1, message: String) {
        self.code = code
        self.message = message
    }

    public var description: String { "WalletWireResultRejection(code: \(code), message: \(message))" }
}

/// Plain sentences a wallet can show. `message` keeps the exact `@bsv/sdk`
/// text that goes on the wire, and `description` keeps code and message for logs.
extension WalletWireResultRejection: LocalizedError {
    public var errorDescription: String? {
        if code == WalletWireErrorCode.abortRefused {
            return "The wallet could not cancel this action because it was already broadcast."
        }
        if message.hasPrefix("Invalid ") || message.hasPrefix("Wallet Wire ") || message.hasPrefix("Missing ") {
            return "The wallet's answer was not in a form the other side can read."
        }
        return message.hasSuffix(".") ? message : message + "."
    }
}

/// Error codes shared with `@bsv/sdk` `walletErrors`.
enum WalletWireErrorCode {
    static let unknownError: UInt8 = 1
    static let unsupportedAction: UInt8 = 2
    static let abortRefused: UInt8 = 8

    /// `@bsv/sdk` sends codes 2 through 8 as given and every other code as 1.
    static func clamped(_ code: UInt8) -> UInt8 {
        (unsupportedAction...abortRefused).contains(code) ? code : unknownError
    }
}

/// Messages `@bsv/sdk` 4.1.1 puts in error frames that peers match on.
enum WalletWireFailureText {
    static let abortRefused =
        "The wallet refused to abort this action because it has already been broadcast"
    static let invalidHMAC = "HMAC is not valid"
    static let invalidSignature = "Signature is not valid"
    static let notAuthenticated = "Wallet did not affirmatively authenticate"
    static let notRelinquishedCertificate = "The wallet did not relinquish the certificate"
    static let probeTrailingData =
        "Wallet Wire certificate compatibility probe request contains trailing data"
    static let unspendableLegacyOutputs =
        "Non-spendable listOutputs records require the spendable encoding extension or JSON"
    static let readerExhausted = "ReaderUint8Array read exceeds available data"

    static func invalidCall(_ code: UInt8) -> String { "Invalid call code: \(code)" }

    /// What a strict UTF-8 decode throws in `@bsv/sdk` (`primitives/utils.ts:237`,
    /// a fatal `TextDecoder`), as Bun and Node word it.
    static let invalidUTF8 = "The encoded data was not valid for encoding utf-8"

    /// `wallet/substrates/WalletWireProcessor.ts:49`.
    static func invalidBooleanFlag(_ field: String, _ flag: UInt8) -> String {
        "Invalid \(field) flag: expected 0 or 1, received \(flag)"
    }

    static func trailingData(_ callName: String) -> String {
        "Wallet Wire \(callName) request contains trailing data"
    }
}

extension WalletCall {
    /// The `@bsv/sdk` method name used in wallet-wire error text.
    var wireMethodName: String { jsonMethodName }
}

extension WalletWireError {
    /// A short, specific phrase for an error frame. It never carries payload bytes.
    var shortMessage: String {
        switch self {
        case .invalidLimit(let name, let value): "invalid limit \(name)=\(value)"
        case .invalidCall(let code): WalletWireFailureText.invalidCall(code)
        case .invalidDiscriminator(let kind, let value): "invalid \(kind) flag \(value)"
        case .invalidUTF8(let kind): "\(kind) is not valid UTF-8"
        case .byteLimitExceeded(let kind, let actual, let maximum):
            "\(kind) is \(actual) bytes, above the limit of \(maximum)"
        case .countLimitExceeded(let kind, let actual, let maximum):
            "\(kind) count \(actual) is above the limit of \(maximum)"
        case .textLimitExceeded(let kind, let actual, let maximum):
            "\(kind) is \(actual) bytes, above the limit of \(maximum)"
        case .noncanonicalCompactSize: "non-canonical varint"
        case .uint32Overflow: "integer does not fit in 32 bits"
        case .truncated: WalletWireFailureText.readerExhausted
        case .trailingBytes: "trailing data"
        case .invalidPublicKey: "invalid public key"
        case .invalidSignature: "invalid DER signature"
        case .nonRoundTrippableValue(let kind): "unsupported \(kind)"
        }
    }
}

/// The message a processor sends when a request frame cannot be decoded.
///
/// Wallet wire, ABI and certificate errors get a short, specific phrase. Any other
/// error gets a fixed text, so type and case names never reach the peer; the
/// processor logs the full error locally.
func walletWireRequestFailureMessage(_ error: any Error, call: WalletCall?) -> String {
    let name = call?.wireMethodName
    if let wire = error as? WalletWireError {
        switch wire {
        case .invalidCall, .truncated:
            return wire.shortMessage
        case .trailingBytes:
            return WalletWireFailureText.trailingData(name ?? "request")
        case .invalidUTF8:
            return WalletWireFailureText.invalidUTF8
        case .invalidDiscriminator(kind: "identity key", let flag):
            return WalletWireFailureText.invalidBooleanFlag("identityKey", flag)
        default:
            return "Invalid Wallet Wire \(name ?? "") request: \(wire.shortMessage)"
        }
    }
    if let rejection = error as? WalletWireResultRejection { return rejection.message }
    if let reason = walletWireShortReason(error) {
        return "Invalid Wallet Wire \(name ?? "") request: \(reason)"
    }
    return "Invalid Wallet Wire \(name ?? "") request"
}

/// The message a processor sends when a wallet result cannot be encoded.
func walletWireResultFailureMessage(_ error: any Error, call: WalletCall) -> String {
    if let reason = walletWireShortReason(error) {
        return "Invalid \(call.wireMethodName) result: \(reason)"
    }
    return "Invalid \(call.wireMethodName) result"
}

/// A short phrase for the errors whose cases name a value, never a payload.
func walletWireShortReason(_ error: any Error) -> String? {
    if let wire = error as? WalletWireError { return wire.shortMessage }
    if let abi = error as? WalletABIError { return abi.shortMessage }
    if let certificate = error as? CertificateError { return certificate.shortMessage }
    return nil
}

extension WalletABIError {
    /// A short, specific phrase for an error frame.
    var shortMessage: String {
        switch self {
        case .invalidLimits: "invalid wallet limits"
        case .invalidEnumText(let type, let value): "\(value) is not a valid \(type)"
        case .conflictingUnionMembers(let what): "conflicting values: \(what)"
        case .countLimitExceeded(let kind, let actual, let maximum):
            "\(kind) count \(actual) is above the limit of \(maximum)"
        case .byteLimitExceeded(let kind, let actual, let maximum):
            "\(kind) is \(actual) bytes, above the limit of \(maximum)"
        case .aggregatePayloadTooLarge(let actual, let maximum):
            "wallet payload is \(actual) bytes, above the limit of \(maximum)"
        case .invalidFieldRelation(let what): what
        case .invalidPaginationLimit(let limit): "page limit \(limit) is out of range"
        case .invalidCanonicalBase64: "value is not canonical base64"
        case .sizeOverflow: "wallet payload size overflows"
        }
    }
}

extension CertificateError {
    /// A short, specific phrase for an error frame.
    var shortMessage: String {
        switch self {
        case .invalidLimits: "invalid certificate limits"
        case .sizeOverflow: "certificate size overflows"
        case .invalidIdentifierByteCount(let expected, let actual):
            "certificate identifier is \(actual) bytes, expected \(expected)"
        case .invalidCanonicalBase64: "certificate value is not canonical base64"
        case .invalidPublicKey: "certificate holds an invalid public key"
        case .invalidRevocationOutpoint: "certificate revocation outpoint is invalid"
        case .emptyFieldName: "certificate field name is empty"
        case .fieldNameTooLong(let actual, let maximum):
            "certificate field name is \(actual) bytes, above the limit of \(maximum)"
        case .tooManyFields(let actual, let maximum):
            "certificate has \(actual) fields, above the limit of \(maximum)"
        case .duplicateFieldName: "certificate repeats a field name"
        case .fieldsNotInCanonicalOrder: "certificate fields are out of order"
        case .fieldValueTooLarge(let actual, let maximum):
            "certificate field value is \(actual) bytes, above the limit of \(maximum)"
        case .keyringValueTooLarge(let actual, let maximum):
            "certificate keyring value is \(actual) bytes, above the limit of \(maximum)"
        case .certificateTooLarge(let actual, let maximum):
            "certificate is \(actual) bytes, above the limit of \(maximum)"
        case .certificateJSONTooLarge(let actual, let maximum):
            "certificate JSON is \(actual) bytes, above the limit of \(maximum)"
        case .truncatedCertificate: "certificate is truncated"
        case .nonCanonicalCompactSize: "certificate holds a non-canonical varint"
        case .invalidOutputIndex: "certificate revocation output index is invalid"
        case .invalidUTF8: "certificate text is not valid UTF-8"
        case .invalidSignature: "certificate signature is invalid"
        case .missingSignature: "certificate is not signed"
        case .alreadySigned: "certificate is already signed"
        case .requirementMismatch: "certificate does not match the request"
        case .signatureMismatch: "certificate signature does not match"
        case .keyringMismatch: "certificate keyring does not match its fields"
        case .fieldNotFound: "certificate field not found"
        case .randomGenerationFailed: "random generation failed"
        case .encryptionFailed: "certificate field encryption failed"
        case .decryptionFailed: "certificate field decryption failed"
        case .walletIdentityMismatch: "certificate subject is not this wallet"
        case .invalidJSON: "certificate JSON is invalid"
        }
    }
}

/// The `@bsv/sdk` 4.1 certificate compatibility call.
let walletWireCertificateCompatibilityCall: UInt8 = 29

/// Answers call 29 as a processor without the compatibility profile does: "Invalid call
/// code: 29", which a TypeScript transceiver downgrades on. A well-formed probe that
/// carries trailing bytes gets the text `@bsv/sdk` 4.1.1 sends for it
/// (wallet/substrates/CertificateWireCompatibility.ts:118-119).
func walletWireRejectCompatibilityProfile(_ request: [UInt8]) throws {
    guard request.first == walletWireCertificateCompatibilityCall else { return }
    var reader = WalletWireReader(request)
    let probeHasTrailingData: Bool = {
        guard (try? reader.readByte()) != nil,
              let originatorCount = try? reader.readByte(),
              (try? reader.readBytes(count: Int(originatorCount))) != nil,
              let mode = try? reader.readByte(),
              let version = try? reader.readByte(),
              mode == 0, version == 1 else { return false }
        return !reader.isAtEnd
    }()
    if probeHasTrailingData {
        throw WalletWireResultRejection(message: WalletWireFailureText.probeTrailingData)
    }
    throw WalletWireError.invalidCall(walletWireCertificateCompatibilityCall)
}

/// Cuts a message to at most `maximum` UTF-8 bytes on a character boundary.
func walletWireTruncatedMessage(_ message: String, maximum: Int) -> String {
    guard message.utf8.count > maximum else { return message }
    var result = ""
    var count = 0
    for character in message {
        let size = String(character).utf8.count
        guard count + size <= maximum else { break }
        result.append(character)
        count += size
    }
    return result
}
