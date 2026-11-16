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
    static let unspendableLegacyOutputs =
        "Non-spendable listOutputs records require the spendable encoding extension or JSON"
    static let readerExhausted = "ReaderUint8Array read exceeds available data"

    static func invalidCall(_ code: UInt8) -> String { "Invalid call code: \(code)" }

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
func walletWireRequestFailureMessage(_ error: any Error, call: WalletCall?) -> String {
    let name = call?.wireMethodName
    if let wire = error as? WalletWireError {
        switch wire {
        case .invalidCall, .truncated:
            return wire.shortMessage
        case .trailingBytes:
            return WalletWireFailureText.trailingData(name ?? "request")
        default:
            return "Invalid Wallet Wire \(name ?? "") request: \(wire.shortMessage)"
        }
    }
    if let rejection = error as? WalletWireResultRejection { return rejection.message }
    return "Invalid Wallet Wire \(name ?? "") request: \(error)"
}

/// The message a processor sends when a wallet result cannot be encoded.
func walletWireResultFailureMessage(_ error: any Error, call: WalletCall) -> String {
    if let wire = error as? WalletWireError {
        return "Invalid \(call.wireMethodName) result: \(wire.shortMessage)"
    }
    return "Invalid \(call.wireMethodName) result: \(error)"
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
