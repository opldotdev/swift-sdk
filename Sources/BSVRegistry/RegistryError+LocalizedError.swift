import Foundation

/// Plain sentences a wallet can show when a registry entry is refused.
/// `String(reflecting:)` still gives the case with its sizes and cause for a log.
extension RegistryError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .nonPositiveLimit, .inconsistentLimit:
            "The registry is not set up correctly."
        case .textTooLong(let field, _, _):
            "The registry \(Self.plainName(field)) is too long."
        case .collectionCountExceedsLimit(let collection, _, _):
            "The registry entry has too many \(Self.plainName(collection))."
        case .aggregateTooLarge:
            "The registry entry is larger than the wallet accepts."
        case .emptyField(let name):
            "The registry \(Self.plainName(name)) must not be empty."
        case .invalidText(let field):
            "The registry \(Self.plainName(field)) contains characters that are not allowed."
        case .invalidRegistryOperator:
            "The registry entry does not name a valid operator key."
        case .unexpectedFieldCount(let kind, _, _):
            "The registry entry is not a valid \(kind.rawValue) entry."
        case .malformedEmbeddedJSON(let field), .nonCanonicalEmbeddedJSON(let field):
            "The registry \(Self.plainName(field)) could not be read."
        case .invalidCertificateFieldType:
            "A certificate field in the registry entry has an unknown type."
        case .pushDropFailure:
            "The registry entry is not in the expected script format."
        case .invalidSignatureEncoding, .invalidSignature:
            "The registry entry is not signed correctly by its operator."
        case .lockingKeyNotLinkedToOperator:
            "The registry entry was not made by the operator it names."
        case .walletIdentityIsNotRegistryOperator:
            "This wallet is not the operator named in the registry entry."
        case .roundTripMismatch:
            "The wallet wrote a registry entry that does not match what was asked. Nothing was published."
        }
    }

    /// Field names as a person would say them.
    private static func plainName(_ name: String) -> String {
        switch name {
        case "basketID": "basket ID"
        case "protocolID": "protocol ID"
        case "type": "certificate type"
        case "name": "name"
        case "iconURL": "icon address"
        case "description": "description"
        case "documentationURL": "documentation address"
        case "certificateFields": "certificate fields"
        case "certificateFieldName": "certificate field name"
        case "registryOperator": "operator key"
        case "signature": "signature"
        case "definitionField": "entry field"
        default: name
        }
    }
}
