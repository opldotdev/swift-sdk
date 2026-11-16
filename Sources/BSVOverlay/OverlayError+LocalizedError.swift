import Foundation

/// Plain sentences a wallet can show when an overlay value is refused.
/// `String(reflecting:)` still gives the case with its names and sizes for a log.
extension OverlayError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .nonPositiveLimit:
            "The overlay limits are not set up correctly."
        case .invalidProtocolIdentifier:
            "The overlay protocol is not SHIP or SLAP."
        case .invalidTopic:
            "The overlay topic name is not valid. It must start with tm_ and use lowercase letters, digits and single underscores."
        case .invalidService:
            "The overlay service name is not valid. It must start with ls_ and use lowercase letters, digits and single underscores."
        case .invalidHost:
            "The overlay address is not a valid HTTPS address."
        case .emptyValue:
            "A required overlay value is empty."
        case .duplicateValue(let name):
            name == "hosts" || name == "acknowledgmentHosts"
                ? "The same overlay address is listed twice."
                : "The same overlay value is listed twice."
        case .limitExceeded:
            "The overlay request is larger than the wallet accepts."
        }
    }
}

/// Plain sentences for an overlay advertisement that is refused.
extension OverlayAdminTokenError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidLimits:
            "The overlay advertisement limits are not set up correctly."
        case .invalidPushDrop, .unexpectedFieldCount:
            "The overlay advertisement is not in the expected script format."
        case .invalidProtocol:
            "The overlay advertisement is not a SHIP or SLAP advertisement."
        case .invalidIdentityKey:
            "The overlay advertisement does not name a valid identity key."
        case .invalidHost:
            "The overlay advertisement does not name a valid public address."
        case .invalidSubject:
            "The overlay advertisement does not name a valid topic or service."
        case .invalidSignature:
            "The overlay advertisement is not signed correctly."
        case .unlinkedLockingKey:
            "The overlay advertisement was not made by the identity it names."
        }
    }
}

/// Plain sentences for an overlay lookup or broadcast that did not succeed.
extension OverlayPolicyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noCompetentHosts:
            "No overlay host was found for this lookup."
        case .noSuccessfulResponses:
            "No overlay host answered. Check your connection and try again."
        case .inconsistentAnswerTypes:
            "The overlay hosts gave answers that do not match."
        case .invalidLookupOutput:
            "The overlay hosts answered, but none of their results could be read."
        case .discoveryResponseNotOutputList:
            "The overlay directory sent an answer the wallet could not read."
        case .noInterestedHosts:
            "No overlay host accepts this kind of transaction."
        case .invalidAtomicBEEF:
            "The transaction could not be prepared for the overlay."
        case .uncertainDelivery:
            "The transaction may have reached an overlay host, but not every host answered. "
                + "Check its status before sending it again."
        case .acknowledgmentFailed:
            "The overlay hosts did not accept the transaction."
        case .invalidSteak:
            "An overlay host sent an answer that does not match the transaction it was sent."
        }
    }
}
