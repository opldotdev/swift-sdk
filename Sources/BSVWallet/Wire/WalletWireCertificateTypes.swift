/// The certificate, discovery, and linkage request subset of the BRC-100 wallet wire.
public enum WalletWireCertificateRequest:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    case revealCounterpartyKeyLinkage(WalletRevealCounterpartyKeyLinkageRequest)
    case revealSpecificKeyLinkage(WalletRevealSpecificKeyLinkageRequest)
    case acquireCertificate(WalletAcquireCertificateRequest)
    case listCertificates(WalletListCertificatesRequest)
    case proveCertificate(WalletProveCertificateRequest)
    case relinquishCertificate(WalletRelinquishCertificateRequest)
    case discoverByIdentityKey(WalletDiscoverByIdentityKeyRequest)
    case discoverByAttributes(WalletDiscoverByAttributesRequest)

    public var call: WalletCall {
        switch self {
        case .revealCounterpartyKeyLinkage: .revealCounterpartyKeyLinkage
        case .revealSpecificKeyLinkage: .revealSpecificKeyLinkage
        case .acquireCertificate: .acquireCertificate
        case .listCertificates: .listCertificates
        case .proveCertificate: .proveCertificate
        case .relinquishCertificate: .relinquishCertificate
        case .discoverByIdentityKey: .discoverByIdentityKey
        case .discoverByAttributes: .discoverByAttributes
        }
    }

    public var description: String {
        "<redacted wallet-wire certificate request call \(call.rawValue)>"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

/// The certificate, discovery, and linkage result subset of the BRC-100 wallet wire.
public enum WalletWireCertificateResult:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    case revealCounterpartyKeyLinkage(WalletRevealCounterpartyKeyLinkageResult)
    case revealSpecificKeyLinkage(WalletRevealSpecificKeyLinkageResult)
    case acquireCertificate(Certificate)
    case listCertificates(WalletListCertificatesResult)
    case proveCertificate(WalletProveCertificateResult)
    case relinquishCertificate(WalletRelinquishCertificateResult)
    case discoverByIdentityKey(WalletDiscoverCertificatesResult)
    case discoverByAttributes(WalletDiscoverCertificatesResult)

    public var call: WalletCall {
        switch self {
        case .revealCounterpartyKeyLinkage: .revealCounterpartyKeyLinkage
        case .revealSpecificKeyLinkage: .revealSpecificKeyLinkage
        case .acquireCertificate: .acquireCertificate
        case .listCertificates: .listCertificates
        case .proveCertificate: .proveCertificate
        case .relinquishCertificate: .relinquishCertificate
        case .discoverByIdentityKey: .discoverByIdentityKey
        case .discoverByAttributes: .discoverByAttributes
        }
    }

    public var description: String {
        "<redacted wallet-wire certificate result call \(call.rawValue)>"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

public struct WalletWireDecodedCertificateRequest:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let originator: String
    public let request: WalletWireCertificateRequest

    public init(originator: String, request: WalletWireCertificateRequest) {
        self.originator = originator
        self.request = request
    }

    public var description: String { "<redacted decoded wallet-wire certificate request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": request.call.rawValue]) }
}
