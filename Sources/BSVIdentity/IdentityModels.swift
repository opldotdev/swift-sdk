import BSVScript
import BSVTransaction
import BSVWallet

/// Resource limits for identity resolution and public disclosure.
public struct IdentityLimits: Hashable, Sendable {
    public static let maximumAllowedIdentityCount = 10_000
    public static let maximumAllowedFieldsToReveal = 256
    public static let maximumAllowedDisplayTextUTF8ByteCount = 65_536
    public static let maximumAllowedAggregateDisplayUTF8ByteCount = 16_777_216
    public static let maximumAllowedDisclosureJSONByteCount = 8_388_608

    /// Zero permits only an empty discovery result.
    public let maximumIdentityCount: Int
    /// Zero disables public disclosure.
    public let maximumFieldsToReveal: Int
    /// Zero permits only empty caller-provided display text.
    public let maximumDisplayTextUTF8ByteCount: Int
    /// Zero permits only an empty aggregate display payload.
    public let maximumAggregateDisplayUTF8ByteCount: Int
    /// Zero disables disclosure JSON construction.
    public let maximumDisclosureJSONByteCount: Int
    public let certificateLimits: CertificateLimits
    public let walletLimits: WalletABILimits
    public let pushDropLimits: PushDropLimits
    public let beefLimits: BEEFLimits

    public init(
        maximumIdentityCount: Int,
        maximumFieldsToReveal: Int,
        maximumDisplayTextUTF8ByteCount: Int,
        maximumAggregateDisplayUTF8ByteCount: Int,
        maximumDisclosureJSONByteCount: Int,
        certificateLimits: CertificateLimits,
        walletLimits: WalletABILimits,
        pushDropLimits: PushDropLimits,
        beefLimits: BEEFLimits
    ) throws {
        guard (0...Self.maximumAllowedIdentityCount).contains(maximumIdentityCount),
              (0...Self.maximumAllowedFieldsToReveal).contains(maximumFieldsToReveal),
              (0...Self.maximumAllowedDisplayTextUTF8ByteCount).contains(
                  maximumDisplayTextUTF8ByteCount
              ),
              (0...Self.maximumAllowedAggregateDisplayUTF8ByteCount).contains(
                  maximumAggregateDisplayUTF8ByteCount
              ),
              (0...Self.maximumAllowedDisclosureJSONByteCount).contains(
                  maximumDisclosureJSONByteCount
              ) else {
            throw IdentityError.invalidLimits
        }
        guard maximumDisplayTextUTF8ByteCount <= maximumAggregateDisplayUTF8ByteCount,
              maximumDisclosureJSONByteCount <= pushDropLimits.maximumFieldByteCount,
              maximumDisclosureJSONByteCount <= walletLimits.maximumBytePayloadCount else {
            throw IdentityError.invalidLimits
        }
        self.maximumIdentityCount = maximumIdentityCount
        self.maximumFieldsToReveal = maximumFieldsToReveal
        self.maximumDisplayTextUTF8ByteCount = maximumDisplayTextUTF8ByteCount
        self.maximumAggregateDisplayUTF8ByteCount = maximumAggregateDisplayUTF8ByteCount
        self.maximumDisclosureJSONByteCount = maximumDisclosureJSONByteCount
        self.certificateLimits = certificateLimits
        self.walletLimits = walletLimits
        self.pushDropLimits = pushDropLimits
        self.beefLimits = beefLimits
    }
}

/// Options for an identity disclosure transaction.
public struct IdentityClientOptions:
    Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let protocolID: WalletProtocolID
    public let keyID: WalletKeyID
    public let tokenAmount: UInt64
    public let outputIndex: UInt32

    public init(
        protocolID: WalletProtocolID? = nil,
        keyID: WalletKeyID? = nil,
        tokenAmount: UInt64 = 1,
        outputIndex: UInt32 = 0
    ) throws {
        guard outputIndex == 0 else {
            throw IdentityError.unsupportedOutputIndex(outputIndex)
        }
        guard tokenAmount > 0 else {
            throw IdentityError.invalidTokenAmount
        }
        if let protocolID {
            self.protocolID = protocolID
        } else {
            self.protocolID = try WalletProtocolID(
                securityLevel: .everyAppAndCounterparty,
                name: "identity"
            )
        }
        if let keyID {
            self.keyID = keyID
        } else {
            self.keyID = try WalletKeyID("1")
        }
        self.tokenAmount = tokenAmount
        self.outputIndex = outputIndex
    }

    public var description: String { "<redacted identity client options>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// One identity formatted for display.
public struct DisplayableIdentity:
    Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let name: String
    public let avatarURL: String
    public let abbreviatedKey: String
    public let identityKey: String
    public let badgeIconURL: String
    public let badgeLabel: String
    public let badgeClickURL: String

    public init(
        name: String,
        avatarURL: String,
        abbreviatedKey: String,
        identityKey: String,
        badgeIconURL: String,
        badgeLabel: String,
        badgeClickURL: String,
        limits: IdentityLimits
    ) throws {
        let values = [
            name, avatarURL, abbreviatedKey, identityKey,
            badgeIconURL, badgeLabel, badgeClickURL,
        ]
        var aggregate = 0
        for value in values {
            let count = value.utf8.count
            guard count <= limits.maximumDisplayTextUTF8ByteCount else {
                throw IdentityError.displayTextTooLarge(
                    actual: count,
                    maximum: limits.maximumDisplayTextUTF8ByteCount
                )
            }
            let (next, overflow) = aggregate.addingReportingOverflow(count)
            guard !overflow else { throw IdentityError.sizeOverflow }
            aggregate = next
        }
        guard aggregate <= limits.maximumAggregateDisplayUTF8ByteCount else {
            throw IdentityError.aggregateDisplayTextTooLarge(
                actual: aggregate,
                maximum: limits.maximumAggregateDisplayUTF8ByteCount
            )
        }
        self.name = name
        self.avatarURL = avatarURL
        self.abbreviatedKey = abbreviatedKey
        self.identityKey = identityKey
        self.badgeIconURL = badgeIconURL
        self.badgeLabel = badgeLabel
        self.badgeClickURL = badgeClickURL
    }

    public var description: String { "<redacted displayable identity>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    public static func unknown(
        avatarURL: String = "XUUB8bbn9fEthk15Ge3zTQXypUShfC94vFjp65v7u5CQ8qkpxzst",
        limits: IdentityLimits
    ) throws -> Self {
        try Self(
            name: "Unknown Identity",
            avatarURL: avatarURL,
            abbreviatedKey: "",
            identityKey: "",
            badgeIconURL: "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG",
            badgeLabel: "Not verified by anyone you trust.",
            badgeClickURL: "https://projectbabbage.com/docs/unknown-identity",
            limits: limits
        )
    }
}

/// Certificate types recognized by the pinned Go identity client.
public enum KnownIdentityType: String, CaseIterable, Hashable, Sendable {
    case identiCert = "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="
    case discord = "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4="
    case phone = "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A="
    case x = "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="
    case registrant = "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0="
    case email = "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA="
    case anyone = "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis="
    case `self` = "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g="
    case cool = "AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo="

    public init?(certificateType: CertificateTypeID) {
        self.init(rawValue: certificateType.base64)
    }

    public var certificateType: CertificateTypeID {
        get throws { try CertificateTypeID(base64: rawValue) }
    }
}

/// Identity operations that can fail after input validation.
public enum IdentityOperation: String, Hashable, Sendable {
    case proveCertificate
    case createAction
    case createDisclosureScript
    case discoverByIdentityKey
    case discoverByAttributes
}

/// Bounded identity-client failures. No case retains attacker-controlled text.
public enum IdentityError: Error, Equatable, Sendable {
    case invalidLimits
    case sizeOverflow
    case unsupportedOutputIndex(UInt32)
    case invalidTokenAmount
    case tooManyIdentities(actual: Int, maximum: Int)
    case displayTextTooLarge(actual: Int, maximum: Int)
    case aggregateDisplayTextTooLarge(actual: Int, maximum: Int)
    case certificateHasNoFields
    case noFieldsToReveal
    case tooManyFieldsToReveal(actual: Int, maximum: Int)
    case duplicateFieldToReveal
    case requestedFieldIsAbsent
    case inconsistentProvedKeyring
    case certificateVerificationFailed
    case disclosureJSONTooLarge(actual: Int, maximum: Int)
    case walletOperationFailed(IdentityOperation)
    case inconsistentDiscoveryTotal
    case missingCompletedTransaction
    case missingSubjectTransaction
    case broadcastTransactionIDMismatch
    case broadcastFailed
}
