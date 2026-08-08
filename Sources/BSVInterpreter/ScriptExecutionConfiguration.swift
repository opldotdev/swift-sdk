import BSVScript

/// The consensus rule set used to evaluate a locking-script pair.
public enum ScriptExecutionEra: String, Hashable, Sendable {
    case beforeGenesis
    case afterGenesis
    case afterChronicle
}

/// Optional validation rules layered on top of the selected consensus era.
public struct ScriptVerificationFlags: OptionSet, Hashable, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    public static let payToScriptHash = Self(rawValue: 1 << 0)
    public static let strictMultiSignatureDummy = Self(rawValue: 1 << 1)
    public static let discourageUpgradeableNops = Self(rawValue: 1 << 2)
    public static let checkLockTimeVerify = Self(rawValue: 1 << 3)
    public static let checkSequenceVerify = Self(rawValue: 1 << 4)
    public static let cleanStack = Self(rawValue: 1 << 5)
    public static let derSignatures = Self(rawValue: 1 << 6)
    public static let lowS = Self(rawValue: 1 << 7)
    public static let minimalData = Self(rawValue: 1 << 8)
    public static let nullFail = Self(rawValue: 1 << 9)
    public static let signaturePushOnly = Self(rawValue: 1 << 10)
    public static let enableForkID = Self(rawValue: 1 << 11)
    public static let strictEncoding = Self(rawValue: 1 << 12)
    public static let bip143SignatureHash = Self(rawValue: 1 << 13)
    public static let minimalIf = Self(rawValue: 1 << 14)
}

/// Caller-owned work and memory ceilings.
///
/// These limits are deliberately separate from consensus limits. Exceeding a
/// caller ceiling produces `resourceBudgetExceeded`, so a local operational
/// policy can never be misreported as a consensus-invalid transaction.
public struct ScriptResourceLimits: Hashable, Sendable {
    public let maximumScriptByteCount: Int
    public let maximumPushDataByteCount: Int
    public let maximumStackItemCount: Int
    public let maximumStackMemoryByteCount: Int
    public let maximumOperationCountPerScript: Int
    public let maximumConditionalDepth: Int
    public let maximumScriptNumberByteCount: Int

    public init(
        maximumScriptByteCount: Int,
        maximumPushDataByteCount: Int,
        maximumStackItemCount: Int,
        maximumStackMemoryByteCount: Int,
        maximumOperationCountPerScript: Int,
        maximumConditionalDepth: Int,
        maximumScriptNumberByteCount: Int
    ) {
        self.maximumScriptByteCount = maximumScriptByteCount
        self.maximumPushDataByteCount = maximumPushDataByteCount
        self.maximumStackItemCount = maximumStackItemCount
        self.maximumStackMemoryByteCount = maximumStackMemoryByteCount
        self.maximumOperationCountPerScript = maximumOperationCountPerScript
        self.maximumConditionalDepth = maximumConditionalDepth
        self.maximumScriptNumberByteCount = maximumScriptNumberByteCount
    }

    /// A practical default that admits every before-Genesis consensus script and the
    /// Go SDK's after-Genesis Script-number ceiling without unbounded allocation.
    public static let standard = Self(
        maximumScriptByteCount: 32 * 1_024 * 1_024,
        maximumPushDataByteCount: 32 * 1_024 * 1_024,
        maximumStackItemCount: 1_000_000,
        maximumStackMemoryByteCount: 64 * 1_024 * 1_024,
        maximumOperationCountPerScript: 1_000_000,
        maximumConditionalDepth: 10_000,
        maximumScriptNumberByteCount: 32 * 1_024 * 1_024
    )
}

public enum ScriptConfigurationError: Error, Equatable, Sendable {
    case nonPositiveLimit(name: String, value: Int)
    case cleanStackRequiresPayToScriptHash
}

/// Fully validated execution policy for one Script evaluation.
public struct ScriptExecutionConfiguration: Hashable, Sendable {
    public let era: ScriptExecutionEra
    public let flags: ScriptVerificationFlags
    public let resourceLimits: ScriptResourceLimits

    public init(
        era: ScriptExecutionEra,
        flags: ScriptVerificationFlags = [],
        resourceLimits: ScriptResourceLimits
    ) throws {
        let values = [
            ("maximumScriptByteCount", resourceLimits.maximumScriptByteCount),
            ("maximumPushDataByteCount", resourceLimits.maximumPushDataByteCount),
            ("maximumStackItemCount", resourceLimits.maximumStackItemCount),
            ("maximumStackMemoryByteCount", resourceLimits.maximumStackMemoryByteCount),
            ("maximumOperationCountPerScript", resourceLimits.maximumOperationCountPerScript),
            ("maximumConditionalDepth", resourceLimits.maximumConditionalDepth),
            ("maximumScriptNumberByteCount", resourceLimits.maximumScriptNumberByteCount),
        ]
        if let invalid = values.first(where: { $0.1 <= 0 }) {
            throw ScriptConfigurationError.nonPositiveLimit(
                name: invalid.0,
                value: invalid.1
            )
        }
        if flags.contains(.cleanStack), !flags.contains(.payToScriptHash) {
            throw ScriptConfigurationError.cleanStackRequiresPayToScriptHash
        }

        self.era = era
        self.flags = flags.contains(.enableForkID)
            ? flags.union(.strictEncoding)
            : flags
        self.resourceLimits = resourceLimits
    }
}

package struct ScriptConsensusLimits: Sendable {
    let maximumScriptByteCount: Int
    let maximumPushDataByteCount: Int
    let maximumStackItemCount: Int
    let maximumOperationCountPerScript: Int
    let maximumScriptNumberByteCount: Int

    static func forEra(_ era: ScriptExecutionEra) -> Self {
        switch era {
        case .beforeGenesis:
            Self(
                maximumScriptByteCount: 10_000,
                maximumPushDataByteCount: 520,
                maximumStackItemCount: 1_000,
                maximumOperationCountPerScript: 500,
                maximumScriptNumberByteCount: ScriptNumber.beforeGenesisMaximumByteCount
            )
        case .afterGenesis:
            Self(
                maximumScriptByteCount: Int(Int32.max),
                maximumPushDataByteCount: Int(Int32.max),
                maximumStackItemCount: Int(Int32.max),
                maximumOperationCountPerScript: Int(Int32.max),
                maximumScriptNumberByteCount: 750_000
            )
        case .afterChronicle:
            Self(
                maximumScriptByteCount: Int(Int32.max),
                maximumPushDataByteCount: Int(Int32.max),
                maximumStackItemCount: Int(Int32.max),
                maximumOperationCountPerScript: Int(Int32.max),
                maximumScriptNumberByteCount: 32 * 1_024 * 1_024
            )
        }
    }
}
