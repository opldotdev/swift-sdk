import BSVCore
import BSVKeys
import BSVTransaction

public enum WalletTrustSelf: String, CaseIterable, Codable, Sendable {
    case known
    public init(_ text: String) throws {
        guard let value = Self(rawValue: text) else {
            throw WalletABIError.invalidEnumText(type: "WalletTrustSelf", value: text)
        }
        self = value
    }
}

public enum WalletActionResultStatus: String, CaseIterable, Codable, Sendable {
    case unproven, sending, failed
    public init(_ text: String) throws {
        guard let value = Self(rawValue: text) else {
            throw WalletABIError.invalidEnumText(type: "WalletActionResultStatus", value: text)
        }
        self = value
    }
}

public enum WalletActionStatus: String, CaseIterable, Codable, Sendable {
    case completed, unprocessed, sending, unproven, unsigned, nosend, nonfinal
    public init(_ text: String) throws {
        guard let value = Self(rawValue: text) else {
            throw WalletABIError.invalidEnumText(type: "WalletActionStatus", value: text)
        }
        self = value
    }
}

/// How an application-supplied input will be unlocked.
public enum WalletInputUnlocking: Equatable, Sendable {
    case script([UInt8])
    case scriptLength(UInt32)
}

public struct WalletCreateActionInput: Equatable, Sendable {
    public let outpoint: Outpoint
    public let inputDescription: String
    public let unlocking: WalletInputUnlocking
    public let sequenceNumber: UInt32?
    package var bytePayloadCount: Int {
        if case .script(let bytes) = unlocking { return bytes.count }
        return 0
    }

    public init(
        outpoint: Outpoint,
        inputDescription: String,
        unlockingScript: [UInt8]? = nil,
        unlockingScriptLength: UInt32? = nil,
        sequenceNumber: UInt32? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireText(inputDescription, kind: "input description", limits: limits)
        switch (unlockingScript, unlockingScriptLength) {
        case (.some(let script), nil):
            try walletABIRequireBytes(script.count, kind: "unlocking script", limits: limits)
            self.unlocking = .script(script)
        case (nil, .some(let length)):
            self.unlocking = .scriptLength(length)
        case (.some, .some):
            throw WalletABIError.conflictingUnionMembers(
                "unlockingScript and unlockingScriptLength are mutually exclusive"
            )
        case (nil, nil):
            throw WalletABIError.invalidFieldRelation(
                "an action input requires an unlocking script or its length"
            )
        }
        self.outpoint = outpoint
        self.inputDescription = inputDescription
        self.sequenceNumber = sequenceNumber
    }
}

public struct WalletCreateActionOutput: Equatable, Sendable {
    public let lockingScript: [UInt8]
    public let satoshis: UInt64
    public let outputDescription: String
    public let basket: String?
    public let customInstructions: String?
    public let tags: [String]
    package var bytePayloadCount: Int { lockingScript.count }

    public init(
        lockingScript: [UInt8],
        satoshis: UInt64,
        outputDescription: String,
        basket: String? = nil,
        customInstructions: String? = nil,
        tags: [String] = [],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireBytes(lockingScript.count, kind: "locking script", limits: limits)
        try walletABIRequireText(outputDescription, kind: "output description", limits: limits)
        if let basket { try walletABIRequireText(basket, kind: "basket", limits: limits) }
        if let customInstructions {
            try walletABIRequireText(customInstructions, kind: "custom instructions", limits: limits)
        }
        try walletABIValidateTexts(
            tags, kind: "tags", countLimit: limits.maximumTagCount, limits: limits
        )
        try walletABIRequireAggregate(
            [lockingScript.count, outputDescription.utf8.count, basket?.utf8.count ?? 0,
             customInstructions?.utf8.count ?? 0] + tags.map(\.utf8.count),
            limits: limits
        )
        self.lockingScript = lockingScript
        self.satoshis = satoshis
        self.outputDescription = outputDescription
        self.basket = basket
        self.customInstructions = customInstructions
        self.tags = tags
    }
}

public struct WalletCreateActionOptions: Equatable, Sendable {
    public let signAndProcess: Bool?
    public let acceptDelayedBroadcast: Bool?
    public let trustSelf: WalletTrustSelf?
    public let knownTransactionIDs: [TransactionID]?
    public let returnTransactionIDOnly: Bool?
    public let noSend: Bool?
    public let noSendChange: [Outpoint]?
    public let sendWith: [TransactionID]?
    public let randomizeOutputs: Bool?

    public init(
        signAndProcess: Bool? = nil,
        acceptDelayedBroadcast: Bool? = nil,
        trustSelf: WalletTrustSelf? = nil,
        knownTransactionIDs: [TransactionID]? = nil,
        returnTransactionIDOnly: Bool? = nil,
        noSend: Bool? = nil,
        noSendChange: [Outpoint]? = nil,
        sendWith: [TransactionID]? = nil,
        randomizeOutputs: Bool? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        if let knownTransactionIDs {
            try walletABIRequireCount(
                knownTransactionIDs.count,
                kind: "known transaction IDs",
                maximum: limits.maximumCollectionCount
            )
        }
        if let noSendChange {
            try walletABIRequireCount(
                noSendChange.count, kind: "no-send change", maximum: limits.maximumCollectionCount
            )
            guard noSend == true else {
                throw WalletABIError.invalidFieldRelation("noSendChange requires noSend to be true")
            }
        }
        if let sendWith {
            try walletABIRequireCount(
                sendWith.count, kind: "send-with transaction IDs", maximum: limits.maximumCollectionCount
            )
        }
        self.signAndProcess = signAndProcess
        self.acceptDelayedBroadcast = acceptDelayedBroadcast
        self.trustSelf = trustSelf
        self.knownTransactionIDs = knownTransactionIDs
        self.returnTransactionIDOnly = returnTransactionIDOnly
        self.noSend = noSend
        self.noSendChange = noSendChange
        self.sendWith = sendWith
        self.randomizeOutputs = randomizeOutputs
    }
}

public struct WalletCreateActionRequest: Equatable, Sendable {
    public let description: String
    public let inputBEEF: BEEF?
    public let inputs: [WalletCreateActionInput]?
    public let outputs: [WalletCreateActionOutput]?
    public let lockTime: UInt32?
    public let version: UInt32?
    public let labels: [String]?
    public let options: WalletCreateActionOptions?

    public init(
        description: String,
        inputBEEF: BEEF? = nil,
        inputs: [WalletCreateActionInput]? = nil,
        outputs: [WalletCreateActionOutput]? = nil,
        lockTime: UInt32? = nil,
        version: UInt32? = nil,
        labels: [String]? = nil,
        options: WalletCreateActionOptions? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireText(description, kind: "action description", limits: limits)
        if let inputs {
            try walletABIRequireCount(inputs.count, kind: "inputs", maximum: limits.maximumCollectionCount)
        }
        if let outputs {
            try walletABIRequireCount(outputs.count, kind: "outputs", maximum: limits.maximumCollectionCount)
        }
        if let labels {
            try walletABIValidateTexts(
                labels, kind: "labels", countLimit: limits.maximumLabelCount, limits: limits
            )
        }
        try walletABIRequireAggregate(
            (inputs?.map(\.bytePayloadCount) ?? []) + (outputs?.map(\.bytePayloadCount) ?? []),
            limits: limits
        )
        self.description = description
        self.inputBEEF = inputBEEF
        self.inputs = inputs
        self.outputs = outputs
        self.lockTime = lockTime
        self.version = version
        self.labels = labels
        self.options = options
    }
}

public struct WalletSendWithResult: Equatable, Sendable {
    public let transactionID: TransactionID
    public let status: WalletActionResultStatus
    public init(transactionID: TransactionID, status: WalletActionResultStatus) {
        self.transactionID = transactionID
        self.status = status
    }
}

public struct WalletSignableTransaction:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let transaction: AtomicBEEF
    public let reference: WalletBase64Data
    public init(transaction: AtomicBEEF, reference: WalletBase64Data) {
        self.transaction = transaction
        self.reference = reference
    }
    public var description: String { "<redacted signable wallet transaction>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletCreateActionResult: Equatable, Sendable {
    public let transactionID: TransactionID?
    public let transaction: AtomicBEEF?
    public let noSendChange: [Outpoint]?
    public let sendWithResults: [WalletSendWithResult]?
    public let signableTransaction: WalletSignableTransaction?

    public init(
        transactionID: TransactionID? = nil,
        transaction: AtomicBEEF? = nil,
        noSendChange: [Outpoint]? = nil,
        sendWithResults: [WalletSendWithResult]? = nil,
        signableTransaction: WalletSignableTransaction? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        if signableTransaction != nil, transactionID != nil || transaction != nil {
            throw WalletABIError.conflictingUnionMembers(
                "a signable transaction cannot coexist with a completed transaction"
            )
        }
        if let noSendChange {
            try walletABIRequireCount(
                noSendChange.count, kind: "no-send change", maximum: limits.maximumCollectionCount
            )
        }
        if let sendWithResults {
            try walletABIRequireCount(
                sendWithResults.count, kind: "send-with results", maximum: limits.maximumCollectionCount
            )
        }
        guard transactionID != nil || transaction != nil || signableTransaction != nil else {
            throw WalletABIError.invalidFieldRelation("createAction result has no transaction value")
        }
        self.transactionID = transactionID
        self.transaction = transaction
        self.noSendChange = noSendChange
        self.sendWithResults = sendWithResults
        self.signableTransaction = signableTransaction
    }
}

public struct WalletSignActionSpend: Equatable, Sendable {
    public let unlockingScript: [UInt8]
    public let sequenceNumber: UInt32?
    public init(
        unlockingScript: [UInt8],
        sequenceNumber: UInt32? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireBytes(unlockingScript.count, kind: "unlocking script", limits: limits)
        self.unlockingScript = unlockingScript
        self.sequenceNumber = sequenceNumber
    }
}

public struct WalletSignActionOptions: Equatable, Sendable {
    public let acceptDelayedBroadcast: Bool?
    public let returnTransactionIDOnly: Bool?
    public let noSend: Bool?
    public let sendWith: [TransactionID]?
    public init(
        acceptDelayedBroadcast: Bool? = nil,
        returnTransactionIDOnly: Bool? = nil,
        noSend: Bool? = nil,
        sendWith: [TransactionID]? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        if let sendWith {
            try walletABIRequireCount(
                sendWith.count, kind: "send-with transaction IDs", maximum: limits.maximumCollectionCount
            )
        }
        self.acceptDelayedBroadcast = acceptDelayedBroadcast
        self.returnTransactionIDOnly = returnTransactionIDOnly
        self.noSend = noSend
        self.sendWith = sendWith
    }
}

public struct WalletSignActionRequest:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let reference: WalletBase64Data
    public let spends: [UInt32: WalletSignActionSpend]
    public let options: WalletSignActionOptions?
    public init(
        reference: WalletBase64Data,
        spends: [UInt32: WalletSignActionSpend],
        options: WalletSignActionOptions? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(spends.count, kind: "spends", maximum: limits.maximumCollectionCount)
        try walletABIRequireAggregate(
            [reference.bytes.count] + spends.values.map(\.unlockingScript.count), limits: limits
        )
        self.reference = reference
        self.spends = spends
        self.options = options
    }
    public var description: String { "<redacted sign-action request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletSignActionResult: Equatable, Sendable {
    public let transactionID: TransactionID?
    public let transaction: AtomicBEEF?
    public let sendWithResults: [WalletSendWithResult]?
    public init(
        transactionID: TransactionID? = nil,
        transaction: AtomicBEEF? = nil,
        sendWithResults: [WalletSendWithResult]? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        guard transactionID != nil || transaction != nil else {
            throw WalletABIError.invalidFieldRelation("signAction result has no transaction value")
        }
        if let sendWithResults {
            try walletABIRequireCount(
                sendWithResults.count, kind: "send-with results", maximum: limits.maximumCollectionCount
            )
        }
        self.transactionID = transactionID
        self.transaction = transaction
        self.sendWithResults = sendWithResults
    }
}

public struct WalletAbortActionRequest:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let reference: WalletBase64Data
    public init(reference: WalletBase64Data) { self.reference = reference }
    public var description: String { "<redacted abort-action request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletAbortActionResult: Equatable, Sendable {
    public let aborted: Bool
    public init(aborted: Bool) { self.aborted = aborted }
}

public struct WalletActionInput: Equatable, Sendable {
    public let sourceOutpoint: Outpoint
    public let sourceSatoshis: UInt64
    public let sourceLockingScript: [UInt8]?
    public let unlockingScript: [UInt8]?
    public let inputDescription: String
    public let sequenceNumber: UInt32
    package var bytePayloadCount: Int {
        (sourceLockingScript?.count ?? 0) + (unlockingScript?.count ?? 0)
    }
    public init(
        sourceOutpoint: Outpoint,
        sourceSatoshis: UInt64,
        sourceLockingScript: [UInt8]? = nil,
        unlockingScript: [UInt8]? = nil,
        inputDescription: String,
        sequenceNumber: UInt32,
        limits: WalletABILimits = .standard
    ) throws {
        if let sourceLockingScript {
            try walletABIRequireBytes(sourceLockingScript.count, kind: "source locking script", limits: limits)
        }
        if let unlockingScript {
            try walletABIRequireBytes(unlockingScript.count, kind: "unlocking script", limits: limits)
        }
        try walletABIRequireAggregate(
            [sourceLockingScript?.count ?? 0, unlockingScript?.count ?? 0], limits: limits
        )
        try walletABIRequireText(inputDescription, kind: "input description", limits: limits)
        self.sourceOutpoint = sourceOutpoint
        self.sourceSatoshis = sourceSatoshis
        self.sourceLockingScript = sourceLockingScript
        self.unlockingScript = unlockingScript
        self.inputDescription = inputDescription
        self.sequenceNumber = sequenceNumber
    }
}

public struct WalletActionOutput: Equatable, Sendable {
    public let satoshis: UInt64
    public let lockingScript: [UInt8]?
    public let spendable: Bool
    public let customInstructions: String?
    public let tags: [String]
    public let outputIndex: UInt32
    public let outputDescription: String
    public let basket: String
    package var bytePayloadCount: Int { lockingScript?.count ?? 0 }
    public init(
        satoshis: UInt64,
        lockingScript: [UInt8]? = nil,
        spendable: Bool,
        customInstructions: String? = nil,
        tags: [String],
        outputIndex: UInt32,
        outputDescription: String,
        basket: String,
        limits: WalletABILimits = .standard
    ) throws {
        if let lockingScript {
            try walletABIRequireBytes(lockingScript.count, kind: "locking script", limits: limits)
        }
        if let customInstructions {
            try walletABIRequireText(customInstructions, kind: "custom instructions", limits: limits)
        }
        try walletABIValidateTexts(tags, kind: "tags", countLimit: limits.maximumTagCount, limits: limits)
        try walletABIRequireText(outputDescription, kind: "output description", limits: limits)
        try walletABIRequireText(basket, kind: "basket", limits: limits)
        self.satoshis = satoshis
        self.lockingScript = lockingScript
        self.spendable = spendable
        self.customInstructions = customInstructions
        self.tags = tags
        self.outputIndex = outputIndex
        self.outputDescription = outputDescription
        self.basket = basket
    }
}

public struct WalletAction: Equatable, Sendable {
    public let transactionID: TransactionID
    public let satoshis: Int64
    public let status: WalletActionStatus
    public let isOutgoing: Bool
    public let description: String
    public let labels: [String]?
    public let version: UInt32
    public let lockTime: UInt32
    public let inputs: [WalletActionInput]?
    public let outputs: [WalletActionOutput]?
    package var bytePayloadCount: Int {
        (inputs?.reduce(0) { $0 + $1.bytePayloadCount } ?? 0)
            + (outputs?.reduce(0) { $0 + $1.bytePayloadCount } ?? 0)
    }
    public init(
        transactionID: TransactionID,
        satoshis: Int64,
        status: WalletActionStatus,
        isOutgoing: Bool,
        description: String,
        labels: [String]? = nil,
        version: UInt32,
        lockTime: UInt32,
        inputs: [WalletActionInput]? = nil,
        outputs: [WalletActionOutput]? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireText(description, kind: "action description", limits: limits)
        if let labels {
            try walletABIValidateTexts(labels, kind: "labels", countLimit: limits.maximumLabelCount, limits: limits)
        }
        if let inputs {
            try walletABIRequireCount(inputs.count, kind: "inputs", maximum: limits.maximumCollectionCount)
        }
        if let outputs {
            try walletABIRequireCount(outputs.count, kind: "outputs", maximum: limits.maximumCollectionCount)
        }
        self.transactionID = transactionID
        self.satoshis = satoshis
        self.status = status
        self.isOutgoing = isOutgoing
        self.description = description
        self.labels = labels
        self.version = version
        self.lockTime = lockTime
        self.inputs = inputs
        self.outputs = outputs
    }
}

public struct WalletListActionsRequest: Equatable, Sendable {
    public let labels: [String]
    public let labelQueryMode: WalletQueryMode?
    public let includeLabels: Bool?
    public let includeInputs: Bool?
    public let includeInputSourceLockingScripts: Bool?
    public let includeInputUnlockingScripts: Bool?
    public let includeOutputs: Bool?
    public let includeOutputLockingScripts: Bool?
    public let pagination: WalletPagination
    public let seekPermission: Bool?
    public init(
        labels: [String],
        labelQueryMode: WalletQueryMode? = nil,
        includeLabels: Bool? = nil,
        includeInputs: Bool? = nil,
        includeInputSourceLockingScripts: Bool? = nil,
        includeInputUnlockingScripts: Bool? = nil,
        includeOutputs: Bool? = nil,
        includeOutputLockingScripts: Bool? = nil,
        pagination: WalletPagination = .standard,
        seekPermission: Bool? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIValidateTexts(labels, kind: "labels", countLimit: limits.maximumLabelCount, limits: limits)
        self.labels = labels
        self.labelQueryMode = labelQueryMode
        self.includeLabels = includeLabels
        self.includeInputs = includeInputs
        self.includeInputSourceLockingScripts = includeInputSourceLockingScripts
        self.includeInputUnlockingScripts = includeInputUnlockingScripts
        self.includeOutputs = includeOutputs
        self.includeOutputLockingScripts = includeOutputLockingScripts
        self.pagination = pagination
        self.seekPermission = seekPermission
    }
}

public struct WalletListActionsResult: Equatable, Sendable {
    public let totalActions: UInt32
    public let actions: [WalletAction]
    public init(
        totalActions: UInt32,
        actions: [WalletAction],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(actions.count, kind: "actions", maximum: limits.maximumCollectionCount)
        try walletABIRequireAggregate(actions.map(\.bytePayloadCount), limits: limits)
        self.totalActions = totalActions
        self.actions = actions
    }
}

public struct WalletOutput: Equatable, Sendable {
    public let satoshis: UInt64
    public let lockingScript: [UInt8]?
    public let spendable: Bool
    public let customInstructions: String?
    public let tags: [String]?
    public let outpoint: Outpoint
    public let labels: [String]?
    package var bytePayloadCount: Int { lockingScript?.count ?? 0 }
    public init(
        satoshis: UInt64,
        lockingScript: [UInt8]? = nil,
        spendable: Bool,
        customInstructions: String? = nil,
        tags: [String]? = nil,
        outpoint: Outpoint,
        labels: [String]? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        if let lockingScript { try walletABIRequireBytes(lockingScript.count, kind: "locking script", limits: limits) }
        if let customInstructions { try walletABIRequireText(customInstructions, kind: "custom instructions", limits: limits) }
        if let tags { try walletABIValidateTexts(tags, kind: "tags", countLimit: limits.maximumTagCount, limits: limits) }
        if let labels { try walletABIValidateTexts(labels, kind: "labels", countLimit: limits.maximumLabelCount, limits: limits) }
        self.satoshis = satoshis
        self.lockingScript = lockingScript
        self.spendable = spendable
        self.customInstructions = customInstructions
        self.tags = tags
        self.outpoint = outpoint
        self.labels = labels
    }
}

public struct WalletListOutputsRequest: Equatable, Sendable {
    public let basket: String
    public let tags: [String]
    public let tagQueryMode: WalletQueryMode?
    public let include: WalletOutputInclude?
    public let includeCustomInstructions: Bool?
    public let includeTags: Bool?
    public let includeLabels: Bool?
    public let pagination: WalletPagination
    public let seekPermission: Bool?
    public init(
        basket: String,
        tags: [String] = [],
        tagQueryMode: WalletQueryMode? = nil,
        include: WalletOutputInclude? = nil,
        includeCustomInstructions: Bool? = nil,
        includeTags: Bool? = nil,
        includeLabels: Bool? = nil,
        pagination: WalletPagination = .standard,
        seekPermission: Bool? = nil,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireText(basket, kind: "basket", limits: limits)
        try walletABIValidateTexts(tags, kind: "tags", countLimit: limits.maximumTagCount, limits: limits)
        self.basket = basket
        self.tags = tags
        self.tagQueryMode = tagQueryMode
        self.include = include
        self.includeCustomInstructions = includeCustomInstructions
        self.includeTags = includeTags
        self.includeLabels = includeLabels
        self.pagination = pagination
        self.seekPermission = seekPermission
    }
}

public struct WalletListOutputsResult: Equatable, Sendable {
    public let totalOutputs: UInt32
    public let beef: BEEF?
    public let outputs: [WalletOutput]
    public init(
        totalOutputs: UInt32,
        beef: BEEF? = nil,
        outputs: [WalletOutput],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireCount(outputs.count, kind: "outputs", maximum: limits.maximumCollectionCount)
        try walletABIRequireAggregate(outputs.map(\.bytePayloadCount), limits: limits)
        self.totalOutputs = totalOutputs
        self.beef = beef
        self.outputs = outputs
    }
}

public struct WalletRelinquishOutputRequest: Equatable, Sendable {
    public let basket: String
    public let output: Outpoint
    public init(basket: String, output: Outpoint, limits: WalletABILimits = .standard) throws {
        try walletABIRequireText(basket, kind: "basket", limits: limits)
        self.basket = basket
        self.output = output
    }
}

public struct WalletRelinquishOutputResult: Equatable, Sendable {
    public let relinquished: Bool
    public init(relinquished: Bool) { self.relinquished = relinquished }
}

public struct WalletPaymentRemittance:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let derivationPrefix: WalletBase64Data
    public let derivationSuffix: WalletBase64Data
    public let senderIdentityKey: PublicKey
    public init(
        derivationPrefix: WalletBase64Data,
        derivationSuffix: WalletBase64Data,
        senderIdentityKey: PublicKey,
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireAggregate(
            [derivationPrefix.bytes.count, derivationSuffix.bytes.count], limits: limits
        )
        self.derivationPrefix = derivationPrefix
        self.derivationSuffix = derivationSuffix
        self.senderIdentityKey = senderIdentityKey
    }
    public var description: String { "<redacted payment remittance>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}

public struct WalletBasketInsertion: Equatable, Sendable {
    public let basket: String
    public let customInstructions: String?
    public let tags: [String]
    public init(
        basket: String,
        customInstructions: String? = nil,
        tags: [String] = [],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireText(basket, kind: "basket", limits: limits)
        if let customInstructions { try walletABIRequireText(customInstructions, kind: "custom instructions", limits: limits) }
        try walletABIValidateTexts(tags, kind: "tags", countLimit: limits.maximumTagCount, limits: limits)
        self.basket = basket
        self.customInstructions = customInstructions
        self.tags = tags
    }
}

public enum WalletInternalizeProtocol: String, CaseIterable, Codable, Sendable {
    case walletPayment = "wallet payment"
    case basketInsertion = "basket insertion"
    public init(_ text: String) throws {
        guard let value = Self(rawValue: text) else {
            throw WalletABIError.invalidEnumText(type: "WalletInternalizeProtocol", value: text)
        }
        self = value
    }
}

public enum WalletInternalizeRemittance: Equatable, Sendable {
    case walletPayment(WalletPaymentRemittance)
    case basketInsertion(WalletBasketInsertion)
    public var `protocol`: WalletInternalizeProtocol {
        switch self {
        case .walletPayment: .walletPayment
        case .basketInsertion: .basketInsertion
        }
    }
    package var bytePayloadCount: Int {
        switch self {
        case .walletPayment(let payment):
            payment.derivationPrefix.bytes.count + payment.derivationSuffix.bytes.count
        case .basketInsertion:
            0
        }
    }
}

public struct WalletInternalizeOutput: Equatable, Sendable {
    public let outputIndex: UInt32
    public let remittance: WalletInternalizeRemittance
    public init(outputIndex: UInt32, remittance: WalletInternalizeRemittance) {
        self.outputIndex = outputIndex
        self.remittance = remittance
    }

    public init(
        outputIndex: UInt32,
        protocol: WalletInternalizeProtocol,
        paymentRemittance: WalletPaymentRemittance? = nil,
        insertionRemittance: WalletBasketInsertion? = nil
    ) throws {
        switch (`protocol`, paymentRemittance, insertionRemittance) {
        case (.walletPayment, .some(let payment), nil):
            self.init(outputIndex: outputIndex, remittance: .walletPayment(payment))
        case (.basketInsertion, nil, .some(let insertion)):
            self.init(outputIndex: outputIndex, remittance: .basketInsertion(insertion))
        default:
            throw WalletABIError.conflictingUnionMembers(
                "internalize protocol must have exactly its matching remittance"
            )
        }
    }
}

public struct WalletInternalizeActionRequest: Equatable, Sendable {
    public let transaction: AtomicBEEF
    public let description: String
    public let labels: [String]
    public let seekPermission: Bool?
    public let outputs: [WalletInternalizeOutput]
    public init(
        transaction: AtomicBEEF,
        description: String,
        labels: [String] = [],
        seekPermission: Bool? = nil,
        outputs: [WalletInternalizeOutput],
        limits: WalletABILimits = .standard
    ) throws {
        try walletABIRequireText(description, kind: "action description", limits: limits)
        try walletABIValidateTexts(labels, kind: "labels", countLimit: limits.maximumLabelCount, limits: limits)
        try walletABIRequireCount(outputs.count, kind: "outputs", maximum: limits.maximumCollectionCount)
        try walletABIRequireAggregate(outputs.map { $0.remittance.bytePayloadCount }, limits: limits)
        self.transaction = transaction
        self.description = description
        self.labels = labels
        self.seekPermission = seekPermission
        self.outputs = outputs
    }
}

public struct WalletInternalizeActionResult: Equatable, Sendable {
    public let accepted: Bool
    public init(accepted: Bool) { self.accepted = accepted }
}
