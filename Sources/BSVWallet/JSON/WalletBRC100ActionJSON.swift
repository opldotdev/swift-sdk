import BSVCore
import BSVTransaction

extension WalletBRC100JSONCodec {
    func decodeActionRequest(call: WalletCall, bytes: [UInt8]) throws -> WalletWireActionRequest {
        switch call {
        case .createAction: .createAction(try decode(CreateActionDTO.self, bytes).model(self))
        case .signAction: .signAction(try decode(SignActionDTO.self, bytes).model(self))
        case .abortAction: .abortAction(try decode(AbortActionDTO.self, bytes).model(self))
        case .listActions: .listActions(try decode(ListActionsDTO.self, bytes).model(self))
        case .internalizeAction: .internalizeAction(try decode(InternalizeActionDTO.self, bytes).model(self))
        case .listOutputs: .listOutputs(try decode(ListOutputsDTO.self, bytes).model(self))
        case .relinquishOutput: .relinquishOutput(try decode(RelinquishOutputDTO.self, bytes).model(self))
        default: throw WalletJSONCodecError.requestCallMismatch(expected: .createAction, actual: call)
        }
    }

    func encodeActionRequest(_ request: WalletWireActionRequest) throws -> [UInt8] {
        switch request {
        case .createAction(let value): try encode(CreateActionDTO(value, codec: self))
        case .signAction(let value): try encode(SignActionDTO(value, codec: self))
        case .abortAction(let value): try encode(AbortActionDTO(value))
        case .listActions(let value): try encode(ListActionsDTO(value))
        case .internalizeAction(let value): try encode(InternalizeActionDTO(value, codec: self))
        case .listOutputs(let value): try encode(ListOutputsDTO(value))
        case .relinquishOutput(let value): try encode(RelinquishOutputDTO(value))
        }
    }

    func decodeActionResult(call: WalletCall, bytes: [UInt8]) throws -> WalletWireActionResult {
        switch call {
        case .createAction: .createAction(try decode(CreateActionResultDTO.self, bytes).model(self))
        case .signAction: .signAction(try decode(SignActionResultDTO.self, bytes).model(self))
        case .abortAction:
            .abortAction(.init(aborted: try decode(AbortResultDTO.self, bytes).aborted))
        case .listActions: .listActions(try decode(ListActionsResultDTO.self, bytes).model(self))
        case .internalizeAction:
            .internalizeAction(.init(accepted: try decode(AcceptedResultDTO.self, bytes).accepted))
        case .listOutputs: .listOutputs(try decode(ListOutputsResultDTO.self, bytes).model(self))
        case .relinquishOutput:
            .relinquishOutput(.init(relinquished: try decode(RelinquishedResultDTO.self, bytes).relinquished))
        default: throw WalletJSONCodecError.resultCallMismatch(expected: .createAction, actual: call)
        }
    }

    func encodeActionResult(_ result: WalletWireActionResult) throws -> [UInt8] {
        switch result {
        case .createAction(let value): try encode(CreateActionResultDTO(value, codec: self))
        case .signAction(let value): try encode(SignActionResultDTO(value, codec: self))
        case .abortAction(let value): try encode(AbortResultDTO(aborted: value.aborted))
        case .listActions(let value): try encode(ListActionsResultDTO(value, codec: self))
        case .internalizeAction(let value): try encode(AcceptedResultDTO(accepted: value.accepted))
        case .listOutputs(let value): try encode(ListOutputsResultDTO(value, codec: self))
        case .relinquishOutput(let value): try encode(RelinquishedResultDTO(relinquished: value.relinquished))
        }
    }
}

private struct CreateActionInputDTO: Codable {
    let outpoint: String
    let inputDescription: String
    let unlockingScript: String?
    let unlockingScriptLength: UInt32?
    let sequenceNumber: UInt32?

    init(_ value: WalletCreateActionInput) {
        outpoint = value.outpoint.description
        inputDescription = value.inputDescription
        switch value.unlocking {
        case .script(let bytes): unlockingScript = Hex.encode(bytes); unlockingScriptLength = nil
        case .scriptLength(let count): unlockingScript = nil; unlockingScriptLength = count
        }
        sequenceNumber = value.sequenceNumber
    }

    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletCreateActionInput {
        try WalletCreateActionInput(
            outpoint: Outpoint(outpoint),
            inputDescription: inputDescription,
            unlockingScript: try unlockingScript.map { try decodeCanonicalHex($0, maximum: codec.abiLimits.maximumBytePayloadCount) },
            unlockingScriptLength: unlockingScriptLength,
            sequenceNumber: sequenceNumber,
            limits: codec.abiLimits
        )
    }
}

private struct CreateActionOutputDTO: Codable {
    let lockingScript: String
    let satoshis: UInt64
    let outputDescription: String
    let basket: String?
    let customInstructions: String?
    let tags: [String]?

    init(_ value: WalletCreateActionOutput) {
        lockingScript = Hex.encode(value.lockingScript)
        satoshis = value.satoshis
        outputDescription = value.outputDescription
        basket = value.basket
        customInstructions = value.customInstructions
        tags = value.tags.isEmpty ? nil : value.tags
    }

    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletCreateActionOutput {
        try WalletCreateActionOutput(
            lockingScript: decodeCanonicalHex(lockingScript, maximum: codec.abiLimits.maximumBytePayloadCount),
            satoshis: satoshis,
            outputDescription: outputDescription,
            basket: basket,
            customInstructions: customInstructions,
            tags: tags ?? [],
            limits: codec.abiLimits
        )
    }
}

private struct CreateActionOptionsDTO: Codable {
    let signAndProcess: Bool?
    let acceptDelayedBroadcast: Bool?
    let trustSelf: WalletTrustSelf?
    let knownTxids: [String]?
    let returnTXIDOnly: Bool?
    let noSend: Bool?
    let noSendChange: [String]?
    let sendWith: [String]?
    let randomizeOutputs: Bool?

    init(_ value: WalletCreateActionOptions) {
        signAndProcess = value.signAndProcess
        acceptDelayedBroadcast = value.acceptDelayedBroadcast
        trustSelf = value.trustSelf
        knownTxids = value.knownTransactionIDs?.map(\.displayHex)
        returnTXIDOnly = value.returnTransactionIDOnly
        noSend = value.noSend
        noSendChange = value.noSendChange?.map(\.description)
        sendWith = value.sendWith?.map(\.displayHex)
        randomizeOutputs = value.randomizeOutputs
    }

    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletCreateActionOptions {
        try WalletCreateActionOptions(
            signAndProcess: signAndProcess,
            acceptDelayedBroadcast: acceptDelayedBroadcast,
            trustSelf: trustSelf,
            knownTransactionIDs: try knownTxids?.map(TransactionID.init(displayHex:)),
            returnTransactionIDOnly: returnTXIDOnly,
            noSend: noSend,
            noSendChange: try noSendChange?.map { try Outpoint($0) },
            sendWith: try sendWith?.map(TransactionID.init(displayHex:)),
            randomizeOutputs: randomizeOutputs,
            limits: codec.abiLimits
        )
    }
}

private struct CreateActionDTO: Codable {
    let description: String
    let inputBEEF: [UInt8]?
    let inputs: [CreateActionInputDTO]?
    let outputs: [CreateActionOutputDTO]?
    let lockTime: UInt32?
    let version: UInt32?
    let labels: [String]?
    let options: CreateActionOptionsDTO?

    init(_ value: WalletCreateActionRequest, codec: WalletBRC100JSONCodec) throws {
        description = value.description
        inputBEEF = try value.inputBEEF?.serialized(limits: codec.beefLimits)
        inputs = value.inputs?.map(CreateActionInputDTO.init)
        outputs = value.outputs?.map(CreateActionOutputDTO.init)
        lockTime = value.lockTime
        version = value.version
        labels = value.labels
        options = value.options.map(CreateActionOptionsDTO.init)
    }

    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletCreateActionRequest {
        try WalletCreateActionRequest(
            description: description,
            inputBEEF: try inputBEEF.map { try BEEF(bytes: $0, limits: codec.beefLimits) },
            inputs: try inputs?.map { try $0.model(codec) },
            outputs: try outputs?.map { try $0.model(codec) },
            lockTime: lockTime,
            version: version,
            labels: labels,
            options: try options?.model(codec),
            limits: codec.abiLimits
        )
    }
}

private struct SendWithResultDTO: Codable {
    let txid: String
    let status: WalletActionResultStatus
    init(_ value: WalletSendWithResult) { txid = value.transactionID.displayHex; status = value.status }
    func model() throws -> WalletSendWithResult { .init(transactionID: try .init(displayHex: txid), status: status) }
}

private struct SignableTransactionDTO: Codable {
    let tx: [UInt8]
    let reference: String
    init(_ value: WalletSignableTransaction, codec: WalletBRC100JSONCodec) throws {
        tx = try value.transaction.serialized(limits: codec.beefLimits)
        reference = value.reference.base64
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletSignableTransaction {
        .init(transaction: try AtomicBEEF(bytes: tx, limits: codec.beefLimits), reference: try .init(base64: reference, limits: codec.abiLimits))
    }
}

private struct CreateActionResultDTO: Codable {
    let txid: String?
    let tx: [UInt8]?
    let noSendChange: [String]?
    let sendWithResults: [SendWithResultDTO]?
    let signableTransaction: SignableTransactionDTO?

    init(_ value: WalletCreateActionResult, codec: WalletBRC100JSONCodec) throws {
        txid = value.transactionID?.displayHex
        tx = try value.transaction?.serialized(limits: codec.beefLimits)
        noSendChange = value.noSendChange?.map(\.description)
        sendWithResults = value.sendWithResults?.map(SendWithResultDTO.init)
        signableTransaction = try value.signableTransaction.map { try SignableTransactionDTO($0, codec: codec) }
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletCreateActionResult {
        try WalletCreateActionResult(
            transactionID: try txid.map(TransactionID.init(displayHex:)),
            transaction: try tx.map { try AtomicBEEF(bytes: $0, limits: codec.beefLimits) },
            noSendChange: try noSendChange?.map { try Outpoint($0) },
            sendWithResults: try sendWithResults?.map { try $0.model() },
            signableTransaction: try signableTransaction?.model(codec),
            limits: codec.abiLimits
        )
    }
}

private struct SignActionSpendDTO: Codable {
    let unlockingScript: String
    let sequenceNumber: UInt32?
    init(_ value: WalletSignActionSpend) { unlockingScript = Hex.encode(value.unlockingScript); sequenceNumber = value.sequenceNumber }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletSignActionSpend {
        try .init(unlockingScript: decodeCanonicalHex(unlockingScript, maximum: codec.abiLimits.maximumBytePayloadCount), sequenceNumber: sequenceNumber, limits: codec.abiLimits)
    }
}

private struct SignActionOptionsDTO: Codable {
    let acceptDelayedBroadcast: Bool?
    let returnTXIDOnly: Bool?
    let noSend: Bool?
    let sendWith: [String]?
    init(_ value: WalletSignActionOptions) {
        acceptDelayedBroadcast = value.acceptDelayedBroadcast
        returnTXIDOnly = value.returnTransactionIDOnly
        noSend = value.noSend
        sendWith = value.sendWith?.map(\.displayHex)
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletSignActionOptions {
        try .init(acceptDelayedBroadcast: acceptDelayedBroadcast, returnTransactionIDOnly: returnTXIDOnly, noSend: noSend, sendWith: try sendWith?.map(TransactionID.init(displayHex:)), limits: codec.abiLimits)
    }
}

private struct SignActionDTO: Codable {
    let reference: String
    let spends: [String: SignActionSpendDTO]
    let options: SignActionOptionsDTO?
    init(_ value: WalletSignActionRequest, codec: WalletBRC100JSONCodec) throws {
        reference = value.reference.base64
        spends = Dictionary(uniqueKeysWithValues: value.spends.map { (String($0.key), SignActionSpendDTO($0.value)) })
        options = value.options.map(SignActionOptionsDTO.init)
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletSignActionRequest {
        var decoded: [UInt32: WalletSignActionSpend] = [:]
        for (key, value) in spends {
            guard let index = UInt32(key), String(index) == key else { throw WalletJSONCodecError.invalidJSON }
            decoded[index] = try value.model(codec)
        }
        return try .init(reference: .init(base64: reference, limits: codec.abiLimits), spends: decoded, options: try options?.model(codec), limits: codec.abiLimits)
    }
}

private struct SignActionResultDTO: Codable {
    let txid: String?
    let tx: [UInt8]?
    let sendWithResults: [SendWithResultDTO]?
    init(_ value: WalletSignActionResult, codec: WalletBRC100JSONCodec) throws {
        txid = value.transactionID?.displayHex
        tx = try value.transaction?.serialized(limits: codec.beefLimits)
        sendWithResults = value.sendWithResults?.map(SendWithResultDTO.init)
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletSignActionResult {
        try .init(transactionID: try txid.map(TransactionID.init(displayHex:)), transaction: try tx.map { try AtomicBEEF(bytes: $0, limits: codec.beefLimits) }, sendWithResults: try sendWithResults?.map { try $0.model() }, limits: codec.abiLimits)
    }
}

private struct AbortActionDTO: Codable {
    let reference: String
    init(_ value: WalletAbortActionRequest) { reference = value.reference.base64 }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletAbortActionRequest { .init(reference: try .init(base64: reference, limits: codec.abiLimits)) }
}
private struct AbortResultDTO: Codable { let aborted: Bool }
private struct AcceptedResultDTO: Codable { let accepted: Bool }
private struct RelinquishedResultDTO: Codable { let relinquished: Bool }

private struct ListActionsDTO: Codable {
    let labels: [String]
    let labelQueryMode: WalletQueryMode?
    let includeLabels: Bool?
    let includeInputs: Bool?
    let includeInputSourceLockingScripts: Bool?
    let includeInputUnlockingScripts: Bool?
    let includeOutputs: Bool?
    let includeOutputLockingScripts: Bool?
    let limit: UInt32?
    let offset: UInt32?
    let seekPermission: Bool?
    init(_ value: WalletListActionsRequest) {
        labels = value.labels; labelQueryMode = value.labelQueryMode; includeLabels = value.includeLabels
        includeInputs = value.includeInputs; includeInputSourceLockingScripts = value.includeInputSourceLockingScripts
        includeInputUnlockingScripts = value.includeInputUnlockingScripts; includeOutputs = value.includeOutputs
        includeOutputLockingScripts = value.includeOutputLockingScripts; limit = value.pagination.limit
        offset = value.pagination.offset; seekPermission = value.seekPermission
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletListActionsRequest {
        try .init(labels: labels, labelQueryMode: labelQueryMode, includeLabels: includeLabels, includeInputs: includeInputs, includeInputSourceLockingScripts: includeInputSourceLockingScripts, includeInputUnlockingScripts: includeInputUnlockingScripts, includeOutputs: includeOutputs, includeOutputLockingScripts: includeOutputLockingScripts, pagination: .init(limit: limit, offset: offset), seekPermission: seekPermission, limits: codec.abiLimits)
    }
}

private struct ActionInputDTO: Codable {
    let sourceOutpoint: String; let sourceSatoshis: UInt64; let sourceLockingScript: String?
    let unlockingScript: String?; let inputDescription: String; let sequenceNumber: UInt32
    init(_ value: WalletActionInput) {
        sourceOutpoint = value.sourceOutpoint.description; sourceSatoshis = value.sourceSatoshis
        sourceLockingScript = value.sourceLockingScript.map(Hex.encode); unlockingScript = value.unlockingScript.map(Hex.encode)
        inputDescription = value.inputDescription; sequenceNumber = value.sequenceNumber
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletActionInput {
        try .init(sourceOutpoint: .init(sourceOutpoint), sourceSatoshis: sourceSatoshis, sourceLockingScript: try sourceLockingScript.map { try decodeCanonicalHex($0, maximum: codec.abiLimits.maximumBytePayloadCount) }, unlockingScript: try unlockingScript.map { try decodeCanonicalHex($0, maximum: codec.abiLimits.maximumBytePayloadCount) }, inputDescription: inputDescription, sequenceNumber: sequenceNumber, limits: codec.abiLimits)
    }
}

private struct ActionOutputDTO: Codable {
    let satoshis: UInt64; let lockingScript: String?; let spendable: Bool; let customInstructions: String?
    let tags: [String]; let outputIndex: UInt32; let outputDescription: String; let basket: String
    init(_ value: WalletActionOutput) {
        satoshis = value.satoshis; lockingScript = value.lockingScript.map(Hex.encode); spendable = value.spendable
        customInstructions = value.customInstructions; tags = value.tags; outputIndex = value.outputIndex
        outputDescription = value.outputDescription; basket = value.basket
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletActionOutput {
        try .init(satoshis: satoshis, lockingScript: try lockingScript.map { try decodeCanonicalHex($0, maximum: codec.abiLimits.maximumBytePayloadCount) }, spendable: spendable, customInstructions: customInstructions, tags: tags, outputIndex: outputIndex, outputDescription: outputDescription, basket: basket, limits: codec.abiLimits)
    }
}

private struct ActionDTO: Codable {
    let txid: String; let satoshis: Int64; let status: WalletActionStatus; let isOutgoing: Bool
    let description: String; let labels: [String]?; let version: UInt32; let lockTime: UInt32
    let inputs: [ActionInputDTO]?; let outputs: [ActionOutputDTO]?
    init(_ value: WalletAction) {
        txid = value.transactionID.displayHex; satoshis = value.satoshis; status = value.status
        isOutgoing = value.isOutgoing; description = value.description; labels = value.labels
        version = value.version; lockTime = value.lockTime; inputs = value.inputs?.map(ActionInputDTO.init)
        outputs = value.outputs?.map(ActionOutputDTO.init)
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletAction {
        try .init(transactionID: .init(displayHex: txid), satoshis: satoshis, status: status, isOutgoing: isOutgoing, description: description, labels: labels, version: version, lockTime: lockTime, inputs: try inputs?.map { try $0.model(codec) }, outputs: try outputs?.map { try $0.model(codec) }, limits: codec.abiLimits)
    }
}

private struct ListActionsResultDTO: Codable {
    let totalActions: UInt32; let actions: [ActionDTO]
    init(_ value: WalletListActionsResult, codec: WalletBRC100JSONCodec) { totalActions = value.totalActions; actions = value.actions.map(ActionDTO.init) }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletListActionsResult { try .init(totalActions: totalActions, actions: try actions.map { try $0.model(codec) }, limits: codec.abiLimits) }
}

private struct PaymentRemittanceDTO: Codable {
    let derivationPrefix: String; let derivationSuffix: String; let senderIdentityKey: String
    init(_ value: WalletPaymentRemittance) { derivationPrefix = value.derivationPrefix.base64; derivationSuffix = value.derivationSuffix.base64; senderIdentityKey = Hex.encode(value.senderIdentityKey.compressedBytes) }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletPaymentRemittance { try .init(derivationPrefix: .init(base64: derivationPrefix, limits: codec.abiLimits), derivationSuffix: .init(base64: derivationSuffix, limits: codec.abiLimits), senderIdentityKey: decodeWalletJSONPublicKey(senderIdentityKey), limits: codec.abiLimits) }
}
private struct BasketInsertionDTO: Codable {
    let basket: String; let customInstructions: String?; let tags: [String]?
    init(_ value: WalletBasketInsertion) { basket = value.basket; customInstructions = value.customInstructions; tags = value.tags.isEmpty ? nil : value.tags }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletBasketInsertion { try .init(basket: basket, customInstructions: customInstructions, tags: tags ?? [], limits: codec.abiLimits) }
}
private struct InternalizeOutputDTO: Codable {
    let outputIndex: UInt32; let `protocol`: WalletInternalizeProtocol
    let paymentRemittance: PaymentRemittanceDTO?; let insertionRemittance: BasketInsertionDTO?
    init(_ value: WalletInternalizeOutput) {
        outputIndex = value.outputIndex; `protocol` = value.remittance.protocol
        switch value.remittance {
        case .walletPayment(let payment): paymentRemittance = PaymentRemittanceDTO(payment); insertionRemittance = nil
        case .basketInsertion(let insertion): paymentRemittance = nil; insertionRemittance = BasketInsertionDTO(insertion)
        }
    }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletInternalizeOutput {
        try .init(outputIndex: outputIndex, protocol: `protocol`, paymentRemittance: try paymentRemittance?.model(codec), insertionRemittance: try insertionRemittance?.model(codec))
    }
}
private struct InternalizeActionDTO: Codable {
    let tx: [UInt8]; let outputs: [InternalizeOutputDTO]; let description: String; let labels: [String]?; let seekPermission: Bool?
    init(_ value: WalletInternalizeActionRequest, codec: WalletBRC100JSONCodec) throws { tx = try value.transaction.serialized(limits: codec.beefLimits); outputs = value.outputs.map(InternalizeOutputDTO.init); description = value.description; labels = value.labels.isEmpty ? nil : value.labels; seekPermission = value.seekPermission }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletInternalizeActionRequest { try .init(transaction: .init(bytes: tx, limits: codec.beefLimits), description: description, labels: labels ?? [], seekPermission: seekPermission, outputs: try outputs.map { try $0.model(codec) }, limits: codec.abiLimits) }
}

private struct OutputDTO: Codable {
    let satoshis: UInt64; let lockingScript: String?; let spendable: Bool; let customInstructions: String?
    let tags: [String]?; let outpoint: String; let labels: [String]?
    init(_ value: WalletOutput) { satoshis = value.satoshis; lockingScript = value.lockingScript.map(Hex.encode); spendable = value.spendable; customInstructions = value.customInstructions; tags = value.tags; outpoint = value.outpoint.description; labels = value.labels }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletOutput { try .init(satoshis: satoshis, lockingScript: try lockingScript.map { try decodeCanonicalHex($0, maximum: codec.abiLimits.maximumBytePayloadCount) }, spendable: spendable, customInstructions: customInstructions, tags: tags, outpoint: .init(outpoint), labels: labels, limits: codec.abiLimits) }
}
private struct ListOutputsDTO: Codable {
    let basket: String; let tags: [String]?; let tagQueryMode: WalletQueryMode?; let include: WalletOutputInclude?
    let includeCustomInstructions: Bool?; let includeTags: Bool?; let includeLabels: Bool?
    let limit: UInt32?; let offset: UInt32?; let seekPermission: Bool?
    init(_ value: WalletListOutputsRequest) { basket = value.basket; tags = value.tags.isEmpty ? nil : value.tags; tagQueryMode = value.tagQueryMode; include = value.include; includeCustomInstructions = value.includeCustomInstructions; includeTags = value.includeTags; includeLabels = value.includeLabels; limit = value.pagination.limit; offset = value.pagination.offset; seekPermission = value.seekPermission }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletListOutputsRequest { try .init(basket: basket, tags: tags ?? [], tagQueryMode: tagQueryMode, include: include, includeCustomInstructions: includeCustomInstructions, includeTags: includeTags, includeLabels: includeLabels, pagination: .init(limit: limit, offset: offset), seekPermission: seekPermission, limits: codec.abiLimits) }
}
private struct ListOutputsResultDTO: Codable {
    let totalOutputs: UInt32; let BEEF: [UInt8]?; let outputs: [OutputDTO]
    init(_ value: WalletListOutputsResult, codec: WalletBRC100JSONCodec) throws { totalOutputs = value.totalOutputs; BEEF = try value.beef?.serialized(limits: codec.beefLimits); outputs = value.outputs.map(OutputDTO.init) }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletListOutputsResult { try .init(totalOutputs: totalOutputs, beef: try BEEF.map { try BSVTransaction.BEEF(bytes: $0, limits: codec.beefLimits) }, outputs: try outputs.map { try $0.model(codec) }, limits: codec.abiLimits) }
}
private struct RelinquishOutputDTO: Codable {
    let basket: String; let output: String
    init(_ value: WalletRelinquishOutputRequest) { basket = value.basket; output = value.output.description }
    func model(_ codec: WalletBRC100JSONCodec) throws -> WalletRelinquishOutputRequest { try .init(basket: basket, output: .init(output), limits: codec.abiLimits) }
}
