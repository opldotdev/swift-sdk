import BSVCore
import BSVKeys
import BSVTransaction

extension WalletWireCodec {
    /// Encodes an action request frame. `listOutputsEncoding: .spendable` appends
    /// the one-byte `01` extension to a `listOutputs` request.
    public static func encodeActionRequest(
        _ request: WalletWireActionRequest,
        originator: String,
        listOutputsEncoding: WalletWireListOutputsEncoding = .legacy,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits = .standard
    ) throws -> [UInt8] {
        var parameters = try encodeActionParameters(
            request, beefLimits: beefLimits, limits: limits
        )
        if case .listOutputs = request, listOutputsEncoding == .spendable {
            parameters.append(1)
        }
        return try encodeRequestFrame(
            WalletWireRequestFrame(call: request.call, originator: originator, parameters: parameters),
            limits: limits
        )
    }

    public static func decodeActionRequest(
        _ bytes: [UInt8],
        beefLimits: BEEFLimits,
        limits: WalletWireLimits = .standard
    ) throws -> WalletWireDecodedActionRequest {
        let frame = try decodeRequestFrame(bytes, limits: limits)
        do {
            var parameters = frame.parameters
            var encoding = WalletWireListOutputsEncoding.legacy
            if frame.call == .listOutputs {
                encoding = try walletWireSplitListOutputsExtension(&parameters, limits: limits)
            }
            return WalletWireDecodedActionRequest(
                originator: frame.originator,
                request: try decodeActionParameters(
                    parameters, call: frame.call, beefLimits: beefLimits, limits: limits
                ),
                listOutputsEncoding: encoding
            )
        } catch let error as WalletWireError {
            throw error
        } catch let error as WalletABIError {
            throw walletWireMapABIError(error)
        }
    }

    /// Encodes an action result frame.
    ///
    /// `request` supplies what the layout depends on: a BRC-112 balance basket
    /// and the `listOutputs` encoding. A refused abort is the error frame code 8
    /// that `@bsv/sdk` 4.1.1 sends. A result with no wire encoding throws
    /// `WalletWireResultRejection`, which a processor sends in-band.
    public static func encodeActionResult(
        _ result: WalletWireActionResult,
        request: WalletWireActionRequest? = nil,
        listOutputsEncoding: WalletWireListOutputsEncoding = .legacy,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits = .standard
    ) throws -> [UInt8] {
        if case .abortAction(let value) = result, !value.aborted {
            return try encodeResultFrame(.failure(WalletWireRemoteError(
                code: WalletWireErrorCode.abortRefused,
                message: WalletWireFailureText.abortRefused,
                stack: "",
                limits: limits
            )), limits: limits)
        }
        let payload = try encodeActionResultPayload(
            result, request: request, listOutputsEncoding: listOutputsEncoding,
            beefLimits: beefLimits, limits: limits
        )
        return try encodeResultFrame(.success(payload), limits: limits)
    }

    /// Decodes an action result frame. With `request`, list pages are checked
    /// against the requested limit and a balance basket's total is read as a
    /// 64-bit balance. Error code 8 on `abortAction` reads as `aborted: false`.
    public static func decodeActionResult(
        _ bytes: [UInt8],
        expectedCall: WalletCall,
        request: WalletWireActionRequest? = nil,
        listOutputsEncoding: WalletWireListOutputsEncoding = .legacy,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits = .standard
    ) throws -> WalletWireActionResult {
        switch try decodeResultFrame(bytes, limits: limits) {
        case .failure(let remote):
            if expectedCall == .abortAction, remote.code == WalletWireErrorCode.abortRefused {
                return .abortAction(WalletAbortActionResult(aborted: false))
            }
            throw remote
        case .success(let payload):
            do {
                return try decodeActionResultPayload(
                    payload, call: expectedCall, request: request,
                    listOutputsEncoding: listOutputsEncoding,
                    beefLimits: beefLimits, limits: limits
                )
            } catch let error as WalletWireError {
                throw error
            } catch let error as WalletABIError {
                throw walletWireMapABIError(error)
            }
        }
    }

    private static func encodeActionParameters(
        _ request: WalletWireActionRequest,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        var writer = WalletWireWriter(maximumByteCount: limits.maximumPayloadByteCount)
        switch request {
        case .createAction(let value):
            try walletWireWriteText(
                value.description, kind: "action description", to: &writer, limits: limits
            )
            try writer.writeOptionalVarBytes(value.inputBEEF.map {
                try walletWireBEEFBytes($0, limits: beefLimits)
            })
            try encodeCreateInputs(value.inputs, to: &writer, limits: limits)
            try encodeCreateOutputs(value.outputs, to: &writer, limits: limits)
            writer.writeOptionalUInt32(value.lockTime)
            writer.writeOptionalUInt32(value.version)
            try walletWireWriteStringSlice(
                value.labels, kind: "labels", to: &writer, limits: limits
            )
            try encodeCreateOptions(value.options, to: &writer, limits: limits)
        case .signAction(let value):
            guard value.spends.count <= limits.abiLimits.maximumCollectionCount else {
                throw WalletWireError.countLimitExceeded(
                    kind: "spends", actual: UInt64(value.spends.count),
                    maximum: limits.abiLimits.maximumCollectionCount
                )
            }
            writer.writeCompactSize(UInt64(value.spends.count))
            for (index, spend) in value.spends.sorted(by: { $0.key < $1.key }) {
                writer.writeCompactSize(UInt64(index))
                try walletWireRequireActionBytes(
                    spend.unlockingScript.count, kind: "unlocking script", limits: limits
                )
                try writer.writeVarBytes(spend.unlockingScript)
                writer.writeOptionalUInt32(spend.sequenceNumber)
            }
            try walletWireRequireActionBytes(
                value.reference.bytes.count, kind: "reference", limits: limits
            )
            try writer.writeVarBytes(value.reference.bytes)
            try encodeSignOptions(value.options, to: &writer, limits: limits)
        case .abortAction(let value):
            try walletWireRequireActionBytes(
                value.reference.bytes.count, kind: "reference", limits: limits
            )
            writer.writeBytes(value.reference.bytes)
        case .listActions(let value):
            try walletWireWriteStringSlice(
                value.labels, kind: "labels", to: &writer, limits: limits
            )
            switch value.labelQueryMode {
            case .any: writer.writeByte(1)
            case .all: writer.writeByte(2)
            case nil: writer.writeByte(0xff)
            }
            writer.writeOptionalBoolean(value.includeLabels)
            writer.writeOptionalBoolean(value.includeInputs)
            writer.writeOptionalBoolean(value.includeInputSourceLockingScripts)
            writer.writeOptionalBoolean(value.includeInputUnlockingScripts)
            writer.writeOptionalBoolean(value.includeOutputs)
            writer.writeOptionalBoolean(value.includeOutputLockingScripts)
            writer.writeOptionalUInt32(value.pagination.limit)
            writer.writeOptionalUInt32(value.pagination.offset)
            writer.writeOptionalBoolean(value.seekPermission)
        case .internalizeAction(let value):
            let transaction = try walletWireAtomicBEEFBytes(value.transaction, limits: beefLimits)
            try writer.writeVarBytes(transaction)
            guard value.outputs.count <= limits.abiLimits.maximumCollectionCount else {
                throw WalletWireError.countLimitExceeded(
                    kind: "outputs", actual: UInt64(value.outputs.count),
                    maximum: limits.abiLimits.maximumCollectionCount
                )
            }
            writer.writeCompactSize(UInt64(value.outputs.count))
            for output in value.outputs {
                writer.writeCompactSize(UInt64(output.outputIndex))
                switch output.remittance {
                case .walletPayment(let payment):
                    writer.writeByte(1)
                    writer.writeBytes(payment.senderIdentityKey.compressedBytes)
                    try walletWireRequireActionBytes(
                        payment.derivationPrefix.bytes.count, kind: "derivation prefix", limits: limits
                    )
                    try walletWireRequireActionBytes(
                        payment.derivationSuffix.bytes.count, kind: "derivation suffix", limits: limits
                    )
                    try writer.writeVarBytes(payment.derivationPrefix.bytes)
                    try writer.writeVarBytes(payment.derivationSuffix.bytes)
                case .basketInsertion(let insertion):
                    writer.writeByte(2)
                    try walletWireWriteText(
                        insertion.basket, kind: "basket", to: &writer, limits: limits
                    )
                    try walletWireWriteOptionalText(
                        insertion.customInstructions, kind: "custom instructions",
                        to: &writer, limits: limits
                    )
                    try walletWireWriteStringSlice(
                        insertion.tags, kind: "tags", to: &writer, limits: limits
                    )
                }
            }
            // @bsv/sdk writes -1 for omitted labels; they default to none.
            try walletWireWriteStringSlice(
                value.labels.isEmpty ? nil : value.labels, kind: "labels", to: &writer, limits: limits
            )
            try walletWireWriteText(
                value.description, kind: "action description", to: &writer, limits: limits
            )
            writer.writeOptionalBoolean(value.seekPermission)
        case .listOutputs(let value):
            try walletWireWriteText(
                value.basket, kind: "basket", to: &writer, limits: limits
            )
            try walletWireWriteStringSlice(
                value.tags, kind: "tags", to: &writer, limits: limits
            )
            switch value.tagQueryMode {
            case .all: writer.writeByte(1)
            case .any: writer.writeByte(2)
            case nil: writer.writeByte(0xff)
            }
            switch value.include {
            case .lockingScripts: writer.writeByte(1)
            case .entireTransactions: writer.writeByte(2)
            case nil: writer.writeByte(0xff)
            }
            writer.writeOptionalBoolean(value.includeCustomInstructions)
            writer.writeOptionalBoolean(value.includeTags)
            writer.writeOptionalBoolean(value.includeLabels)
            writer.writeOptionalUInt32(value.pagination.limit)
            writer.writeOptionalUInt32(value.pagination.offset)
            writer.writeOptionalBoolean(value.seekPermission)
        case .relinquishOutput(let value):
            try walletWireWriteText(
                value.basket, kind: "basket", to: &writer, limits: limits
            )
            writer.writeActionOutpoint(value.output)
        }
        try writer.requireWithinLimit(kind: "request parameters")
        return writer.bytes
    }

    private static func decodeActionParameters(
        _ bytes: [UInt8],
        call: WalletCall,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits
    ) throws -> WalletWireActionRequest {
        var reader = WalletWireReader(bytes)
        let value: WalletWireActionRequest
        switch call {
        case .createAction:
            let description = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "action description"
            )
            let inputBytes = try reader.readOptionalVarBytes(
                maximum: beefLimits.maximumByteCount, kind: "input BEEF"
            )
            let inputs = try decodeCreateInputs(from: &reader, limits: limits)
            let outputs = try decodeCreateOutputs(from: &reader, limits: limits)
            let lockTime = try reader.readOptionalUInt32(kind: "lock time")
            let version = try reader.readOptionalUInt32(kind: "version")
            let labels = try walletWireReadStringSlice(
                from: &reader, kind: "labels", optional: true, limits: limits
            )
            let options = try decodeCreateOptions(from: &reader, limits: limits)
            value = .createAction(try WalletCreateActionRequest(
                description: description,
                inputBEEF: try inputBytes.map { try walletWireParseBEEF($0, limits: beefLimits) },
                inputs: inputs,
                outputs: outputs,
                lockTime: lockTime,
                version: version,
                labels: labels,
                options: options,
                limits: limits.abiLimits
            ))
        case .signAction:
            let count = try reader.readCount(
                maximum: limits.abiLimits.maximumCollectionCount, kind: "spends"
            )
            var spends: [UInt32: WalletSignActionSpend] = [:]
            spends.reserveCapacity(min(count, reader.remainingCount))
            for _ in 0..<count {
                let rawIndex = try reader.readCompactSize()
                guard let index = UInt32(exactly: rawIndex) else { throw WalletWireError.uint32Overflow }
                guard spends[index] == nil else {
                    throw WalletWireError.nonRoundTrippableValue(kind: "duplicate spend index")
                }
                let script = try reader.readVarBytes(
                    maximum: limits.abiLimits.maximumBytePayloadCount, kind: "unlocking script"
                )
                let sequence = try reader.readOptionalUInt32(kind: "sequence number")
                spends[index] = try WalletSignActionSpend(
                    unlockingScript: script, sequenceNumber: sequence, limits: limits.abiLimits
                )
            }
            let reference = try reader.readVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "reference"
            )
            let options = try decodeSignOptions(from: &reader, limits: limits)
            value = .signAction(try WalletSignActionRequest(
                reference: try WalletBase64Data(reference, limits: limits.abiLimits),
                spends: spends,
                options: options,
                limits: limits.abiLimits
            ))
        case .abortAction:
            value = .abortAction(WalletAbortActionRequest(
                reference: try WalletBase64Data(
                    reader.readRemainder(
                        maximum: limits.abiLimits.maximumBytePayloadCount, kind: "reference"
                    ),
                    limits: limits.abiLimits
                )
            ))
        case .listActions:
            let labels = try walletWireReadStringSlice(
                from: &reader, kind: "labels", optional: false, limits: limits
            ) ?? []
            let mode: WalletQueryMode?
            switch try reader.readByte() {
            case 1: mode = .any
            case 2: mode = .all
            case 0xff: mode = nil
            case let flag: throw WalletWireError.invalidDiscriminator(kind: "label query mode", value: flag)
            }
            let includeLabels = try reader.readOptionalBoolean(kind: "include labels")
            let includeInputs = try reader.readOptionalBoolean(kind: "include inputs")
            let includeSource = try reader.readOptionalBoolean(kind: "include source locking scripts")
            let includeUnlocking = try reader.readOptionalBoolean(kind: "include unlocking scripts")
            let includeOutputs = try reader.readOptionalBoolean(kind: "include outputs")
            let includeLocking = try reader.readOptionalBoolean(kind: "include output locking scripts")
            let limit = try reader.readOptionalUInt32(kind: "limit")
            let offset = try reader.readOptionalUInt32(kind: "offset")
            let seek = try reader.readOptionalBoolean(kind: "seek permission")
            value = .listActions(try WalletListActionsRequest(
                labels: labels,
                labelQueryMode: mode,
                includeLabels: includeLabels,
                includeInputs: includeInputs,
                includeInputSourceLockingScripts: includeSource,
                includeInputUnlockingScripts: includeUnlocking,
                includeOutputs: includeOutputs,
                includeOutputLockingScripts: includeLocking,
                pagination: try WalletPagination(limit: limit, offset: offset),
                seekPermission: seek,
                limits: limits.abiLimits
            ))
        case .internalizeAction:
            let transactionBytes = try reader.readVarBytes(
                maximum: beefLimits.maximumByteCount, kind: "Atomic BEEF"
            )
            let outputCount = try reader.readCount(
                maximum: limits.abiLimits.maximumCollectionCount, kind: "outputs"
            )
            var outputs: [WalletInternalizeOutput] = []
            outputs.reserveCapacity(min(outputCount, reader.remainingCount / 2))
            for _ in 0..<outputCount {
                let rawIndex = try reader.readCompactSize()
                guard let index = UInt32(exactly: rawIndex) else { throw WalletWireError.uint32Overflow }
                switch try reader.readByte() {
                case 1:
                    let keyBytes = try reader.readBytes(count: 33)
                    let key: PublicKey
                    do {
                        key = try PublicKey(keyBytes)
                        guard key.compressedBytes == keyBytes else { throw WalletWireError.invalidPublicKey }
                    } catch { throw WalletWireError.invalidPublicKey }
                    let prefix = try reader.readVarBytes(
                        maximum: limits.abiLimits.maximumBytePayloadCount, kind: "derivation prefix"
                    )
                    let suffix = try reader.readVarBytes(
                        maximum: limits.abiLimits.maximumBytePayloadCount, kind: "derivation suffix"
                    )
                    outputs.append(WalletInternalizeOutput(
                        outputIndex: index,
                        remittance: .walletPayment(try WalletPaymentRemittance(
                            derivationPrefix: try WalletBase64Data(prefix, limits: limits.abiLimits),
                            derivationSuffix: try WalletBase64Data(suffix, limits: limits.abiLimits),
                            senderIdentityKey: key,
                            limits: limits.abiLimits
                        ))
                    ))
                case 2:
                    let basket = try reader.readString(
                        maximum: walletWireMaximumText(limits), kind: "basket"
                    )
                    let custom = try reader.readOptionalString(
                        maximum: walletWireMaximumText(limits), kind: "custom instructions"
                    )
                    let tags = try walletWireReadStringSlice(
                        from: &reader, kind: "tags", optional: false, limits: limits
                    ) ?? []
                    outputs.append(WalletInternalizeOutput(
                        outputIndex: index,
                        remittance: .basketInsertion(try WalletBasketInsertion(
                            basket: basket, customInstructions: custom, tags: tags,
                            limits: limits.abiLimits
                        ))
                    ))
                case let flag:
                    throw WalletWireError.invalidDiscriminator(kind: "internalize protocol", value: flag)
                }
            }
            let labels = try walletWireReadStringSlice(
                from: &reader, kind: "labels", optional: false, limits: limits
            ) ?? []
            let description = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "action description"
            )
            let seek = try reader.readOptionalBoolean(kind: "seek permission")
            value = .internalizeAction(try WalletInternalizeActionRequest(
                transaction: try walletWireParseAtomicBEEF(transactionBytes, limits: beefLimits),
                description: description,
                labels: labels,
                seekPermission: seek,
                outputs: outputs,
                limits: limits.abiLimits
            ))
        case .listOutputs:
            let basket = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "basket"
            )
            let tags = try walletWireReadStringSlice(
                from: &reader, kind: "tags", optional: false, limits: limits
            ) ?? []
            let mode: WalletQueryMode?
            switch try reader.readByte() {
            case 1: mode = .all
            case 2: mode = .any
            case 0xff: mode = nil
            case let flag: throw WalletWireError.invalidDiscriminator(kind: "tag query mode", value: flag)
            }
            let include: WalletOutputInclude?
            switch try reader.readByte() {
            case 1: include = .lockingScripts
            case 2: include = .entireTransactions
            case 0xff: include = nil
            case let flag: throw WalletWireError.invalidDiscriminator(kind: "output include", value: flag)
            }
            let includeCustom = try reader.readOptionalBoolean(kind: "include custom instructions")
            let includeTags = try reader.readOptionalBoolean(kind: "include tags")
            let includeLabels = try reader.readOptionalBoolean(kind: "include labels")
            let limit = try reader.readOptionalUInt32(kind: "limit")
            let offset = try reader.readOptionalUInt32(kind: "offset")
            let seek = try reader.readOptionalBoolean(kind: "seek permission")
            value = .listOutputs(try WalletListOutputsRequest(
                basket: basket, tags: tags, tagQueryMode: mode, include: include,
                includeCustomInstructions: includeCustom, includeTags: includeTags,
                includeLabels: includeLabels,
                pagination: try WalletPagination(limit: limit, offset: offset),
                seekPermission: seek,
                limits: limits.abiLimits
            ))
        case .relinquishOutput:
            let basket = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "basket"
            )
            value = .relinquishOutput(try WalletRelinquishOutputRequest(
                basket: basket, output: reader.readActionOutpoint(), limits: limits.abiLimits
            ))
        default:
            throw WalletWireError.invalidCall(call.rawValue)
        }
        try reader.requireEnd()
        return value
    }
}

private extension WalletWireCodec {
    static func encodeCreateInputs(
        _ inputs: [WalletCreateActionInput]?,
        to writer: inout WalletWireWriter,
        limits: WalletWireLimits
    ) throws {
        guard let inputs else {
            writer.writeCompactSize(UInt64.max)
            return
        }
        guard inputs.count <= limits.abiLimits.maximumCollectionCount else {
            throw WalletWireError.countLimitExceeded(
                kind: "inputs", actual: UInt64(inputs.count),
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        writer.writeCompactSize(UInt64(inputs.count))
        for input in inputs {
            writer.writeActionOutpoint(input.outpoint)
            switch input.unlocking {
            case .script(let bytes):
                guard !bytes.isEmpty else {
                    throw WalletWireError.nonRoundTrippableValue(kind: "empty unlocking script")
                }
                try walletWireRequireActionBytes(
                    bytes.count, kind: "unlocking script", limits: limits
                )
                try writer.writeVarBytes(bytes)
            case .scriptLength(let length):
                writer.writeCompactSize(UInt64.max)
                writer.writeCompactSize(UInt64(length))
            }
            try walletWireWriteText(
                input.inputDescription, kind: "input description", to: &writer, limits: limits
            )
            writer.writeOptionalUInt32(input.sequenceNumber)
        }
    }

    static func decodeCreateInputs(
        from reader: inout WalletWireReader,
        limits: WalletWireLimits
    ) throws -> [WalletCreateActionInput]? {
        let count = try reader.readCompactSize()
        if count == UInt64.max { return nil }
        guard count <= UInt64(limits.abiLimits.maximumCollectionCount), count <= UInt64(Int.max) else {
            throw WalletWireError.countLimitExceeded(
                kind: "inputs", actual: count, maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        var result: [WalletCreateActionInput] = []
        result.reserveCapacity(min(Int(count), reader.remainingCount / 34))
        for _ in 0..<Int(count) {
            let outpoint = try reader.readActionOutpoint()
            let script = try reader.readOptionalVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "unlocking script"
            )
            let scriptLength: UInt32?
            if script == nil {
                let rawLength = try reader.readCompactSize()
                guard let length = UInt32(exactly: rawLength) else { throw WalletWireError.uint32Overflow }
                scriptLength = length
            } else {
                guard script?.isEmpty == false else {
                    throw WalletWireError.nonRoundTrippableValue(kind: "empty unlocking script")
                }
                scriptLength = nil
            }
            let description = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "input description"
            )
            let sequence = try reader.readOptionalUInt32(kind: "sequence number")
            result.append(try WalletCreateActionInput(
                outpoint: outpoint,
                inputDescription: description,
                unlockingScript: script,
                unlockingScriptLength: scriptLength,
                sequenceNumber: sequence,
                limits: limits.abiLimits
            ))
        }
        return result
    }

    static func encodeCreateOutputs(
        _ outputs: [WalletCreateActionOutput]?,
        to writer: inout WalletWireWriter,
        limits: WalletWireLimits
    ) throws {
        guard let outputs else {
            writer.writeCompactSize(UInt64.max)
            return
        }
        guard outputs.count <= limits.abiLimits.maximumCollectionCount else {
            throw WalletWireError.countLimitExceeded(
                kind: "outputs", actual: UInt64(outputs.count),
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        writer.writeCompactSize(UInt64(outputs.count))
        for output in outputs {
            guard !output.lockingScript.isEmpty else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "empty create-action locking script"
                )
            }
            try walletWireRequireActionBytes(
                output.lockingScript.count, kind: "locking script", limits: limits
            )
            try writer.writeVarBytes(output.lockingScript)
            writer.writeCompactSize(output.satoshis)
            try walletWireWriteText(
                output.outputDescription, kind: "output description", to: &writer, limits: limits
            )
            try walletWireWriteOptionalText(
                output.basket, kind: "basket", to: &writer, limits: limits
            )
            try walletWireWriteOptionalText(
                output.customInstructions, kind: "custom instructions",
                to: &writer, limits: limits
            )
            // @bsv/sdk writes -1 for omitted tags; they default to none.
            try walletWireWriteStringSlice(
                output.tags.isEmpty ? nil : output.tags, kind: "tags", to: &writer, limits: limits
            )
        }
    }

    static func decodeCreateOutputs(
        from reader: inout WalletWireReader,
        limits: WalletWireLimits
    ) throws -> [WalletCreateActionOutput]? {
        let count = try reader.readCompactSize()
        if count == UInt64.max { return nil }
        guard count <= UInt64(limits.abiLimits.maximumCollectionCount), count <= UInt64(Int.max) else {
            throw WalletWireError.countLimitExceeded(
                kind: "outputs", actual: count, maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        var result: [WalletCreateActionOutput] = []
        result.reserveCapacity(min(Int(count), reader.remainingCount))
        for _ in 0..<Int(count) {
            let script = try reader.readVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "locking script"
            )
            guard !script.isEmpty else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "empty create-action locking script"
                )
            }
            let satoshis = try reader.readCompactSize()
            let description = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "output description"
            )
            let basket = try reader.readOptionalString(
                maximum: walletWireMaximumText(limits), kind: "basket"
            )
            let custom = try reader.readOptionalString(
                maximum: walletWireMaximumText(limits), kind: "custom instructions"
            )
            let tags = try walletWireReadStringSlice(
                from: &reader, kind: "tags", optional: false, limits: limits
            ) ?? []
            result.append(try WalletCreateActionOutput(
                lockingScript: script, satoshis: satoshis, outputDescription: description,
                basket: basket, customInstructions: custom, tags: tags, limits: limits.abiLimits
            ))
        }
        return result
    }

    static func encodeCreateOptions(
        _ options: WalletCreateActionOptions?,
        to writer: inout WalletWireWriter,
        limits: WalletWireLimits
    ) throws {
        guard let options else {
            writer.writeByte(0)
            return
        }
        writer.writeByte(1)
        writer.writeOptionalBoolean(options.signAndProcess)
        writer.writeOptionalBoolean(options.acceptDelayedBroadcast)
        writer.writeByte(options.trustSelf == .known ? 1 : 0xff)
        try walletWireWriteTransactionIDs(
            options.knownTransactionIDs, kind: "known transaction IDs", to: &writer, limits: limits
        )
        writer.writeOptionalBoolean(options.returnTransactionIDOnly)
        writer.writeOptionalBoolean(options.noSend)
        // @bsv/sdk 4.1.1: an outpoint count (or -1) followed by the outpoints.
        try walletWireWriteOutpointCollection(
            options.noSendChange, kind: "no-send change", to: &writer, limits: limits
        )
        try walletWireWriteTransactionIDs(
            options.sendWith, kind: "send-with transaction IDs", to: &writer, limits: limits
        )
        writer.writeOptionalBoolean(options.randomizeOutputs)
    }

    static func decodeCreateOptions(
        from reader: inout WalletWireReader,
        limits: WalletWireLimits
    ) throws -> WalletCreateActionOptions? {
        switch try reader.readByte() {
        case 0: return nil
        case 1: break
        case let flag: throw WalletWireError.invalidDiscriminator(kind: "create options", value: flag)
        }
        let sign = try reader.readOptionalBoolean(kind: "sign and process")
        let delayed = try reader.readOptionalBoolean(kind: "accept delayed broadcast")
        let trust: WalletTrustSelf?
        switch try reader.readByte() {
        case 1: trust = .known
        case 0xff: trust = nil
        case let flag: throw WalletWireError.invalidDiscriminator(kind: "trust self", value: flag)
        }
        let known = try walletWireReadTransactionIDs(
            from: &reader, kind: "known transaction IDs", limits: limits
        )
        let txidOnly = try reader.readOptionalBoolean(kind: "return transaction ID only")
        let noSend = try reader.readOptionalBoolean(kind: "no send")
        let noSendChange = try walletWireReadOutpointCollection(
            from: &reader, kind: "no-send change", limits: limits
        )
        let sendWith = try walletWireReadTransactionIDs(
            from: &reader, kind: "send-with transaction IDs", limits: limits
        )
        let randomize = try reader.readOptionalBoolean(kind: "randomize outputs")
        return try WalletCreateActionOptions(
            signAndProcess: sign,
            acceptDelayedBroadcast: delayed,
            trustSelf: trust,
            knownTransactionIDs: known,
            returnTransactionIDOnly: txidOnly,
            noSend: noSend,
            noSendChange: noSendChange,
            sendWith: sendWith,
            randomizeOutputs: randomize,
            limits: limits.abiLimits
        )
    }

    static func encodeSignOptions(
        _ options: WalletSignActionOptions?,
        to writer: inout WalletWireWriter,
        limits: WalletWireLimits
    ) throws {
        guard let options else {
            writer.writeByte(0)
            return
        }
        writer.writeByte(1)
        writer.writeOptionalBoolean(options.acceptDelayedBroadcast)
        writer.writeOptionalBoolean(options.returnTransactionIDOnly)
        writer.writeOptionalBoolean(options.noSend)
        try walletWireWriteTransactionIDs(
            options.sendWith, kind: "send-with transaction IDs", to: &writer, limits: limits
        )
    }

    static func decodeSignOptions(
        from reader: inout WalletWireReader,
        limits: WalletWireLimits
    ) throws -> WalletSignActionOptions? {
        switch try reader.readByte() {
        case 0: return nil
        case 1: break
        case let flag: throw WalletWireError.invalidDiscriminator(kind: "sign options", value: flag)
        }
        return try WalletSignActionOptions(
            acceptDelayedBroadcast: reader.readOptionalBoolean(kind: "accept delayed broadcast"),
            returnTransactionIDOnly: reader.readOptionalBoolean(kind: "return transaction ID only"),
            noSend: reader.readOptionalBoolean(kind: "no send"),
            sendWith: walletWireReadTransactionIDs(
                from: &reader, kind: "send-with transaction IDs", limits: limits
            ),
            limits: limits.abiLimits
        )
    }
}

/// Splits the optional `listOutputs` request extension. @bsv/sdk 4.1 appends one
/// `01` byte after `seekPermission` to ask for the spendable response layout.
func walletWireSplitListOutputsExtension(
    _ parameters: inout [UInt8],
    limits: WalletWireLimits
) throws -> WalletWireListOutputsEncoding {
    var reader = WalletWireReader(parameters)
    _ = try reader.readVarBytes(maximum: walletWireMaximumText(limits), kind: "basket")
    let tagCount = try reader.readCompactSize()
    if tagCount != UInt64.max, tagCount > 0 {
        guard tagCount <= UInt64(limits.abiLimits.maximumTagCount) else {
            throw WalletWireError.countLimitExceeded(
                kind: "tags", actual: tagCount, maximum: limits.abiLimits.maximumTagCount
            )
        }
        for _ in 0..<Int(tagCount) {
            let length = try reader.readCompactSize()
            if length != UInt64.max {
                guard length <= UInt64(reader.remainingCount) else { throw WalletWireError.truncated }
                _ = try reader.readBytes(count: Int(length))
            }
        }
    }
    _ = try reader.readBytes(count: 5) // tag mode, include, three include flags
    for _ in 0..<2 { _ = try reader.readCompactSize() } // limit, offset
    _ = try reader.readByte() // seekPermission
    guard !reader.isAtEnd else { return .legacy }
    let flag = try reader.readByte()
    guard flag == 1 else {
        throw WalletWireResultRejection(message: "Invalid listOutputs encoding extension: expected 1")
    }
    try reader.requireEnd()
    parameters.removeLast()
    return .spendable
}
