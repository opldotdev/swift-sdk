import BSVCore
import BSVTransaction

extension WalletWireCodec {
    static func encodeActionResultPayload(
        _ result: WalletWireActionResult,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        var writer = WalletWireWriter(maximumByteCount: limits.maximumPayloadByteCount)
        switch result {
        case .createAction(let value):
            // The pinned serializer embeds a second success byte in this call's payload.
            writer.writeByte(0)
            guard let transactionID = value.transactionID else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "create-action result without transaction ID"
                )
            }
            guard value.signableTransaction == nil else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "pinned Go signable create-action result"
                )
            }
            writer.writeByte(1)
            writer.writeWireTransactionID(transactionID)
            if let transaction = value.transaction {
                writer.writeByte(1)
                try writer.writeVarBytes(walletWireAtomicBEEFBytes(transaction, limits: beefLimits))
            } else { writer.writeByte(0) }
            try encodeOptionalOutpointBytes(
                value.noSendChange, kind: "no-send change", to: &writer, limits: limits
            )
            try encodeSendWithResults(value.sendWithResults, to: &writer, limits: limits)
            writer.writeByte(0)
        case .signAction(let value):
            guard let transactionID = value.transactionID else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "sign-action result without transaction ID"
                )
            }
            writer.writeByte(1)
            writer.writeWireTransactionID(transactionID)
            if let transaction = value.transaction {
                writer.writeByte(1)
                try writer.writeVarBytes(walletWireAtomicBEEFBytes(transaction, limits: beefLimits))
            } else { writer.writeByte(0) }
            try encodeSendWithResults(value.sendWithResults, to: &writer, limits: limits)
        case .abortAction(let value):
            guard value.aborted else {
                throw WalletWireError.nonRoundTrippableValue(kind: "false abort-action result")
            }
        case .listActions(let value):
            guard let actionCount = UInt32(exactly: value.actions.count),
                  value.totalActions == actionCount else {
                throw WalletWireError.nonRoundTrippableValue(kind: "total actions mismatch")
            }
            writer.writeCompactSize(UInt64(value.totalActions))
            for action in value.actions {
                writer.writeDisplayTransactionID(action.transactionID)
                writer.writeCompactSize(UInt64(bitPattern: action.satoshis))
                writer.writeByte(actionStatusCode(action.status))
                writer.writeByte(action.isOutgoing ? 1 : 0)
                try walletWireWriteText(
                    action.description, kind: "action description", to: &writer, limits: limits
                )
                try walletWireWriteStringSlice(
                    action.labels, kind: "labels", to: &writer, limits: limits
                )
                writer.writeCompactSize(UInt64(action.version))
                writer.writeCompactSize(UInt64(action.lockTime))
                try encodeActionInputs(action.inputs, to: &writer, limits: limits)
                try encodeActionOutputs(action.outputs, to: &writer, limits: limits)
            }
        case .internalizeAction(let value):
            guard value.accepted else {
                throw WalletWireError.nonRoundTrippableValue(kind: "false internalize-action result")
            }
        case .listOutputs(let value):
            guard let outputCount = UInt32(exactly: value.outputs.count),
                  value.totalOutputs == outputCount else {
                throw WalletWireError.nonRoundTrippableValue(kind: "total outputs mismatch")
            }
            writer.writeCompactSize(UInt64(value.totalOutputs))
            if let beef = value.beef {
                try writer.writeVarBytes(walletWireBEEFBytes(beef, limits: beefLimits))
            } else { writer.writeCompactSize(UInt64.max) }
            for output in value.outputs {
                guard output.spendable else {
                    throw WalletWireError.nonRoundTrippableValue(kind: "unspendable listed output")
                }
                writer.writeActionOutpoint(output.outpoint)
                writer.writeCompactSize(output.satoshis)
                if let script = output.lockingScript {
                    guard !script.isEmpty else {
                        throw WalletWireError.nonRoundTrippableValue(kind: "empty optional locking script")
                    }
                    try walletWireRequireActionBytes(
                        script.count, kind: "locking script", limits: limits
                    )
                    try writer.writeVarBytes(script)
                } else { writer.writeCompactSize(UInt64.max) }
                try walletWireWriteOptionalText(
                    output.customInstructions, kind: "custom instructions",
                    to: &writer, limits: limits
                )
                try walletWireWriteStringSlice(
                    output.tags, kind: "tags", to: &writer, limits: limits
                )
                try walletWireWriteStringSlice(
                    output.labels, kind: "labels", to: &writer, limits: limits
                )
            }
        case .relinquishOutput(let value):
            guard value.relinquished else {
                throw WalletWireError.nonRoundTrippableValue(kind: "false relinquish-output result")
            }
        }
        try writer.requireWithinLimit(kind: "result payload")
        return writer.bytes
    }

    static func decodeActionResultPayload(
        _ bytes: [UInt8],
        call: WalletCall,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits
    ) throws -> WalletWireActionResult {
        var reader = WalletWireReader(bytes)
        let value: WalletWireActionResult
        switch call {
        case .createAction:
            guard try reader.readByte() == 0 else {
                throw WalletWireError.nonRoundTrippableValue(kind: "nested create-action failure")
            }
            let transactionID = try decodeRequiredGoTransactionID(from: &reader)
            let transaction = try decodeOptionalAtomicBEEF(
                from: &reader, beefLimits: beefLimits
            )
            let noSendChange = try decodeOptionalOutpointBytes(
                from: &reader, kind: "no-send change", limits: limits
            )
            let sendWith = try decodeSendWithResults(from: &reader, limits: limits)
            switch try reader.readByte() {
            case 0: break
            case 1:
                // Go always re-encodes a zero transaction ID with this union. It cannot
                // preserve the Swift ABI's mutually exclusive signable representation.
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "pinned Go signable create-action result"
                )
            case let flag:
                throw WalletWireError.invalidDiscriminator(kind: "signable transaction", value: flag)
            }
            value = .createAction(try WalletCreateActionResult(
                transactionID: transactionID,
                transaction: transaction,
                noSendChange: noSendChange,
                sendWithResults: sendWith,
                limits: limits.abiLimits
            ))
        case .signAction:
            let transactionID = try decodeRequiredGoTransactionID(from: &reader)
            let transaction = try decodeOptionalAtomicBEEF(
                from: &reader, beefLimits: beefLimits
            )
            let sendWith = try decodeSendWithResults(from: &reader, limits: limits)
            value = .signAction(try WalletSignActionResult(
                transactionID: transactionID,
                transaction: transaction,
                sendWithResults: sendWith,
                limits: limits.abiLimits
            ))
        case .abortAction:
            try reader.requireEnd()
            value = .abortAction(WalletAbortActionResult(aborted: true))
        case .listActions:
            let count = try reader.readCount(
                maximum: limits.abiLimits.maximumCollectionCount, kind: "actions"
            )
            guard let total = UInt32(exactly: count) else { throw WalletWireError.uint32Overflow }
            var actions: [WalletAction] = []
            actions.reserveCapacity(min(count, reader.remainingCount / 40))
            for _ in 0..<count {
                let transactionID = try reader.readDisplayTransactionID()
                let satoshis = Int64(bitPattern: try reader.readCompactSize())
                let status = try decodeActionStatus(reader.readByte())
                let outgoing: Bool
                switch try reader.readByte() {
                case 0: outgoing = false
                case 1: outgoing = true
                case let flag:
                    throw WalletWireError.invalidDiscriminator(kind: "is outgoing", value: flag)
                }
                let description = try reader.readString(
                    maximum: walletWireMaximumText(limits), kind: "action description"
                )
                let labels = try walletWireReadStringSlice(
                    from: &reader, kind: "labels", optional: true, limits: limits
                )
                let versionRaw = try reader.readCompactSize()
                let lockTimeRaw = try reader.readCompactSize()
                guard let version = UInt32(exactly: versionRaw),
                      let lockTime = UInt32(exactly: lockTimeRaw) else {
                    throw WalletWireError.uint32Overflow
                }
                let inputs = try decodeActionInputs(from: &reader, limits: limits)
                let outputs = try decodeActionOutputs(from: &reader, limits: limits)
                actions.append(try WalletAction(
                    transactionID: transactionID, satoshis: satoshis, status: status,
                    isOutgoing: outgoing, description: description, labels: labels,
                    version: version, lockTime: lockTime, inputs: inputs, outputs: outputs,
                    limits: limits.abiLimits
                ))
            }
            value = .listActions(try WalletListActionsResult(
                totalActions: total, actions: actions, limits: limits.abiLimits
            ))
        case .internalizeAction:
            try reader.requireEnd()
            value = .internalizeAction(WalletInternalizeActionResult(accepted: true))
        case .listOutputs:
            let count = try reader.readCount(
                maximum: limits.abiLimits.maximumCollectionCount, kind: "outputs"
            )
            guard let total = UInt32(exactly: count) else { throw WalletWireError.uint32Overflow }
            let beefBytes = try reader.readOptionalVarBytes(
                maximum: beefLimits.maximumByteCount, kind: "BEEF"
            )
            var outputs: [WalletOutput] = []
            outputs.reserveCapacity(min(count, reader.remainingCount / 34))
            for _ in 0..<count {
                let outpoint = try reader.readActionOutpoint()
                let satoshis = try reader.readCompactSize()
                let lockingScript = try reader.readOptionalVarBytes(
                    maximum: limits.abiLimits.maximumBytePayloadCount, kind: "locking script"
                )
                if lockingScript?.isEmpty == true {
                    throw WalletWireError.nonRoundTrippableValue(kind: "empty optional locking script")
                }
                let custom = try reader.readOptionalString(
                    maximum: walletWireMaximumText(limits), kind: "custom instructions"
                )
                let tags = try walletWireReadStringSlice(
                    from: &reader, kind: "tags", optional: true, limits: limits
                )
                let labels = try walletWireReadStringSlice(
                    from: &reader, kind: "labels", optional: true, limits: limits
                )
                outputs.append(try WalletOutput(
                    satoshis: satoshis, lockingScript: lockingScript, spendable: true,
                    customInstructions: custom, tags: tags, outpoint: outpoint,
                    labels: labels, limits: limits.abiLimits
                ))
            }
            value = .listOutputs(try WalletListOutputsResult(
                totalOutputs: total,
                beef: try beefBytes.map { try walletWireParseBEEF($0, limits: beefLimits) },
                outputs: outputs,
                limits: limits.abiLimits
            ))
        case .relinquishOutput:
            try reader.requireEnd()
            value = .relinquishOutput(WalletRelinquishOutputResult(relinquished: true))
        default:
            throw WalletWireError.invalidCall(call.rawValue)
        }
        try reader.requireEnd()
        return value
    }
}

private extension WalletWireCodec {
    static func actionStatusCode(_ value: WalletActionStatus) -> UInt8 {
        switch value {
        case .completed: 1
        case .unprocessed: 2
        case .sending: 3
        case .unproven: 4
        case .unsigned: 5
        case .nosend: 6
        case .nonfinal: 7
        }
    }

    static func decodeActionStatus(_ value: UInt8) throws -> WalletActionStatus {
        switch value {
        case 1: .completed
        case 2: .unprocessed
        case 3: .sending
        case 4: .unproven
        case 5: .unsigned
        case 6: .nosend
        case 7: .nonfinal
        default: throw WalletWireError.invalidDiscriminator(kind: "action status", value: value)
        }
    }

    static func sendWithStatusCode(_ value: WalletActionResultStatus) -> UInt8 {
        switch value {
        case .unproven: 1
        case .sending: 2
        case .failed: 3
        }
    }

    static func decodeSendWithStatus(_ value: UInt8) throws -> WalletActionResultStatus {
        switch value {
        case 1: .unproven
        case 2: .sending
        case 3: .failed
        default: throw WalletWireError.invalidDiscriminator(kind: "send-with status", value: value)
        }
    }

    static func encodeSendWithResults(
        _ values: [WalletSendWithResult]?,
        to writer: inout WalletWireWriter,
        limits: WalletWireLimits
    ) throws {
        if values?.isEmpty == true {
            throw WalletWireError.nonRoundTrippableValue(kind: "empty send-with results")
        }
        let values = values ?? []
        guard values.count <= limits.abiLimits.maximumCollectionCount else {
            throw WalletWireError.countLimitExceeded(
                kind: "send-with results", actual: UInt64(values.count),
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        writer.writeCompactSize(UInt64(values.count))
        for value in values {
            writer.writeWireTransactionID(value.transactionID)
            writer.writeByte(sendWithStatusCode(value.status))
        }
    }

    static func decodeSendWithResults(
        from reader: inout WalletWireReader,
        limits: WalletWireLimits
    ) throws -> [WalletSendWithResult]? {
        let count = try reader.readCount(
            maximum: limits.abiLimits.maximumCollectionCount, kind: "send-with results"
        )
        if count == 0 { return nil }
        guard count <= reader.remainingCount / 33 else { throw WalletWireError.truncated }
        var values: [WalletSendWithResult] = []
        values.reserveCapacity(count)
        for _ in 0..<count {
            values.append(WalletSendWithResult(
                transactionID: try reader.readWireTransactionID(),
                status: try decodeSendWithStatus(reader.readByte())
            ))
        }
        return values
    }

    static func encodeOptionalOutpointBytes(
        _ values: [Outpoint]?,
        kind: String,
        to writer: inout WalletWireWriter,
        limits: WalletWireLimits
    ) throws {
        guard let values else {
            try writer.writeOptionalVarBytes(nil)
            return
        }
        let nestedCount = try walletWireOutpointCollectionByteCount(
            values, kind: kind, limits: limits
        )
        writer.writeCompactSize(UInt64(nestedCount))
        try walletWireWriteOutpointCollection(
            values, kind: kind, to: &writer, limits: limits
        )
    }

    static func decodeOptionalOutpointBytes(
        from reader: inout WalletWireReader,
        kind: String,
        limits: WalletWireLimits
    ) throws -> [Outpoint]? {
        guard let bytes = try reader.readOptionalVarBytes(
            maximum: limits.maximumPayloadByteCount, kind: kind
        ) else { return nil }
        var nested = WalletWireReader(bytes)
        let values = try walletWireReadOutpointCollection(
            from: &nested, kind: kind, limits: limits
        )
        try nested.requireEnd()
        guard let values else {
            throw WalletWireError.nonRoundTrippableValue(kind: "nested absent \(kind)")
        }
        return values
    }

    static func decodeRequiredGoTransactionID(
        from reader: inout WalletWireReader
    ) throws -> TransactionID {
        switch try reader.readByte() {
        case 1: return try reader.readWireTransactionID()
        case 0:
            throw WalletWireError.nonRoundTrippableValue(kind: "absent pinned Go transaction ID")
        case let flag:
            throw WalletWireError.invalidDiscriminator(kind: "transaction ID", value: flag)
        }
    }

    static func decodeOptionalAtomicBEEF(
        from reader: inout WalletWireReader,
        beefLimits: BEEFLimits
    ) throws -> AtomicBEEF? {
        switch try reader.readByte() {
        case 0: return nil
        case 1:
            return try walletWireParseAtomicBEEF(
                reader.readVarBytes(maximum: beefLimits.maximumByteCount, kind: "Atomic BEEF"),
                limits: beefLimits
            )
        case let flag:
            throw WalletWireError.invalidDiscriminator(kind: "transaction", value: flag)
        }
    }

    static func encodeActionInputs(
        _ values: [WalletActionInput]?,
        to writer: inout WalletWireWriter,
        limits: WalletWireLimits
    ) throws {
        guard let values, !values.isEmpty else {
            if values?.isEmpty == true {
                throw WalletWireError.nonRoundTrippableValue(kind: "empty action inputs")
            }
            writer.writeCompactSize(UInt64.max)
            return
        }
        guard values.count <= limits.abiLimits.maximumCollectionCount else {
            throw WalletWireError.countLimitExceeded(
                kind: "inputs", actual: UInt64(values.count),
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        writer.writeCompactSize(UInt64(values.count))
        for value in values {
            writer.writeActionOutpoint(value.sourceOutpoint)
            writer.writeCompactSize(value.sourceSatoshis)
            guard let source = value.sourceLockingScript, !source.isEmpty else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "absent or empty action source locking script"
                )
            }
            guard let unlocking = value.unlockingScript, !unlocking.isEmpty else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "absent or empty action unlocking script"
                )
            }
            try walletWireRequireActionBytes(
                source.count, kind: "source locking script", limits: limits
            )
            try walletWireRequireActionBytes(
                unlocking.count, kind: "unlocking script", limits: limits
            )
            try writer.writeVarBytes(source)
            try writer.writeVarBytes(unlocking)
            try walletWireWriteText(
                value.inputDescription, kind: "input description", to: &writer, limits: limits
            )
            writer.writeCompactSize(UInt64(value.sequenceNumber))
        }
    }

    static func decodeActionInputs(
        from reader: inout WalletWireReader,
        limits: WalletWireLimits
    ) throws -> [WalletActionInput]? {
        let count = try reader.readCompactSize()
        if count == UInt64.max { return nil }
        if count == 0 {
            throw WalletWireError.nonRoundTrippableValue(kind: "empty action inputs")
        }
        guard count <= UInt64(limits.abiLimits.maximumCollectionCount), count <= UInt64(Int.max) else {
            throw WalletWireError.countLimitExceeded(
                kind: "inputs", actual: count, maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        var values: [WalletActionInput] = []
        values.reserveCapacity(min(Int(count), reader.remainingCount / 35))
        for _ in 0..<Int(count) {
            let outpoint = try reader.readActionOutpoint()
            let satoshis = try reader.readCompactSize()
            guard let source = try reader.readOptionalVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "source locking script"
            ) else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "absent action source locking script"
                )
            }
            guard let unlocking = try reader.readOptionalVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "unlocking script"
            ) else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "absent action unlocking script"
                )
            }
            if source.isEmpty || unlocking.isEmpty {
                throw WalletWireError.nonRoundTrippableValue(kind: "empty action script")
            }
            let description = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "input description"
            )
            let sequenceRaw = try reader.readCompactSize()
            guard let sequence = UInt32(exactly: sequenceRaw) else { throw WalletWireError.uint32Overflow }
            values.append(try WalletActionInput(
                sourceOutpoint: outpoint, sourceSatoshis: satoshis,
                sourceLockingScript: source, unlockingScript: unlocking,
                inputDescription: description, sequenceNumber: sequence,
                limits: limits.abiLimits
            ))
        }
        return values
    }

    static func encodeActionOutputs(
        _ values: [WalletActionOutput]?,
        to writer: inout WalletWireWriter,
        limits: WalletWireLimits
    ) throws {
        guard let values, !values.isEmpty else {
            if values?.isEmpty == true {
                throw WalletWireError.nonRoundTrippableValue(kind: "empty action outputs")
            }
            writer.writeCompactSize(UInt64.max)
            return
        }
        guard values.count <= limits.abiLimits.maximumCollectionCount else {
            throw WalletWireError.countLimitExceeded(
                kind: "outputs", actual: UInt64(values.count),
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        writer.writeCompactSize(UInt64(values.count))
        for value in values {
            writer.writeCompactSize(UInt64(value.outputIndex))
            writer.writeCompactSize(value.satoshis)
            guard let script = value.lockingScript, !script.isEmpty else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "absent or empty action output locking script"
                )
            }
            try walletWireRequireActionBytes(
                script.count, kind: "locking script", limits: limits
            )
            try writer.writeVarBytes(script)
            writer.writeByte(value.spendable ? 1 : 0)
            try walletWireWriteText(
                value.outputDescription, kind: "output description", to: &writer, limits: limits
            )
            try walletWireWriteText(
                value.basket, kind: "basket", to: &writer, limits: limits
            )
            try walletWireWriteStringSlice(value.tags, kind: "tags", to: &writer, limits: limits)
            try walletWireWriteOptionalText(
                value.customInstructions, kind: "custom instructions",
                to: &writer, limits: limits
            )
        }
    }

    static func decodeActionOutputs(
        from reader: inout WalletWireReader,
        limits: WalletWireLimits
    ) throws -> [WalletActionOutput]? {
        let count = try reader.readCompactSize()
        if count == UInt64.max { return nil }
        if count == 0 {
            throw WalletWireError.nonRoundTrippableValue(kind: "empty action outputs")
        }
        guard count <= UInt64(limits.abiLimits.maximumCollectionCount), count <= UInt64(Int.max) else {
            throw WalletWireError.countLimitExceeded(
                kind: "outputs", actual: count, maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        var values: [WalletActionOutput] = []
        values.reserveCapacity(min(Int(count), reader.remainingCount))
        for _ in 0..<Int(count) {
            let indexRaw = try reader.readCompactSize()
            guard let index = UInt32(exactly: indexRaw) else { throw WalletWireError.uint32Overflow }
            let satoshis = try reader.readCompactSize()
            guard let script = try reader.readOptionalVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "locking script"
            ) else {
                throw WalletWireError.nonRoundTrippableValue(
                    kind: "absent action output locking script"
                )
            }
            if script.isEmpty {
                throw WalletWireError.nonRoundTrippableValue(kind: "empty action output locking script")
            }
            let spendable: Bool
            switch try reader.readByte() {
            case 0: spendable = false
            case 1: spendable = true
            case let flag:
                throw WalletWireError.invalidDiscriminator(kind: "spendable", value: flag)
            }
            let description = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "output description"
            )
            let basket = try reader.readString(
                maximum: walletWireMaximumText(limits), kind: "basket"
            )
            guard let tags = try walletWireReadStringSlice(
                from: &reader, kind: "tags", optional: false, limits: limits
            ) else { throw WalletWireError.nonRoundTrippableValue(kind: "absent tags") }
            let custom = try reader.readOptionalString(
                maximum: walletWireMaximumText(limits), kind: "custom instructions"
            )
            values.append(try WalletActionOutput(
                satoshis: satoshis, lockingScript: script, spendable: spendable,
                customInstructions: custom, tags: tags, outputIndex: index,
                outputDescription: description, basket: basket, limits: limits.abiLimits
            ))
        }
        return values
    }
}
