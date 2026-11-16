import BSVCore
import BSVTransaction

extension WalletWireCodec {
    static func encodeActionResultPayload(
        _ result: WalletWireActionResult,
        request: WalletWireActionRequest?,
        listOutputsEncoding: WalletWireListOutputsEncoding,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        var writer = WalletWireWriter(maximumByteCount: limits.maximumPayloadByteCount)
        switch result {
        case .createAction(let value):
            // @bsv/sdk 4.1.1 layout: txid flag, tx flag, noSendChange, sendWithResults,
            // signableTransaction flag. Every part may be absent (COMP-045).
            encodeOptionalTransactionID(value.transactionID, to: &writer)
            try encodeOptionalAtomicBEEF(value.transaction, to: &writer, beefLimits: beefLimits)
            try walletWireWriteOutpointCollection(
                value.noSendChange, kind: "no-send change", to: &writer, limits: limits
            )
            try encodeSendWithResults(value.sendWithResults, to: &writer, limits: limits)
            if let signable = value.signableTransaction {
                writer.writeByte(1)
                try writer.writeVarBytes(
                    walletWireAtomicBEEFBytes(signable.transaction, limits: beefLimits)
                )
                try walletWireRequireActionBytes(
                    signable.reference.bytes.count, kind: "reference", limits: limits
                )
                try writer.writeVarBytes(signable.reference.bytes)
            } else {
                writer.writeByte(0)
            }
        case .signAction(let value):
            encodeOptionalTransactionID(value.transactionID, to: &writer)
            try encodeOptionalAtomicBEEF(value.transaction, to: &writer, beefLimits: beefLimits)
            try encodeSendWithResults(value.sendWithResults, to: &writer, limits: limits)
        case .abortAction(let value):
            // A refusal travels as error code 8 (WalletWireCodec.encodeActionResult).
            guard value.aborted else {
                throw WalletWireResultRejection(
                    code: WalletWireErrorCode.abortRefused,
                    message: WalletWireFailureText.abortRefused
                )
            }
        case .listActions(let value):
            try walletWireRequireResultPage(
                records: value.actions.count,
                total: UInt64(value.totalActions),
                limit: walletWireRequestedPageLimit(request),
                call: "listActions",
                totalField: "totalActions",
                entriesField: "actions",
                resultName: "listActions result"
            )
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
                throw WalletWireResultRejection(message: "The wallet did not accept the action")
            }
        case .listOutputs(let value):
            let balance: Bool
            if case .listOutputs(let query)? = request {
                balance = walletIsBalanceBasket(query.basket)
            } else {
                balance = false
            }
            if balance {
                try walletWireRequireBalanceResult(value)
            } else {
                try walletWireRequireResultPage(
                    records: value.outputs.count,
                    total: value.totalOutputs,
                    limit: walletWireRequestedPageLimit(request),
                    call: "listOutputs",
                    totalField: "totalOutputs",
                    entriesField: "outputs",
                    resultName: "listOutputs result"
                )
            }
            let spendable = listOutputsEncoding == .spendable
            if !spendable, value.outputs.contains(where: { !$0.spendable }) {
                throw WalletWireResultRejection(
                    message: WalletWireFailureText.unspendableLegacyOutputs
                )
            }
            // The spendable layout acknowledges the request extension with -1.
            if spendable { writer.writeCompactSize(UInt64.max) }
            writer.writeCompactSize(value.totalOutputs)
            if let beef = value.beef {
                try writer.writeVarBytes(walletWireBEEFBytes(beef, limits: beefLimits))
            } else { writer.writeCompactSize(UInt64.max) }
            for output in value.outputs {
                writer.writeActionOutpoint(output.outpoint)
                writer.writeCompactSize(output.satoshis)
                if let script = output.lockingScript {
                    try walletWireRequireActionBytes(
                        script.count, kind: "locking script", limits: limits
                    )
                    try writer.writeVarBytes(script)
                } else { writer.writeCompactSize(UInt64.max) }
                if spendable { writer.writeByte(output.spendable ? 1 : 0) }
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
                throw WalletWireResultRejection(message: "The wallet did not relinquish the output")
            }
        }
        try writer.requireWithinLimit(kind: "result payload")
        return writer.bytes
    }

    static func decodeActionResultPayload(
        _ bytes: [UInt8],
        call: WalletCall,
        request: WalletWireActionRequest?,
        listOutputsEncoding: WalletWireListOutputsEncoding,
        beefLimits: BEEFLimits,
        limits: WalletWireLimits
    ) throws -> WalletWireActionResult {
        var reader = WalletWireReader(bytes)
        let value: WalletWireActionResult
        switch call {
        case .createAction:
            let transactionID = try decodeOptionalTransactionID(from: &reader)
            let transaction = try decodeOptionalAtomicBEEF(
                from: &reader, beefLimits: beefLimits
            )
            let noSendChange = try walletWireReadOutpointCollection(
                from: &reader, kind: "no-send change", limits: limits
            )
            let sendWith = try decodeSendWithResults(from: &reader, limits: limits)
            let signable: WalletSignableTransaction?
            switch try reader.readByte() {
            case 0: signable = nil
            case 1:
                let transaction = try walletWireParseAtomicBEEF(
                    reader.readVarBytes(maximum: beefLimits.maximumByteCount, kind: "Atomic BEEF"),
                    limits: beefLimits
                )
                let reference = try reader.readVarBytes(
                    maximum: limits.abiLimits.maximumBytePayloadCount, kind: "reference"
                )
                signable = WalletSignableTransaction(
                    transaction: transaction,
                    reference: try WalletBase64Data(reference, limits: limits.abiLimits)
                )
            case let flag:
                throw WalletWireError.invalidDiscriminator(kind: "signable transaction", value: flag)
            }
            value = .createAction(try WalletCreateActionResult(
                transactionID: transactionID,
                transaction: transaction,
                noSendChange: noSendChange,
                sendWithResults: sendWith,
                signableTransaction: signable,
                limits: limits.abiLimits
            ))
        case .signAction:
            let transactionID = try decodeOptionalTransactionID(from: &reader)
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
            let totalRaw = try reader.readCompactSize()
            guard let total = UInt32(exactly: totalRaw) else { throw WalletWireError.uint32Overflow }
            let pageLimit = walletWirePageLimit(request)
            var actions: [WalletAction] = []
            // @bsv/sdk writes the total, then records until the end of the frame.
            while !reader.isAtEnd {
                try walletWireRequirePageCapacity(actions.count, limit: pageLimit, call: "listActions")
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
            try walletWireRequireResponsePage(records: actions.count, total: totalRaw, call: "listActions")
            value = .listActions(try WalletListActionsResult(
                totalActions: total, actions: actions, limits: limits.abiLimits
            ))
        case .internalizeAction:
            try reader.requireEnd()
            value = .internalizeAction(WalletInternalizeActionResult(accepted: true))
        case .listOutputs:
            let spendable = listOutputsEncoding == .spendable
            if spendable {
                guard try reader.readCompactSize() == UInt64.max else {
                    throw WalletWireResultRejection(
                        message: "Missing listOutputs spendable encoding acknowledgement"
                    )
                }
            }
            let balance: Bool
            if case .listOutputs(let query)? = request {
                balance = walletIsBalanceBasket(query.basket)
            } else {
                balance = false
            }
            // A BRC-112 balance is a full unsigned 64-bit amount, not an output count.
            let total = try reader.readCompactSize()
            if !balance, total > UInt64(UInt32.max) { throw WalletWireError.uint32Overflow }
            let beefBytes = try reader.readOptionalVarBytes(
                maximum: beefLimits.maximumByteCount, kind: "BEEF"
            )
            let pageLimit = walletWirePageLimit(request)
            var outputs: [WalletOutput] = []
            while !reader.isAtEnd {
                try walletWireRequirePageCapacity(outputs.count, limit: pageLimit, call: "listOutputs")
                let outpoint = try reader.readActionOutpoint()
                let satoshis = try reader.readCompactSize()
                let lockingScript = try reader.readOptionalVarBytes(
                    maximum: limits.abiLimits.maximumBytePayloadCount, kind: "locking script"
                )
                var isSpendable = true
                if spendable {
                    switch try reader.readByte() {
                    case 0: isSpendable = false
                    case 1: isSpendable = true
                    case let flag:
                        throw WalletWireError.invalidDiscriminator(kind: "spendable", value: flag)
                    }
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
                    satoshis: satoshis, lockingScript: lockingScript, spendable: isSpendable,
                    customInstructions: custom, tags: tags, outpoint: outpoint,
                    labels: labels, limits: limits.abiLimits
                ))
            }
            let result = try WalletListOutputsResult(
                totalOutputs: total,
                beef: try beefBytes.map { try walletWireParseBEEF($0, limits: beefLimits) },
                outputs: outputs,
                limits: limits.abiLimits
            )
            if balance {
                try walletWireRequireBalanceResult(result)
            } else {
                try walletWireRequireResponsePage(records: outputs.count, total: total, call: "listOutputs")
            }
            value = .listOutputs(result)
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

/// The page size a list request asks for, or nil when there is no request to check against.
func walletWireRequestedPageLimit(_ request: WalletWireActionRequest?) -> Int? {
    switch request {
    case .listActions(let value)?: Int(value.pagination.effectiveLimit)
    case .listOutputs(let value)?: Int(value.pagination.effectiveLimit)
    default: nil
    }
}

/// The page size a list request allows: its limit, or the BRC-100 default of 10.
func walletWirePageLimit(_ request: WalletWireActionRequest?) -> Int {
    switch request {
    case .listActions(let value)?: Int(value.pagination.effectiveLimit)
    case .listOutputs(let value)?: Int(value.pagination.effectiveLimit)
    default: Int(WalletABILimits.maximumProtocolPageSize)
    }
}

func walletWireRequirePageCapacity(_ returned: Int, limit: Int, call: String) throws {
    guard returned < limit else {
        throw WalletWireResultRejection(
            message: "Wallet Wire \(call) response exceeds the requested page limit of \(limit)"
        )
    }
}

/// Checks a wallet's list result before a processor writes it, in `@bsv/sdk` 4.1.1 order:
/// the result checks (`wallet/WalletResultValidation.ts:1932-1951`), then the wire total
/// (`wallet/substrates/WalletWireProcessor.ts:178-191`). A page may be shorter than its
/// total, because the total counts every matching record, but never longer than the
/// request's limit (10 when the request gives none).
func walletWireRequireResultPage(
    records: Int,
    total: UInt64,
    limit: Int?,
    call: String,
    totalField: String,
    entriesField: String,
    resultName: String
) throws {
    let maximumSafeInteger: UInt64 = 9_007_199_254_740_991
    guard total <= maximumSafeInteger else {
        throw WalletWireResultRejection(
            message: "Invalid \(call) result \(totalField): expected an integer from 0 to \(maximumSafeInteger)"
        )
    }
    guard UInt64(records) <= total else {
        throw WalletWireResultRejection(
            message: "Invalid \(call) result \(totalField): expected at least \(records)"
        )
    }
    if let limit, records > limit {
        throw WalletWireResultRejection(
            message: "Invalid \(call) result \(entriesField): expected at most the requested limit of \(limit)"
        )
    }
    guard total <= UInt64(UInt32.max) else {
        throw WalletWireResultRejection(
            message: "Invalid \(resultName) total: expected an integer from 0 to \(UInt32.max), received \(total)"
        )
    }
}

/// A page read from a peer may be shorter than its total, never longer
/// (`wallet/substrates/WalletWireTransceiver.ts:2088-2094`).
func walletWireRequireResponsePage(records: Int, total: UInt64, call: String) throws {
    guard UInt64(records) <= total else {
        throw WalletWireResultRejection(
            message: "Wallet Wire \(call) response returned \(records) records but declared a total of \(total)"
        )
    }
}

/// BRC-112: a balance basket answers with the balance and no records or BEEF.
func walletWireRequireBalanceResult(_ value: WalletListOutputsResult) throws {
    guard value.outputs.isEmpty, value.beef == nil else {
        throw WalletWireResultRejection(
            message: "Invalid listOutputs result: a balance basket returns no outputs or BEEF"
        )
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
        case .failed: 8
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
        case 8: .failed
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
        guard let values else {
            writer.writeCompactSize(UInt64.max)
            return
        }
        guard values.count <= limits.abiLimits.maximumCollectionCount else {
            throw WalletWireError.countLimitExceeded(
                kind: "send-with results", actual: UInt64(values.count),
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        writer.writeCompactSize(UInt64(values.count))
        for value in values {
            writer.writeWalletTransactionID(value.transactionID)
            writer.writeByte(sendWithStatusCode(value.status))
        }
    }

    static func decodeSendWithResults(
        from reader: inout WalletWireReader,
        limits: WalletWireLimits
    ) throws -> [WalletSendWithResult]? {
        let rawCount = try reader.readCompactSize()
        if rawCount == UInt64.max { return nil }
        guard rawCount <= UInt64(limits.abiLimits.maximumCollectionCount) else {
            throw WalletWireError.countLimitExceeded(
                kind: "send-with results", actual: rawCount,
                maximum: limits.abiLimits.maximumCollectionCount
            )
        }
        let count = Int(rawCount)
        guard count <= reader.remainingCount / 33 else { throw WalletWireError.truncated }
        var values: [WalletSendWithResult] = []
        values.reserveCapacity(count)
        for _ in 0..<count {
            values.append(WalletSendWithResult(
                transactionID: try reader.readWalletTransactionID(),
                status: try decodeSendWithStatus(reader.readByte())
            ))
        }
        return values
    }

    static func encodeOptionalTransactionID(
        _ value: TransactionID?,
        to writer: inout WalletWireWriter
    ) {
        guard let value else {
            writer.writeByte(0)
            return
        }
        writer.writeByte(1)
        writer.writeWalletTransactionID(value)
    }

    static func decodeOptionalTransactionID(
        from reader: inout WalletWireReader
    ) throws -> TransactionID? {
        switch try reader.readByte() {
        case 0: return nil
        case 1: return try reader.readWalletTransactionID()
        case let flag:
            throw WalletWireError.invalidDiscriminator(kind: "transaction ID", value: flag)
        }
    }

    static func encodeOptionalAtomicBEEF(
        _ value: AtomicBEEF?,
        to writer: inout WalletWireWriter,
        beefLimits: BEEFLimits
    ) throws {
        guard let value else {
            writer.writeByte(0)
            return
        }
        writer.writeByte(1)
        try writer.writeVarBytes(walletWireAtomicBEEFBytes(value, limits: beefLimits))
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
        guard let values else {
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
            // Scripts are present only when the request asked for them.
            for script in [value.sourceLockingScript, value.unlockingScript] {
                if let script {
                    try walletWireRequireActionBytes(script.count, kind: "script", limits: limits)
                }
                try writer.writeOptionalVarBytes(script)
            }
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
            let source = try reader.readOptionalVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "source locking script"
            )
            let unlocking = try reader.readOptionalVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "unlocking script"
            )
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
        guard let values else {
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
            if let script = value.lockingScript {
                try walletWireRequireActionBytes(
                    script.count, kind: "locking script", limits: limits
                )
            }
            try writer.writeOptionalVarBytes(value.lockingScript)
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
            let script = try reader.readOptionalVarBytes(
                maximum: limits.abiLimits.maximumBytePayloadCount, kind: "locking script"
            )
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
            // @bsv/sdk writes -1 when an action output has no basket.
            let basket = try reader.readOptionalString(
                maximum: walletWireMaximumText(limits), kind: "basket"
            ) ?? ""
            let tags = try walletWireReadStringSlice(
                from: &reader, kind: "tags", optional: false, limits: limits
            ) ?? []
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
