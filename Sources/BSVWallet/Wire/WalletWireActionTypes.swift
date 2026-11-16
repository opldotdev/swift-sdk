/// The action and output-query request subset of the BRC-100 wallet wire.
public enum WalletWireActionRequest:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    case createAction(WalletCreateActionRequest)
    case signAction(WalletSignActionRequest)
    case abortAction(WalletAbortActionRequest)
    case listActions(WalletListActionsRequest)
    case internalizeAction(WalletInternalizeActionRequest)
    case listOutputs(WalletListOutputsRequest)
    case relinquishOutput(WalletRelinquishOutputRequest)

    public var call: WalletCall {
        switch self {
        case .createAction: .createAction
        case .signAction: .signAction
        case .abortAction: .abortAction
        case .listActions: .listActions
        case .internalizeAction: .internalizeAction
        case .listOutputs: .listOutputs
        case .relinquishOutput: .relinquishOutput
        }
    }

    public var description: String { "<redacted wallet-wire action request call \(call.rawValue)>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

/// The action and output-query result subset of the BRC-100 wallet wire.
public enum WalletWireActionResult:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    case createAction(WalletCreateActionResult)
    case signAction(WalletSignActionResult)
    case abortAction(WalletAbortActionResult)
    case listActions(WalletListActionsResult)
    case internalizeAction(WalletInternalizeActionResult)
    case listOutputs(WalletListOutputsResult)
    case relinquishOutput(WalletRelinquishOutputResult)

    public var call: WalletCall {
        switch self {
        case .createAction: .createAction
        case .signAction: .signAction
        case .abortAction: .abortAction
        case .listActions: .listActions
        case .internalizeAction: .internalizeAction
        case .listOutputs: .listOutputs
        case .relinquishOutput: .relinquishOutput
        }
    }

    public var description: String { "<redacted wallet-wire action result call \(call.rawValue)>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": call.rawValue]) }
}

public struct WalletWireDecodedActionRequest:
    Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let originator: String
    public let request: WalletWireActionRequest
    /// The `listOutputs` response layout the caller asked for.
    public let listOutputsEncoding: WalletWireListOutputsEncoding

    public init(
        originator: String,
        request: WalletWireActionRequest,
        listOutputsEncoding: WalletWireListOutputsEncoding = .legacy
    ) {
        self.originator = originator
        self.request = request
        self.listOutputsEncoding = listOutputsEncoding
    }

    public var description: String { "<redacted decoded wallet-wire action request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": request.call.rawValue]) }
}

/// The `listOutputs` response layout a transceiver asks for.
///
/// `.legacy` is the deployed SDK 2/3 layout, which cannot carry an unspendable
/// output. `.spendable` appends the one-byte request extension `01` and reads
/// the response with an explicit spendable flag per output (TypeScript
/// `WalletWireTransceiver` option `listOutputsEncoding: 'spendable'`).
public enum WalletWireListOutputsEncoding: Hashable, Sendable {
    case legacy
    case spendable
}
