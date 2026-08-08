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

    public init(originator: String, request: WalletWireActionRequest) {
        self.originator = originator
        self.request = request
    }

    public var description: String { "<redacted decoded wallet-wire action request>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["call": request.call.rawValue]) }
}
