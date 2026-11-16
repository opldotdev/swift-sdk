import BSVCore
import Foundation

/// Plain sentences a wallet can show when a transaction cannot be read, built or signed.
///
/// The cases stay typed for callers that branch on them, and `String(reflecting:)` still gives
/// the case with its values for a log. Input numbers count from 0, as the transaction does.
extension TransactionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidMaximumTransactionByteCount, .invalidMaximumInputCount,
            .invalidMaximumOutputCount, .invalidMaximumScriptByteCount:
            "The transaction size limits are not valid."
        case .transactionTooLarge, .inputCountExceedsLimit, .outputCountExceedsLimit,
            .countNotRepresentable, .scriptTooLarge, .serializedSizeOverflow:
            "The transaction is larger than the wallet can handle."
        case .invalidExtendedFormatMarker, .malformed, .invalidHex:
            "The transaction data could not be read."
        case .invalidInputIndex(let index):
            "The transaction has no input \(index)."
        case .missingSourceOutput(let inputIndex):
            "Input \(inputIndex) is missing the output it spends, so it cannot be signed or checked."
        case .sourceOutputIsNotPayToPublicKeyHash(let inputIndex):
            "Input \(inputIndex) spends an output that is not a plain address payment, so this signer cannot sign it."
        case .privateKeyDoesNotMatchSourceOutput(let inputIndex):
            "The key for input \(inputIndex) does not match the address it spends from."
        case .satoshiTotalOverflow, .feeCalculationOverflow:
            "The transaction amounts are too large to add up."
        case .outputSatoshisExceedInputs(let inputs, let outputs):
            "The transaction sends \(outputs) satoshis, but its inputs hold only \(inputs)."
        case .missingUnlockingScriptEstimate(let inputIndex),
            .invalidUnlockingScriptEstimate(let inputIndex, _),
            .unlockingScriptEstimateExceedsLimit(let inputIndex, _, _):
            "The fee could not be worked out: the signature size for input \(inputIndex) is missing or not valid."
        case .insufficientInputSatoshis(let inputs, let outputs, let fee):
            "Not enough funds: the inputs hold \(inputs) satoshis, but the outputs need \(outputs) plus a fee of \(fee)."
        }
    }
}

/// Plain sentences for a Merkle proof that cannot be read or does not prove its transaction.
extension MerklePathError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidMaximumByteCount, .invalidMaximumLeavesPerLevel, .invalidMaximumTotalLeaves:
            "The Merkle proof size limits are not valid."
        case .pathTooLarge, .leafCountExceedsLimit, .totalLeafCountExceedsLimit,
            .countNotRepresentable, .serializedSizeOverflow:
            "The Merkle proof is larger than the wallet can handle."
        case .blockHeightOutOfRange, .invalidTreeHeight, .invalidFlags, .duplicateLeafOffset,
            .duplicateMarkerRequiresOddOffset, .transactionIDMarkerOutsideLevelZero,
            .offsetOutOfRange, .missingLevelZeroHash, .malformed, .invalidHex, .invalidJSON,
            .missingSibling, .conflictingElement:
            "The Merkle proof could not be read."
        case .transactionNotInPath:
            "The Merkle proof does not include this transaction."
        case .blockHeightMismatch(let expected, let actual):
            "The Merkle proof is for block \(actual), not block \(expected)."
        case .rootMismatch, .inconsistentRoot:
            "The Merkle proof does not match the block it names."
        }
    }
}
