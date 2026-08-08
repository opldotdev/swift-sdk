import BSVCore

/// Dependency validation results that do not require script execution or a chain tracker.
public struct BEEFValidationResult: Hashable, Sendable {
    public let validTransactionIDs: [TransactionID]
    public let invalidTransactionIDs: [TransactionID]
    public let transactionIDOnly: [TransactionID]
    public let missingInputTransactionIDs: [TransactionID]

    public var isValid: Bool {
        invalidTransactionIDs.isEmpty && missingInputTransactionIDs.isEmpty
    }
}

extension BEEF {
    /// Validates proof references and dependency closure in wire order.
    ///
    /// This deliberately excludes script execution and longest-chain trust.
    /// BRC-96 txid-only records are implicit validation anchors only when the
    /// caller opts into that trust policy.
    public func validation(
        allowTransactionIDOnly: Bool,
        limits: TransactionLimits
    ) throws -> BEEFValidationResult {
        let entries = try indexedEntries(limits: limits)
        var valid: Set<TransactionID> = []
        var invalid: [TransactionID] = []
        var transactionIDOnly: [TransactionID] = []
        var missing: Set<TransactionID> = []

        for entry in transactions {
            let transactionID = try entry.transactionID(limits: limits)
            switch entry {
            case .transactionID:
                transactionIDOnly.append(transactionID)
                if allowTransactionIDOnly {
                    valid.insert(transactionID)
                } else {
                    invalid.append(transactionID)
                }
            case .raw, .rawWithMerklePath:
                if isProven(transactionID, entry: entry) {
                    valid.insert(transactionID)
                    continue
                }
                guard let transaction = entry.transaction, !transaction.inputs.isEmpty else {
                    invalid.append(transactionID)
                    continue
                }

                var hasMissingInput = false
                var hasInvalidInput = false
                for input in transaction.inputs {
                    let parentID = input.previousOutput.transactionID
                    if valid.contains(parentID) { continue }
                    if entries[parentID] == nil {
                        missing.insert(parentID)
                        hasMissingInput = true
                    } else {
                        hasInvalidInput = true
                    }
                }
                if hasMissingInput || hasInvalidInput {
                    invalid.append(transactionID)
                } else {
                    valid.insert(transactionID)
                }
            }
        }

        return BEEFValidationResult(
            validTransactionIDs: transactions.compactMap { entry in
                guard let transactionID = try? entry.transactionID(limits: limits),
                      valid.contains(transactionID) else { return nil }
                return transactionID
            },
            invalidTransactionIDs: invalid,
            transactionIDOnly: transactionIDOnly,
            missingInputTransactionIDs: missing.sorted { $0.displayHex < $1.displayHex }
        )
    }

    /// Computes every level-zero leaf root and cross-checks them by block height.
    public func merkleRootsByBlockHeight() throws -> [UInt32: Hash256] {
        var roots: [UInt32: Hash256] = [:]
        for (index, path) in merklePaths.enumerated() {
            var pathRoot: Hash256?
            for element in path.levels[0] {
                guard let hash = element.hash else { continue }
                let transactionID = TransactionID(
                    exactDigestBytesGuaranteed: hash.bytes
                )
                let root: Hash256
                do {
                    root = try path.root(for: transactionID)
                } catch let error as MerklePathError {
                    throw BEEFError.invalidMerklePath(index: index, cause: error)
                }
                if let existing = pathRoot, existing != root {
                    throw BEEFError.conflictingMerkleRoot(blockHeight: path.blockHeight)
                }
                pathRoot = root
            }
            if let pathRoot {
                if let existing = roots[path.blockHeight], existing != pathRoot {
                    throw BEEFError.conflictingMerkleRoot(blockHeight: path.blockHeight)
                }
                roots[path.blockHeight] = pathRoot
            }
        }
        return roots
    }
}
