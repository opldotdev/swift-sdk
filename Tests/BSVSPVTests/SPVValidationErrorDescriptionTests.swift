import BSVCore
import BSVSPV
import Foundation
import Testing

/// What a wallet shows when a received transaction fails verification, and what the log keeps.
@Suite("SPV validation error descriptions")
struct SPVValidationErrorDescriptionTests {
    @Test("fee and missing-source failures read in plain words")
    func sentences() throws {
        let transactionID = try TransactionID(displayHex: String(repeating: "cd", count: 32))
        #expect(
            SPVValidationError.feeTooLow(paid: 10, required: 25).localizedDescription
                == "The transaction fee is too low: it pays 10 satoshis and needs 25."
        )
        #expect(
            SPVValidationError.missingSourceTransaction(
                transactionID: transactionID,
                inputIndex: 1,
                sourceTransactionID: transactionID
            ).localizedDescription
                == "The transaction data is missing the transaction that input 1 spends."
        )
    }

    @Test("the log form names the case and prints transaction IDs as display hex")
    func debugForm() throws {
        let transactionID = try TransactionID(displayHex: String(repeating: "cd", count: 32))
        #expect(
            String(reflecting: SPVValidationError.rootTransactionMissing(transactionID))
                == "SPVValidationError.rootTransactionMissing(\(transactionID.displayHex))"
        )
        #expect(
            String(reflecting: SPVValidationError.feeTooLow(paid: 10, required: 25))
                == "SPVValidationError.feeTooLow(paid: 10, required: 25)"
        )
    }
}
