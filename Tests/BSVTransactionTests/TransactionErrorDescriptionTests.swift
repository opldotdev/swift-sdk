import BSVCore
import BSVTransaction
import Foundation
import Testing

/// What a wallet shows when a transaction cannot be built, signed or proved.
@Suite("Transaction error descriptions")
struct TransactionErrorDescriptionTests {
    @Test("signing and funding failures name the input and the amounts")
    func transactionSentences() {
        #expect(
            TransactionError.insufficientInputSatoshis(inputs: 1_000, outputs: 900, fee: 150)
                .localizedDescription
                == "Not enough funds: the inputs hold 1000 satoshis, but the outputs need 900 plus a fee of 150."
        )
        #expect(
            TransactionError.privateKeyDoesNotMatchSourceOutput(inputIndex: 2).localizedDescription
                == "The key for input 2 does not match the address it spends from."
        )
        #expect(
            TransactionError.missingSourceOutput(inputIndex: 0).localizedDescription
                == "Input 0 is missing the output it spends, so it cannot be signed or checked."
        )
        #expect(
            TransactionError.serializedSizeOverflow.localizedDescription
                == "The transaction is larger than the wallet can handle."
        )
    }

    @Test("Merkle proof failures say what is wrong with the proof")
    func merkleSentences() {
        #expect(
            MerklePathError.blockHeightMismatch(expected: 800_000, actual: 800_001).localizedDescription
                == "The Merkle proof is for block 800001, not block 800000."
        )
        #expect(
            MerklePathError.rootMismatch.localizedDescription
                == "The Merkle proof does not match the block it names."
        )
    }
}
