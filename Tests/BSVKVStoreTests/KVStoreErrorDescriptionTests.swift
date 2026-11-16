import BSVKVStore
import BSVWallet
import Foundation
import Testing

@Suite("Key-value store error descriptions")
struct KVStoreErrorDescriptionTests {
    @Test("errors added for TypeScript tokens have plain sentences")
    func plainSentences() throws {
        #expect(
            KVStoreError.invalidWalletLocator(.protocolNameTooShort(actualUTF8ByteCount: 3, minimum: 5))
                .localizedDescription == "The key-value store name must be at least 5 characters long."
        )
        #expect(
            KVStoreError.invalidWalletLocator(.keyIDTooShort).localizedDescription
                == "The key is not a length the wallet accepts."
        )
        #expect(
            KVStoreError.lockingKeyMismatch.localizedDescription
                == "The stored entry does not belong to this wallet."
        )
        #expect(KVStoreError.invalidSignature.localizedDescription == "The stored entry is not signed correctly.")
        #expect(
            KVStoreError.invalidTokenFieldCount(actual: 1).localizedDescription
                == "The stored entry is not in the expected format."
        )
        // The log form keeps the cause.
        #expect(
            String(reflecting: KVStoreError.invalidWalletLocator(.keyIDTooShort)).contains("keyIDTooShort")
        )
    }
}
