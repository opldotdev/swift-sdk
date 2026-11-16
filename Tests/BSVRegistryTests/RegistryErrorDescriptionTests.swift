import BSVRegistry
import BSVScript
import Foundation
import Testing

@Suite("Registry error descriptions")
struct RegistryErrorDescriptionTests {
    @Test("registry errors have plain sentences and keep detail for logs")
    func plainSentences() {
        #expect(
            RegistryError.emptyField(name: "iconURL").localizedDescription
                == "The registry icon address must not be empty."
        )
        #expect(
            RegistryError.textTooLong(field: "description", actual: 16_385, maximum: 16_384)
                .localizedDescription == "The registry description is too long."
        )
        #expect(
            RegistryError.aggregateTooLarge(actual: 70_000, maximum: 65_536).localizedDescription
                == "The registry entry is larger than the wallet accepts."
        )
        let pushDrop = RegistryError.pushDropFailure(.malformedPush(offset: 3))
        #expect(pushDrop.localizedDescription == "The registry entry is not in the expected script format.")
        #expect(String(reflecting: pushDrop).contains("malformedPush"))
        #expect(
            RegistryError.roundTripMismatch.localizedDescription
                == "The wallet wrote a registry entry that does not match what was asked. Nothing was published."
        )
        #expect(
            RegistryError.lockingKeyNotLinkedToOperator.localizedDescription
                == "The registry entry was not made by the operator it names."
        )
        #expect(
            RegistryError.invalidSignature.localizedDescription
                == "The registry entry is not signed correctly by its operator."
        )
    }
}
