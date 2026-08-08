import XCTest
import BSVCore
import BSVKeys
@testable import BSVWallet

final class WalletKeyDeriverTests: XCTestCase {
    func testPinnedDerivationAndBRC42Directions() throws {
        let alice = try walletTestPrivateKey(42)
        let bob = try walletTestPrivateKey(69)
        let protocolID = try walletTestProtocol()
        let keyID = try walletTestKeyID()
        let deriver = WalletKeyDeriver(rootKey: alice)
        XCTAssertEqual(deriver.invoice(protocolID: protocolID, keyID: keyID), "0-testprotocol-12345")

        let privateChild = try deriver.derivePrivateKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(bob.publicKey)
        )
        let forSelf = try deriver.derivePublicKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(bob.publicKey),
            forSelf: true
        )
        let byCounterparty = try WalletKeyDeriver(rootKey: bob).derivePublicKey(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: .publicKey(alice.publicKey),
            forSelf: false
        )
        XCTAssertEqual(privateChild.publicKey, forSelf)
        XCTAssertEqual(forSelf, byCounterparty)

        // Pinned Go v1.3.3 (de26fdec57a945ddc06de5d5617f6c32374f3929)
        // oracle expectation for the BRC-42 inputs above.
        XCTAssertEqual(
            Hex.encode(try deriver.deriveSymmetricKey(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: .publicKey(bob.publicKey)
            ).bytes),
            "4ce8e868f2006e3fa8fc61ea4bc4be77d397b412b44b4dca047fb7ec3ca7cfd8"
        )
    }

    func testAnyoneSelfAndDomainSeparation() throws {
        let root = try walletTestPrivateKey(42)
        let deriver = WalletKeyDeriver(rootKey: root)
        XCTAssertEqual(try WalletKeyDeriver.anyone().identityKey, try walletTestPrivateKey(1).publicKey)
        let protocolID = try walletTestProtocol()
        let keyID = try walletTestKeyID()
        let selfKey = try deriver.derivePrivateKey(protocolID: protocolID, keyID: keyID, counterparty: .self)
        let anyoneKey = try deriver.derivePrivateKey(protocolID: protocolID, keyID: keyID, counterparty: .anyone)
        XCTAssertNotEqual(selfKey, anyoneKey)
        XCTAssertNotEqual(
            selfKey,
            try deriver.derivePrivateKey(
                protocolID: WalletProtocolID(securityLevel: .everyApp, name: protocolID.name),
                keyID: keyID,
                counterparty: .self
            )
        )
        XCTAssertNotEqual(
            selfKey,
            try deriver.derivePrivateKey(protocolID: protocolID, keyID: WalletKeyID("12346"), counterparty: .self)
        )
    }

    func testCanonicalUnicodeIDsAndConcurrentDerivation() async throws {
        let deriver = WalletKeyDeriver(rootKey: try walletTestPrivateKey(42))
        let protocolID = try walletTestProtocol()
        let composed = try deriver.derivePrivateKey(protocolID: protocolID, keyID: WalletKeyID("é"), counterparty: .self)
        let decomposed = try deriver.derivePrivateKey(protocolID: protocolID, keyID: WalletKeyID("e\u{301}"), counterparty: .self)
        XCTAssertNotEqual(composed, decomposed)

        let expected = try deriver.derivePublicKey(
            protocolID: protocolID,
            keyID: walletTestKeyID(),
            counterparty: .self,
            forSelf: false
        )
        try await withThrowingTaskGroup(of: PublicKey.self) { group in
            for _ in 0..<32 {
                group.addTask {
                    try deriver.derivePublicKey(
                        protocolID: protocolID,
                        keyID: walletTestKeyID(),
                        counterparty: .self,
                        forSelf: false
                    )
                }
            }
            for try await result in group { XCTAssertEqual(result, expected) }
        }
    }
}
