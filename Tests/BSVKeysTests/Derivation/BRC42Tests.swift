import BSVCore
@testable import BSVKeys
import Testing

@Suite("BRC-42 key derivation")
struct BRC42Tests {
    @Test("sender public derivation matches recipient private derivation")
    func bilateralConsistency() throws {
        let sender = try PrivateKey(scalar(7))
        let recipient = try PrivateKey(scalar(19))
        let invoices = [
            "",
            "invoice-1",
            "2-authentication-key",
            "caf\u{00E9}",
            "cafe\u{0301}",
            "embedded\0nul",
            "\u{1F512}/\u{65E5}\u{672C}\u{8A9E}",
        ]

        var observed = Set<PublicKey>()
        for invoice in invoices {
            let privateChild = try recipient.derivedChild(
                with: sender.publicKey,
                invoiceNumber: invoice
            )
            let publicChild = try recipient.publicKey.derivedChild(
                with: sender,
                invoiceNumber: invoice
            )
            #expect(privateChild.publicKey == publicChild)
            observed.insert(publicChild)
        }
        #expect(observed.count == invoices.count)
    }

    @Test("roles are explicit and derivation is deterministic")
    func rolesAndDeterminism() throws {
        let sender = try PrivateKey(scalar(3))
        let recipient = try PrivateKey(scalar(5))

        let first = try recipient.derivedChild(
            with: sender.publicKey,
            invoiceNumber: "example"
        )
        let second = try recipient.derivedChild(
            with: sender.publicKey,
            invoiceNumber: "example"
        )
        let reversedRoles = try sender.derivedChild(
            with: recipient.publicKey,
            invoiceNumber: "example"
        )

        #expect(first == second)
        #expect(first != reversedRoles)
    }

    @Test("scalar reduction handles order boundary")
    func scalarReduction() throws {
        let order = try Hex.decode(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            maximumDecodedByteCount: 32
        )
        var orderPlusFive = order
        orderPlusFive[31] &+= 5

        #expect(reducedScalarModuloOrder([UInt8](repeating: 0xff, count: 32)).count == 32)
        #expect(reducedScalarModuloOrder(order) == [UInt8](repeating: 0, count: 32))
        #expect(reducedScalarModuloOrder(orderPlusFive) == scalar(5))
        #expect(reducedScalarModuloOrder(scalar(9)) == scalar(9))
    }

    private func scalar(_ value: UInt8) -> [UInt8] {
        [UInt8](repeating: 0, count: 31) + [value]
    }
}
