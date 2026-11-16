import BSVWallet
import Foundation
import Testing

/// What a wallet shows when the wallet wire refuses a result.
@Suite("Wallet wire refusal descriptions")
struct WalletWireFailureDescriptionTests {
    @Test("refusals read as plain sentences and keep the wire text for logs")
    func refusalSentences() {
        let abort = WalletWireResultRejection(
            code: 8,
            message: "The wallet refused to abort this action because it has already been broadcast"
        )
        #expect(abort.localizedDescription
            == "The wallet could not cancel this action because it was already broadcast.")

        let page = WalletWireResultRejection(
            message: "Invalid listActions result: returned 3 records but declared a total of 2"
        )
        #expect(page.localizedDescription == "The wallet's answer was not in a form the other side can read.")
        #expect(String(describing: page).contains("returned 3 records but declared a total of 2"))

        let relinquish = WalletWireResultRejection(message: "The wallet did not relinquish the output")
        #expect(relinquish.localizedDescription == "The wallet did not relinquish the output.")
    }
}
