import XCTest
@testable import BSVWallet

private func requireSendable<T: Sendable>(_: T.Type) {}

final class WalletSendableTests: XCTestCase {
    func testPublicTypesAreSendable() {
        requireSendable(WalletSecurityLevel.self)
        requireSendable(WalletProtocolID.self)
        requireSendable(WalletKeyID.self)
        requireSendable(WalletCounterparty.self)
        requireSendable(WalletKeyAccess.self)
        requireSendable(WalletCryptoLimits.self)
        requireSendable(WalletSignaturePayload.self)
        requireSendable(WalletPublicKeySelection.self)
        requireSendable(WalletGetPublicKeyRequest.self)
        requireSendable(WalletGetPublicKeyResult.self)
        requireSendable(WalletEncryptRequest.self)
        requireSendable(WalletEncryptResult.self)
        requireSendable(WalletDecryptRequest.self)
        requireSendable(WalletDecryptResult.self)
        requireSendable(WalletCreateHMACRequest.self)
        requireSendable(WalletCreateHMACResult.self)
        requireSendable(WalletVerifyHMACRequest.self)
        requireSendable(WalletVerifyHMACResult.self)
        requireSendable(WalletCreateSignatureRequest.self)
        requireSendable(WalletCreateSignatureResult.self)
        requireSendable(WalletVerifySignatureRequest.self)
        requireSendable(WalletVerifySignatureResult.self)
        requireSendable(WalletHMAC.self)
        requireSendable(WalletKeyDeriver.self)
        requireSendable(ProtoWallet.self)
        requireSendable((any WalletPublicKeyProviding).self)
        requireSendable((any WalletCipherOperations).self)
        requireSendable((any WalletHMACOperations).self)
        requireSendable((any WalletSignatureOperations).self)
        requireSendable((any WalletKeyOperations).self)
    }
}
