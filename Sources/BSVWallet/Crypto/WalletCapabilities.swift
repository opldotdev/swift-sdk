public protocol WalletPublicKeyProviding: Sendable {
    func getPublicKey(
        _ request: WalletGetPublicKeyRequest
    ) async throws -> WalletGetPublicKeyResult
}

public protocol WalletCipherOperations: Sendable {
    func encrypt(
        _ request: WalletEncryptRequest
    ) async throws -> WalletEncryptResult

    func decrypt(
        _ request: WalletDecryptRequest
    ) async throws -> WalletDecryptResult
}

public protocol WalletHMACOperations: Sendable {
    func createHMAC(
        _ request: WalletCreateHMACRequest
    ) async throws -> WalletCreateHMACResult

    func verifyHMAC(
        _ request: WalletVerifyHMACRequest
    ) async throws -> WalletVerifyHMACResult
}

public protocol WalletSignatureOperations: Sendable {
    func createSignature(
        _ request: WalletCreateSignatureRequest
    ) async throws -> WalletCreateSignatureResult

    func verifySignature(
        _ request: WalletVerifySignatureRequest
    ) async throws -> WalletVerifySignatureResult
}

public protocol WalletKeyOperations:
    WalletPublicKeyProviding,
    WalletCipherOperations,
    WalletHMACOperations,
    WalletSignatureOperations {}
