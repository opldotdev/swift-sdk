/// The narrow wallet surface required to sign and verify BRC-52 certificates.
public protocol CertificateSignatureWallet:
    WalletPublicKeyProviding, WalletSignatureOperations {}

/// The narrow wallet surface required for BRC-52 field/keyring encryption.
public protocol CertificateCipherWallet:
    WalletPublicKeyProviding, WalletCipherOperations {}

/// The complete narrow offline BRC-52 wallet surface.
public protocol CertificateWallet:
    CertificateSignatureWallet, CertificateCipherWallet {}

extension ProtoWallet: CertificateWallet {}
