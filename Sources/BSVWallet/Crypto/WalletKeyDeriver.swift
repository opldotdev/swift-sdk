import BSVCrypto
import BSVKeys

/// Stateless BRC-42 wallet key derivation. Swift values and arrays cannot
/// guarantee zeroization; callers should minimize the lifetime of root and
/// derived key copies.
public struct WalletKeyDeriver:
    Sendable,
    CustomStringConvertible,
    CustomDebugStringConvertible,
    CustomReflectable {
    private let rootKey: PrivateKey

    public init(rootKey: PrivateKey) {
        self.rootKey = rootKey
    }

    public static func anyone() throws -> WalletKeyDeriver {
        var scalar = [UInt8](repeating: 0, count: 32)
        guard let last = scalar.indices.last else {
            throw WalletCryptoError.keyDerivationFailed
        }
        scalar[last] = 1
        do {
            return WalletKeyDeriver(rootKey: try PrivateKey(scalar))
        } catch {
            throw WalletCryptoError.keyDerivationFailed
        }
    }

    public var identityKey: PublicKey { rootKey.publicKey }

    public func derivePrivateKey(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty
    ) throws -> PrivateKey {
        do {
            return try rootKey.derivedChild(
                with: try normalizedCounterparty(counterparty),
                invoiceNumber: invoice(protocolID: protocolID, keyID: keyID)
            )
        } catch {
            throw WalletCryptoError.keyDerivationFailed
        }
    }

    public func derivePublicKey(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty,
        forSelf: Bool
    ) throws -> PublicKey {
        let counterpartyKey: PublicKey
        do {
            counterpartyKey = try normalizedCounterparty(counterparty)
            if forSelf {
                return try rootKey.derivedChild(
                    with: counterpartyKey,
                    invoiceNumber: invoice(protocolID: protocolID, keyID: keyID)
                ).publicKey
            }
            return try counterpartyKey.derivedChild(
                with: rootKey,
                invoiceNumber: invoice(protocolID: protocolID, keyID: keyID)
            )
        } catch {
            throw WalletCryptoError.keyDerivationFailed
        }
    }

    public func deriveSymmetricKey(
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty
    ) throws -> SymmetricKey {
        do {
            let privateKey = try derivePrivateKey(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: counterparty
            )
            let publicKey = try derivePublicKey(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: counterparty,
                forSelf: false
            )
            let point = try privateKey.sharedSecret(with: publicKey).compressedBytes
            guard point.count == 33 else {
                throw WalletCryptoError.keyDerivationFailed
            }
            return try SymmetricKey(Array(point.dropFirst()))
        } catch {
            throw WalletCryptoError.keyDerivationFailed
        }
    }

    internal func invoice(protocolID: WalletProtocolID, keyID: WalletKeyID) -> String {
        "\(protocolID.securityLevel.rawValue)-\(protocolID.name)-\(keyID.value)"
    }

    private func normalizedCounterparty(_ counterparty: WalletCounterparty) throws -> PublicKey {
        switch counterparty {
        case .self:
            return identityKey
        case .anyone:
            return try Self.anyone().identityKey
        case .publicKey(let key):
            return key
        }
    }

    public var description: String { "<redacted wallet key deriver>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { walletEmptyMirror(self) }
}
