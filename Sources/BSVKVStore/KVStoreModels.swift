import BSVCrypto
import BSVKeys
import BSVScript
import BSVWallet

/// Resource bounds for the transport-neutral key-value token codec.
public struct KVStoreLimits: Hashable, Sendable {
    /// Bounds for a wallet-tagged locator and a 2 MiB value, the largest
    /// value field TypeScript `LocalKVStore` reads (`MAX_LOCAL_TOKEN_BYTES`).
    public static let standard = KVStoreLimits(
        validatedMaximumLocatorUTF8ByteCount: 2_000,
        validatedMaximumValueByteCount: 2_097_152,
        validatedMaximumScriptByteCount: 2_097_266
    )

    /// The largest strict DER secp256k1 signature, in bytes.
    static let maximumSignatureByteCount = 72

    public let maximumLocatorUTF8ByteCount: Int
    public let maximumValueByteCount: Int
    public let maximumScriptByteCount: Int

    /// Creates limits which can encode every value permitted by
    /// `maximumValueByteCount`.
    public init(
        maximumLocatorUTF8ByteCount: Int = 2_000,
        maximumValueByteCount: Int = 2_097_152,
        maximumScriptByteCount: Int = 2_097_266
    ) throws {
        guard maximumLocatorUTF8ByteCount > 0,
              maximumValueByteCount > 0,
              maximumValueByteCount <= Int(UInt32.max),
              maximumScriptByteCount > 0 else {
            throw KVStoreError.invalidLimits
        }

        let requiredScriptByteCount = try Self.maximumTokenScriptByteCount(
            forValueByteCount: maximumValueByteCount
        )
        guard maximumScriptByteCount >= requiredScriptByteCount else {
            throw KVStoreError.invalidLimits
        }

        self.init(
            validatedMaximumLocatorUTF8ByteCount: maximumLocatorUTF8ByteCount,
            validatedMaximumValueByteCount: maximumValueByteCount,
            validatedMaximumScriptByteCount: maximumScriptByteCount
        )
    }

    private init(
        validatedMaximumLocatorUTF8ByteCount: Int,
        validatedMaximumValueByteCount: Int,
        validatedMaximumScriptByteCount: Int
    ) {
        maximumLocatorUTF8ByteCount = validatedMaximumLocatorUTF8ByteCount
        maximumValueByteCount = validatedMaximumValueByteCount
        maximumScriptByteCount = validatedMaximumScriptByteCount
    }

    /// The largest token script for a value: lock (35), value push,
    /// signature push (at most 73), and one `OP_2DROP`.
    static func maximumTokenScriptByteCount(forValueByteCount byteCount: Int) throws -> Int {
        guard byteCount > 0, byteCount <= Int(UInt32.max) else {
            throw KVStoreError.invalidLimits
        }

        let prefixByteCount: Int
        switch byteCount {
        case 1...75:
            prefixByteCount = 1
        case 76...0xFF:
            prefixByteCount = 2
        case 0x100...0xFFFF:
            prefixByteCount = 3
        default:
            prefixByteCount = 5
        }

        let (encodedFieldByteCount, encodedFieldOverflow) = byteCount.addingReportingOverflow(
            prefixByteCount
        )
        guard !encodedFieldOverflow else {
            throw KVStoreError.sizeOverflow
        }
        let (withSignature, signatureOverflow) = encodedFieldByteCount.addingReportingOverflow(
            1 + maximumSignatureByteCount
        )
        guard !signatureOverflow else {
            throw KVStoreError.sizeOverflow
        }
        let (withDrop, dropOverflow) = withSignature.addingReportingOverflow(1)
        guard !dropOverflow else {
            throw KVStoreError.sizeOverflow
        }
        let (withLock, lockOverflow) = withDrop.addingReportingOverflow(35)
        guard !lockOverflow else {
            throw KVStoreError.sizeOverflow
        }
        return withLock
    }
}

/// A wallet-side basket and tag used to locate a key-value token.
///
/// A locator is not committed into the PushDrop locking script. A future wallet
/// adapter must preserve the basket/tag association independently.
public struct KVStoreLocator: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let context: String
    public let key: String

    public init(
        context: String,
        key: String,
        limits: KVStoreLimits = .standard
    ) throws {
        guard !context.isEmpty else {
            throw KVStoreError.emptyContext
        }
        guard !key.isEmpty else {
            throw KVStoreError.emptyKey
        }
        try Self.validateLocatorComponent(
            context,
            kind: "context",
            limits: limits
        )
        try Self.validateLocatorComponent(
            key,
            kind: "key",
            limits: limits
        )
        self.context = context
        self.key = key
    }

    /// The wallet protocol that locks and signs this locator's token:
    /// `[2, context]`, as TypeScript `LocalKVStore.getProtocol` uses.
    ///
    /// Throws `KVStoreError.invalidWalletLocator` when the context is not a
    /// valid wallet protocol name (for example shorter than 5 characters).
    public func walletProtocolID() throws -> WalletProtocolID {
        do {
            return try WalletProtocolID(securityLevel: .everyAppAndCounterparty, name: context)
        } catch let error as WalletValidationError {
            throw KVStoreError.invalidWalletLocator(error)
        }
    }

    /// The wallet key ID for this locator's token: the key itself.
    ///
    /// Throws `KVStoreError.invalidWalletLocator` when the key is not a valid
    /// wallet key ID.
    public func walletKeyID() throws -> WalletKeyID {
        do {
            return try WalletKeyID(key)
        } catch let error as WalletValidationError {
            throw KVStoreError.invalidWalletLocator(error)
        }
    }

    public var description: String { "<redacted key-value locator>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }

    private static func validateLocatorComponent(
        _ value: String,
        kind: String,
        limits: KVStoreLimits
    ) throws {
        let byteCount = value.utf8.count
        guard byteCount <= limits.maximumLocatorUTF8ByteCount else {
            throw KVStoreError.locatorByteCountExceedsLimit(
                kind: kind,
                actual: byteCount,
                maximum: limits.maximumLocatorUTF8ByteCount
            )
        }
    }
}

/// The value, public-key lock, and owner signature of one key-value token.
///
/// This is the `LocalKVStore` token of `@bsv/sdk` 4.1.1: two PushDrop
/// fields, the value and a signature over the value by the locking key
/// (`kvstore/LocalKVStore.ts`). A token value always carries a signature that
/// verifies under its locking key.
public struct KVStoreToken: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    public let value: [UInt8]
    public let lockingPublicKey: PublicKey
    public let signature: ECDSASignature

    public init(
        value: [UInt8],
        lockingPublicKey: PublicKey,
        signature: ECDSASignature,
        limits: KVStoreLimits = .standard
    ) throws {
        guard !value.isEmpty else {
            throw KVStoreError.emptyValue
        }
        guard value.count <= limits.maximumValueByteCount else {
            throw KVStoreError.valueByteCountExceedsLimit(
                actual: value.count,
                maximum: limits.maximumValueByteCount
            )
        }
        // TypeScript verification has no low-S rule, so a high-S signature
        // from another wallet is accepted here too.
        guard signature.verifiesInScript(
            publicKey: lockingPublicKey,
            digest: BSVHashing.sha256(value)
        ) else {
            throw KVStoreError.invalidSignature
        }
        self.value = value
        self.lockingPublicKey = lockingPublicKey
        self.signature = signature
    }

    public var description: String { "<redacted key-value token>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<(label: String?, value: Any)>())
    }
}

/// Validation and structural failures for key-value token values.
public enum KVStoreError: Error, Equatable, Sendable {
    case invalidLimits
    case sizeOverflow
    case emptyContext
    case emptyKey
    case emptyValue
    case locatorByteCountExceedsLimit(kind: String, actual: Int, maximum: Int)
    case valueByteCountExceedsLimit(actual: Int, maximum: Int)
    case invalidTokenFieldCount(actual: Int)
    case invalidLockingScript(PushDropError)
    case invalidSignatureEncoding
    case invalidSignature
    case lockingKeyMismatch
    /// The locator's context or key is not valid in the wallet's protocol
    /// or key ID grammar.
    case invalidWalletLocator(WalletValidationError)
}
