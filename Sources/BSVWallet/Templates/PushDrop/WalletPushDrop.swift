import BSVKeys
import BSVScript
import BSVTransaction

/// Wallet-backed PushDrop failures.
public enum WalletPushDropError: Error, Equatable, Sendable {
    /// The wallet signature does not match the public key in the source lock.
    case signatureDoesNotMatchLockingPublicKey(inputIndex: Int)
}

public extension PushDrop {
    /// Creates an unsigned PushDrop lock with a BRC-42 wallet key.
    ///
    /// Lock-after is the BRC-48 layout. Use `.beforeCompatibility` only for
    /// scripts that require the pinned Go SDK layout.
    static func lockingScript(
        fields: [[UInt8]],
        using wallet: any WalletPublicKeyProviding,
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty,
        forSelf: Bool = false,
        lockPosition: PushDropLockPosition = .after,
        access: WalletKeyAccess = .standard,
        limits: PushDropLimits = .standard
    ) async throws -> Script {
        try await walletLockingScript(
            fields: fields,
            publicKeyWallet: wallet,
            signatureWallet: nil,
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            forSelf: forSelf,
            lockPosition: lockPosition,
            access: access,
            limits: limits
        )
    }

    /// Creates a PushDrop lock and can append a wallet signature field.
    ///
    /// If `includeSignature` is true, the wallet signs the exact concatenation
    /// of the original fields. Pass this argument explicitly when the wallet
    /// signature capability is available.
    static func lockingScript(
        fields: [[UInt8]],
        using wallet: any WalletPublicKeyProviding & WalletSignatureOperations,
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty,
        forSelf: Bool = false,
        includeSignature: Bool,
        lockPosition: PushDropLockPosition = .after,
        access: WalletKeyAccess = .standard,
        limits: PushDropLimits = .standard
    ) async throws -> Script {
        try await walletLockingScript(
            fields: fields,
            publicKeyWallet: wallet,
            signatureWallet: includeSignature ? wallet : nil,
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            forSelf: forSelf,
            lockPosition: lockPosition,
            access: access,
            limits: limits
        )
    }

    private static func walletLockingScript(
        fields: [[UInt8]],
        publicKeyWallet: any WalletPublicKeyProviding,
        signatureWallet: (any WalletSignatureOperations)?,
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty,
        forSelf: Bool,
        lockPosition: PushDropLockPosition,
        access: WalletKeyAccess,
        limits: PushDropLimits
    ) async throws -> Script {
        let includeSignature = signatureWallet != nil
        if includeSignature {
            // A strict DER signature is at least eight bytes. This detects all
            // guaranteed count, field, and script-limit failures before the
            // wallet is called. The exact signature size is known afterward.
            try preflight(
                fields: fields + [[UInt8](repeating: 0x30, count: 8)],
                limits: limits
            )
        } else {
            try preflight(fields: fields, limits: limits)
        }

        try Task.checkCancellation()
        let publicKey = try await publicKeyWallet.getPublicKey(.init(
            selection: .derived(
                protocolID: protocolID,
                keyID: keyID,
                counterparty: counterparty,
                forSelf: forSelf
            ),
            access: access
        )).publicKey
        try Task.checkCancellation()

        guard let signatureWallet else {
            let script = try lockingScript(
                fields: fields,
                publicKey: publicKey,
                lockPosition: lockPosition,
                limits: limits
            )
            try Task.checkCancellation()
            return script
        }

        var data: [UInt8] = []
        for field in fields {
            data.append(contentsOf: field)
        }
        try Task.checkCancellation()
        let signature = try await signatureWallet.createSignature(.init(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            payload: .data(data),
            access: access
        )).signature
        try Task.checkCancellation()

        let script = try lockingScript(
            fields: fields + [signature.derBytes],
            publicKey: publicKey,
            lockPosition: lockPosition,
            limits: limits
        )
        try Task.checkCancellation()
        return script
    }
}

public extension Transaction {
    /// Signs one PushDrop input with a BRC-42 wallet key.
    ///
    /// The wallet receives the existing ForkID digest directly. The input is
    /// changed only after the signature matches the public key in the source
    /// locking script and the candidate transaction passes all limits.
    mutating func signPushDropInput(
        at inputIndex: Int,
        using wallet: any WalletSignatureOperations,
        protocolID: WalletProtocolID,
        keyID: WalletKeyID,
        counterparty: WalletCounterparty,
        lockPosition: PushDropLockPosition = .after,
        hashType: ForkIDSignatureHashType = .all,
        access: WalletKeyAccess = .standard,
        limits: TransactionLimits
    ) async throws {
        guard inputs.indices.contains(inputIndex) else {
            throw TransactionError.invalidInputIndex(inputIndex)
        }
        guard let sourceOutput = inputs[inputIndex].sourceOutput else {
            throw TransactionError.missingSourceOutput(inputIndex: inputIndex)
        }

        let maximumScriptByteCount = Int(min(
            limits.maximumScriptByteCount,
            UInt64(Int.max)
        ))
        let decodingLimits = try PushDropLimits(
            maximumFieldCount: PushDropLimits.standard.maximumFieldCount,
            maximumFieldByteCount: maximumScriptByteCount,
            maximumScriptByteCount: maximumScriptByteCount
        )
        let decoded = try PushDrop.decode(
            sourceOutput.lockingScript,
            lockPosition: lockPosition,
            limits: decodingLimits
        )
        let digest = try forkIDSignatureHash(
            inputIndex: inputIndex,
            hashType: hashType,
            scriptCode: sourceOutput.lockingScript,
            limits: limits
        )

        // A strict DER signature plus its hash type needs at least a ten-byte
        // script. Validate guaranteed local failures before the wallet call.
        var minimumUnlockingScript = try Script(
            bytes: [],
            maximumByteCount: maximumScriptByteCount
        )
        try minimumUnlockingScript.appendMinimalPush(
            [UInt8](repeating: 0x30, count: 8) + [hashType.rawValue],
            maximumScriptByteCount: maximumScriptByteCount
        )
        var minimumCandidate = self
        minimumCandidate.inputs[inputIndex].unlockingScript = minimumUnlockingScript
        _ = try minimumCandidate.serializedByteCount(limits: limits)

        try Task.checkCancellation()
        let signature = try await wallet.createSignature(.init(
            protocolID: protocolID,
            keyID: keyID,
            counterparty: counterparty,
            payload: .digest(digest),
            access: access
        )).signature
        try Task.checkCancellation()
        guard decoded.publicKey.verify(signature, digest: digest) else {
            throw WalletPushDropError.signatureDoesNotMatchLockingPublicKey(
                inputIndex: inputIndex
            )
        }

        var unlockingScript = try Script(bytes: [], maximumByteCount: maximumScriptByteCount)
        try unlockingScript.appendMinimalPush(
            signature.derBytes + [hashType.rawValue],
            maximumScriptByteCount: maximumScriptByteCount
        )
        var candidate = self
        candidate.inputs[inputIndex].unlockingScript = unlockingScript
        _ = try candidate.serializedByteCount(limits: limits)
        try Task.checkCancellation()
        self = candidate
    }
}
