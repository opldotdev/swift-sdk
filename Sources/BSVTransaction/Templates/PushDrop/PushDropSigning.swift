import BSVKeys
import BSVScript

public extension Transaction {
    /// Signs one PushDrop input with a canonical ForkID transaction signature.
    ///
    /// Lock-after is the BRC-48 default. Reading or signing the pinned Go SDK's
    /// lock-before layout requires explicitly passing `.beforeCompatibility`.
    /// Mutation is atomic: `self` changes only after the completed candidate
    /// transaction satisfies all caller-selected transaction limits.
    mutating func signPushDropInput(
        at inputIndex: Int,
        with privateKey: PrivateKey,
        hashType: ForkIDSignatureHashType = .all,
        limits: TransactionLimits
    ) throws {
        try signPushDropInput(
            at: inputIndex,
            with: privateKey,
            lockPosition: .after,
            hashType: hashType,
            limits: limits
        )
    }

    /// Signs a PushDrop input using an explicitly selected wire layout.
    ///
    /// Pass `.beforeCompatibility` only for the pinned Go SDK's non-BRC-48
    /// layout. Ordinary BRC-48 callers should use the lock-after overload.
    mutating func signPushDropInput(
        at inputIndex: Int,
        with privateKey: PrivateKey,
        lockPosition: PushDropLockPosition,
        hashType: ForkIDSignatureHashType = .all,
        limits: TransactionLimits
    ) throws {
        guard inputs.indices.contains(inputIndex) else {
            throw TransactionError.invalidInputIndex(inputIndex)
        }
        guard let sourceOutput = inputs[inputIndex].sourceOutput else {
            throw TransactionError.missingSourceOutput(inputIndex: inputIndex)
        }

        let maximumScriptByteCount = Int(limits.maximumScriptByteCount)
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
        guard decoded.publicKey == privateKey.publicKey else {
            throw PushDropError.privateKeyDoesNotMatchPublicKey(inputIndex: inputIndex)
        }

        let digest = try forkIDSignatureHash(
            inputIndex: inputIndex,
            hashType: hashType,
            scriptCode: sourceOutput.lockingScript,
            limits: limits
        )
        let signature = try privateKey.sign(digest: digest)
        var unlockingScript = try Script(bytes: [], maximumByteCount: maximumScriptByteCount)
        try unlockingScript.appendMinimalPush(
            signature.derBytes + [hashType.rawValue],
            maximumScriptByteCount: maximumScriptByteCount
        )

        var candidate = self
        candidate.inputs[inputIndex].unlockingScript = unlockingScript
        _ = try candidate.serializedByteCount(limits: limits)
        self = candidate
    }
}
