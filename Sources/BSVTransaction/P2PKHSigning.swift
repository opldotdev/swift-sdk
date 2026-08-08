import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript

public extension Transaction {
    /// Signs one exact P2PKH input and installs its canonical unlocking script.
    ///
    /// Mutation is transactional: the input is changed only after source-script
    /// validation, digest creation, signing, and bounded Script construction all
    /// succeed. The source P2PKH hash must match the chosen public-key format.
    mutating func signPayToPublicKeyHashInput(
        at inputIndex: Int,
        with privateKey: PrivateKey,
        publicKeyFormat: PublicKeyFormat = .compressed,
        hashType: ForkIDSignatureHashType = .all,
        limits: TransactionLimits
    ) throws {
        guard inputs.indices.contains(inputIndex) else {
            throw TransactionError.invalidInputIndex(inputIndex)
        }
        guard let sourceOutput = inputs[inputIndex].sourceOutput else {
            throw TransactionError.missingSourceOutput(inputIndex: inputIndex)
        }
        guard let publicKeyHash = sourceOutput.lockingScript.publicKeyHash,
              let expectedHash = try? Hash160(publicKeyHash) else {
            throw TransactionError.sourceOutputIsNotPayToPublicKeyHash(inputIndex: inputIndex)
        }

        let publicKeyBytes = privateKey.publicKey.serialized(as: publicKeyFormat)
        guard BSVHashing.hash160(publicKeyBytes) == expectedHash else {
            throw TransactionError.privateKeyDoesNotMatchSourceOutput(inputIndex: inputIndex)
        }

        let digest = try forkIDSignatureHash(
            inputIndex: inputIndex,
            hashType: hashType,
            limits: limits
        )
        let signature = try privateKey.sign(digest: digest)
        let scriptMaximum = Int(limits.maximumScriptByteCount)
        var unlockingScript = try Script(bytes: [], maximumByteCount: scriptMaximum)
        try unlockingScript.appendPushData(
            signature.derBytes + [hashType.rawValue],
            maximumScriptByteCount: scriptMaximum
        )
        try unlockingScript.appendPushData(
            publicKeyBytes,
            maximumScriptByteCount: scriptMaximum
        )
        var candidate = self
        candidate.inputs[inputIndex].unlockingScript = unlockingScript
        _ = try candidate.serializedByteCount(limits: limits)
        self = candidate
    }
}
