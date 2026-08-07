/// Stable errors produced by secp256k1 key-agreement and key-tweak operations.
public enum Secp256k1OperationError: Error, Equatable, Sendable {
    /// A tweak was not exactly one 32-byte big-endian scalar.
    case invalidTweakByteCount(Int)

    /// A tweak was outside the operation's scalar domain or produced an invalid result.
    /// Additive tweaks permit zero; multiplicative tweaks require a nonzero value.
    case invalidTweak

    /// A validated SDK key could not be converted or used for key agreement.
    case keyAgreementFailed
}
