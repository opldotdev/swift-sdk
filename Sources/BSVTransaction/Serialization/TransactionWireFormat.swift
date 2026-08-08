/// The transaction packet representation to parse or serialize.
///
/// No format detection is performed. Callers must explicitly select
/// ``extended`` when handling a BRC-30/BIP-239 Extended Format packet.
public enum TransactionWireFormat: Hashable, Sendable {
    /// The canonical Bitcoin transaction wire format used for transaction IDs.
    case raw

    /// BRC-30/BIP-239 Extended Format with asserted spent-output metadata.
    case extended
}
