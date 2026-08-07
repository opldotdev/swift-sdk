/// A stable error reported while parsing a legacy key or address format.
public enum KeyFormatError: Error, Equatable, Sendable {
    /// Base58Check decoding failed with the preserved underlying cause.
    case invalidEncoding(Base58CheckError)
    /// The checksum-valid payload has an unsupported byte count.
    case invalidPayloadByteCount(Int)
    /// The checksum-valid payload has an unsupported network version.
    case unsupportedVersion(UInt8)
    /// A compressed WIF payload does not end in the required `0x01` marker.
    case invalidCompressionMarker(UInt8)
    /// The WIF payload contains an invalid secp256k1 private scalar.
    case invalidPrivateKey(Secp256k1KeyError)
}
