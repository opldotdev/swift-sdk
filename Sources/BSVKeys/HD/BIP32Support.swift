import BSVCore
import BSVCrypto

enum BIP32Version {
    static let mainPrivate: UInt32 = 0x0488_ade4
    static let mainPublic: UInt32 = 0x0488_b21e
    static let testPrivate: UInt32 = 0x0435_8394
    static let testPublic: UInt32 = 0x0435_87cf

    static func value(network: BitcoinNetwork, kind: ExtendedKeyKind) -> UInt32 {
        switch (network, kind) {
        case (.mainnet, .privateKey): mainPrivate
        case (.mainnet, .publicKey): mainPublic
        case (.testnet, .privateKey): testPrivate
        case (.testnet, .publicKey): testPublic
        }
    }

    static func decode(_ value: UInt32) throws -> (BitcoinNetwork, ExtendedKeyKind) {
        switch value {
        case mainPrivate: (.mainnet, .privateKey)
        case mainPublic: (.mainnet, .publicKey)
        case testPrivate: (.testnet, .privateKey)
        case testPublic: (.testnet, .publicKey)
        default: throw ExtendedKeyError.unknownVersion(value)
        }
    }
}

struct BIP32Payload {
    let network: BitcoinNetwork
    let kind: ExtendedKeyKind
    let depth: UInt8
    let parentFingerprint: UInt32
    let childNumber: UInt32
    let chainCode: Hash256
    let keyData: [UInt8]

    init(serialized text: String) throws {
        // Standard xprv/xpub/tprv/tpub values are exactly 111 ASCII bytes. Inspect
        // at most one byte beyond that boundary before Base58 decoding so hostile
        // text cannot force an unbounded validation pass.
        guard text.utf8.prefix(112).count == 111 else {
            throw ExtendedKeyError.invalidSerializedTextLength
        }

        let payload: [UInt8]
        do {
            payload = try Base58Check.decode(text, maximumPayloadByteCount: 78)
        } catch let error as Base58CheckError {
            throw ExtendedKeyError.invalidEncoding(error)
        }
        guard payload.count == 78 else {
            throw ExtendedKeyError.invalidPayloadByteCount(payload.count)
        }

        (network, kind) = try BIP32Version.decode(readUInt32(payload, at: 0))
        depth = payload[4]
        parentFingerprint = readUInt32(payload, at: 5)
        childNumber = readUInt32(payload, at: 9)
        if depth == 0, parentFingerprint != 0 || childNumber != 0 {
            throw ExtendedKeyError.inconsistentRootMetadata
        }
        chainCode = try Hash256(Array(payload[13..<45]))
        keyData = Array(payload[45..<78])
    }
}

func serializeBIP32(
    network: BitcoinNetwork,
    kind: ExtendedKeyKind,
    depth: UInt8,
    parentFingerprint: UInt32,
    childNumber: UInt32,
    chainCode: Hash256,
    keyData: [UInt8]
) -> String {
    var payload: [UInt8] = []
    payload.reserveCapacity(78)
    payload.append(contentsOf: bytes(of: BIP32Version.value(network: network, kind: kind)))
    payload.append(depth)
    payload.append(contentsOf: bytes(of: parentFingerprint))
    payload.append(contentsOf: bytes(of: childNumber))
    payload.append(contentsOf: chainCode.bytes)
    payload.append(contentsOf: keyData)
    return Base58Check.encode(payload)
}

func keyFingerprint(_ publicKey: PublicKey) -> UInt32 {
    readUInt32(BSVHashing.hash160(publicKey.compressedBytes).bytes, at: 0)
}

func bytes(of value: UInt32) -> [UInt8] {
    [
        UInt8(truncatingIfNeeded: value >> 24),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value),
    ]
}

func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24
        | UInt32(bytes[offset + 1]) << 16
        | UInt32(bytes[offset + 2]) << 8
        | UInt32(bytes[offset + 3])
}

func sameNetwork(_ lhs: BitcoinNetwork, _ rhs: BitcoinNetwork) -> Bool {
    BIP32Version.value(network: lhs, kind: .privateKey)
        == BIP32Version.value(network: rhs, kind: .privateKey)
}

func hashNetwork(_ network: BitcoinNetwork, into hasher: inout Hasher) {
    hasher.combine(BIP32Version.value(network: network, kind: .privateKey))
}
