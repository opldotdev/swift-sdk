import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVStorage
import BSVWallet
import XCTest

/// A UHRP advertisement produced by `@bsv/sdk` 4.1.1 itself (ts-stack
/// `3b1abc569`) under bun, the way a TypeScript storage host writes it
/// (`infra/uhrp-server-cloud-bucket/src/utils/createUHRPAdvertisement.ts:63-89`),
/// and accepted by TypeScript `decodeAndVerifyUHRPAdvertisement`:
///
/// ```ts
/// const { PrivateKey, ProtoWallet, PushDrop, Utils, Hash, decodeAndVerifyUHRPAdvertisement } =
///   await import(`${process.env.TS_SDK}/mod.ts`)
/// const key = new PrivateKey(42)
/// const wallet = new ProtoWallet(key)
/// const identityKey = key.toPublicKey().toString()
/// const hash = Hash.sha256(Utils.toArray('hello uhrp', 'utf8'))
/// const url = 'https://cdn.example/files/hello'
/// const fields = [
///   Utils.toArray(identityKey, 'hex'), hash, Utils.toArray(url, 'utf8'),
///   new Utils.Writer().writeVarIntNum(1_900_000_000).toArray(),
///   new Utils.Writer().writeVarIntNum(10).toArray()
/// ]
/// const script = await new PushDrop(wallet).lock(fields, [2, 'uhrp advertisement'], '1', 'anyone', true)
/// await decodeAndVerifyUHRPAdvertisement(script)
/// console.log(script.toHex())
/// ```
final class UHRPAdvertisementTypeScriptVectorTests: XCTestCase {
    private static let scriptHex =
        "21021e5239b8c0615d92d659e584d3d3b585c493f5ab961c995edc3d6daba915656fac2102fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af20b6164577a44b48ddff81de1c05dce50fb14ae872170f6ae5cff2e75fb939083d1f68747470733a2f2f63646e2e6578616d706c652f66696c65732f68656c6c6f05fe00b33f715a4630440220307dbe7e669bec8796a18dd9ccebb0545f76185df3664b1b53b07018e7a7a25d0220536d333d793a3a0f6452ff9f4980724972c851cb6f08e5319f4a7115e59ee8426d6d6d"
    private static let hostKeyHex =
        "02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af"

    func testDecodesTypeScriptAdvertisement() async throws {
        let script = try Script(
            bytes: Hex.decode(Self.scriptHex, maximumDecodedByteCount: 1_000),
            maximumByteCount: 1_000
        )
        let advertisement = try UHRPAdvertisement.decode(script)
        let hostKey = try PrivateKey([UInt8](repeating: 0, count: 31) + [42])
        XCTAssertEqual(Hex.encode(hostKey.publicKey.compressedBytes), Self.hostKeyHex)
        XCTAssertEqual(advertisement.hostIdentityKey, hostKey.publicKey)
        XCTAssertEqual(advertisement.hash.bytes, BSVHashing.sha256(Array("hello uhrp".utf8)).bytes)
        XCTAssertEqual(advertisement.hostedFileLocation.absoluteString, "https://cdn.example/files/hello")
        XCTAssertEqual(advertisement.expiryTime, 1_900_000_000)
        XCTAssertEqual(advertisement.fileSize, 10)

        // Swift's wallet path derives the same locking key as TypeScript
        // `lock(fields, [2, 'uhrp advertisement'], '1', 'anyone', true)`.
        let walletKey = try await ProtoWallet(rootKey: hostKey).getPublicKey(.init(
            selection: .derived(
                protocolID: try WalletProtocolID(
                    securityLevel: .everyAppAndCounterparty, name: "uhrp advertisement"),
                keyID: try WalletKeyID("1"),
                counterparty: .anyone,
                forSelf: true
            )
        )).publicKey
        XCTAssertEqual(walletKey, advertisement.lockingPublicKey)
        XCTAssertEqual(try UHRPAdvertisement.linkedLockingKey(for: hostKey.publicKey), walletKey)
    }
}
