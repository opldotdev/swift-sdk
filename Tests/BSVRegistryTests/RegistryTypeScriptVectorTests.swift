import BSVCore
import BSVKeys
import BSVRegistry
import BSVScript
import BSVWallet
import XCTest

/// Registry tokens produced by `@bsv/sdk` 4.1.1 itself (ts-stack `3b1abc569`)
/// under bun, the way `RegistryClient.registerDefinition` writes them
/// (`registry/RegistryClient.ts:314-320, 688-722`), and accepted by TypeScript
/// `decodeAndVerifyRegistryToken`:
///
/// ```ts
/// const { PrivateKey, ProtoWallet, PushDrop, Utils, decodeAndVerifyRegistryToken } =
///   await import(`${process.env.TS_SDK}/mod.ts`)
/// const key = new PrivateKey(42)
/// const pushdrop = new PushDrop(new ProtoWallet(key))
/// const identityKey = key.toPublicKey().toString()
/// async function registry (type, protocolID, text) {
///   const fields = [...text, identityKey].map(f => Utils.toArray(f, 'utf8'))
///   const script = await pushdrop.lock(fields, protocolID, '1', 'anyone', true)
///   await decodeAndVerifyRegistryToken(type, script)
///   return script.toHex()
/// }
/// const meta = ['Todo Tokens', 'https://icon.example/todo.png', 'Todo list items', 'https://docs.example/todo']
/// await registry('basket', [1, 'basketmap'], ['todo tokens', ...meta])
/// await registry('protocol', [1, 'protomap'], [JSON.stringify([1, 'todo list']), ...meta])
/// // Field names and descriptor keys deliberately out of byte order.
/// const certificateFields = JSON.stringify({
///   zeta: { type: 'text', fieldIcon: 'https://icon.example/z.png', friendlyName: 'Zeta', description: 'Last field' },
///   alpha: { description: 'First field', friendlyName: 'Alpha', fieldIcon: 'https://icon.example/a.png', type: 'imageURL' }
/// })
/// await registry('certificate', [1, 'certmap'], ['todo certificate', ...meta, certificateFields])
/// ```
final class RegistryTypeScriptVectorTests: XCTestCase {
    private static let basketHex =
        "2102b65e93f5470461efa4ea35c52fe0b68136c9bbeecde3dc5662a50817c6761b6bac0b746f646f20746f6b656e730b546f646f20546f6b656e731d68747470733a2f2f69636f6e2e6578616d706c652f746f646f2e706e670f546f646f206c697374206974656d731968747470733a2f2f646f63732e6578616d706c652f746f646f423032666538643165623162636233343332623164623538333366663566323232366439636235653635636565343330353538633138656433613363383663653161664730450221008bb09f7ce233c44d13f8557c6dd32da66dd8297ee827a3472623cc800aa5c86502204bc0b1b76ef8d216f93e3b69cf928fc811c8e63d92e075823f1892bd0c97557a6d6d6d75"
    private static let protocolHex =
        "21031c4a742268957273e6a0d42d8e55e6847261d0e1eb76317d58d009c2ce52b0e2ac0f5b312c22746f646f206c697374225d0b546f646f20546f6b656e731d68747470733a2f2f69636f6e2e6578616d706c652f746f646f2e706e670f546f646f206c697374206974656d731968747470733a2f2f646f63732e6578616d706c652f746f646f42303266653864316562316263623334333262316462353833336666356632323236643963623565363563656534333035353863313865643361336338366365316166473045022100ad0d4ccd78c315a937414539087c953959c5fe5bcf9ac62e69b8561e7889d71002203b245182378adca5691c12e212e32dab373fb4804e4acb4d73760054391ce3106d6d6d75"
    private static let certificateHex =
        "2102344447857d867a428d6301dbacee2c05383d60f1def89cba6bbe9e5ae41682a4ac10746f646f2063657274696669636174650b546f646f20546f6b656e731d68747470733a2f2f69636f6e2e6578616d706c652f746f646f2e706e670f546f646f206c697374206974656d731968747470733a2f2f646f63732e6578616d706c652f746f646f4cea7b227a657461223a7b2274797065223a2274657874222c226669656c6449636f6e223a2268747470733a2f2f69636f6e2e6578616d706c652f7a2e706e67222c22667269656e646c794e616d65223a225a657461222c226465736372697074696f6e223a224c617374206669656c64227d2c22616c706861223a7b226465736372697074696f6e223a224669727374206669656c64222c22667269656e646c794e616d65223a22416c706861222c226669656c6449636f6e223a2268747470733a2f2f69636f6e2e6578616d706c652f612e706e67222c2274797065223a22696d61676555524c227d7d423032666538643165623162636233343332623164623538333366663566323232366439636235653635636565343330353538633138656433613363383663653161664730450221008233f951aec5a5626ab312f43b4ca1dc24cf44f283040f3dd3821bc14cdfe01b02204f1a23497b114f60c3e722d460a0c0eaabad17c622ecbe1778232109cc291ce56d6d6d6d"

    private let operatorKey = try! PrivateKey([UInt8](repeating: 0, count: 31) + [42])

    func testDecodesTypeScriptTokensAndWalletMatches() async throws {
        let registryOperator = RegistryOperator(publicKey: operatorKey.publicKey)
        let metadata = try RegistryMetadata(
            name: "Todo Tokens", iconURL: "https://icon.example/todo.png",
            description: "Todo list items", documentationURL: "https://docs.example/todo")
        let expected: [(String, RegistryDefinition)] = [
            (Self.basketHex, .basket(try RegistryBasketDefinition(
                basketID: "todo tokens", metadata: metadata, registryOperator: registryOperator))),
            (Self.protocolHex, .protocolDefinition(try RegistryProtocolDefinition(
                protocolID: try WalletProtocolID(securityLevel: .everyApp, name: "todo list"),
                metadata: metadata, registryOperator: registryOperator))),
            (Self.certificateHex, .certificate(try RegistryCertificateDefinition(
                type: "todo certificate", metadata: metadata,
                fields: [
                    "zeta": try RegistryCertificateFieldDescriptor(
                        friendlyName: "Zeta", description: "Last field", type: .text,
                        fieldIcon: "https://icon.example/z.png"),
                    "alpha": try RegistryCertificateFieldDescriptor(
                        friendlyName: "Alpha", description: "First field", type: .imageURL,
                        fieldIcon: "https://icon.example/a.png"),
                ],
                registryOperator: registryOperator))),
        ]
        let wallet = ProtoWallet(rootKey: operatorKey)
        for (hex, definition) in expected {
            let tsScript = try script(hex)
            XCTAssertEqual(try RegistryDefinitionCodec.decode(tsScript, kind: definition.kind), definition)

            let swiftScript = try await RegistryDefinitionCodec.lockingScript(
                for: definition, using: wallet)
            XCTAssertEqual(
                try PushDrop.decode(swiftScript, lockPosition: .beforeCompatibility).publicKey,
                try PushDrop.decode(tsScript, lockPosition: .beforeCompatibility).publicKey)
            if definition.kind != .certificate {
                // Same fields and deterministic low-S signatures: byte for byte.
                XCTAssertEqual(Hex.encode(swiftScript.bytes), hex)
            }
        }
    }

    private func script(_ hex: String) throws -> Script {
        try Script(bytes: Hex.decode(hex, maximumDecodedByteCount: 2_000), maximumByteCount: 2_000)
    }
}
