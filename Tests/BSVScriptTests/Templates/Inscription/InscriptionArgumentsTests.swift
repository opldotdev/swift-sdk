import BSVScript
import Testing

@Suite("BRC-307 inscription arguments")
struct InscriptionArgsTests {
    @Test("argument construction keeps the canonical basic envelope")
    func canonicalEnvelope() throws {
        let limits = try InscriptionLimits(
            maximumScriptByteCount: 1_024,
            maximumContentTypeByteCount: 128,
            maximumContentByteCount: 128,
            maximumEnrichedItemCount: 4,
            maximumEnrichedItemByteCount: 128
        )
        let arguments = InscriptionArgs(
            lockingScript: try Script(bytes: [Opcode.one.rawValue], maximumByteCount: 1),
            data: Array("hi".utf8),
            contentType: "text/plain"
        )

        #expect(
            try arguments.brc307LockingScript(limits: limits).hex
                == "0063036f7264510a746578742f706c61696e000268696851"
        )
    }
}
