@testable import BSVCrypto
import Testing

@Suite("System secure randomness")
struct SecureRandomSourceTests {
    @Test("returns the exact requested count")
    func exactCount() throws {
        let source = SystemSecureRandomSource()
        #expect(try source.randomBytes(count: 0).isEmpty)
        #expect(try source.randomBytes(count: 1).count == 1)
        #expect(try source.randomBytes(count: 32).count == 32)
        #expect(try source.randomBytes(count: 65).count == 65)
    }

    @Test("successive system draws differ")
    func freshDraws() throws {
        let source = SystemSecureRandomSource()
        #expect(try source.randomBytes(count: 32) != source.randomBytes(count: 32))
    }

    @Test("negative counts are rejected")
    func negativeCount() {
        #expect(throws: SecureRandomSourceError.invalidByteCount(-1)) {
            try SystemSecureRandomSource().randomBytes(count: -1)
        }
    }
}
