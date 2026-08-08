import BSVCore
import BSVKeys
import Testing

@Suite("ECIESConformance", .serialized)
struct ECIESConformanceTests {
    @Test("required pinned Go ECIES differentials agree bidirectionally")
    func requiredGoOracleDifferential() throws {
        let configuration = GoOracleConfiguration.default()
        let client: GoOracleClient
        switch try GoOracleClient.connect(configuration: configuration) {
        case .available(let availableClient):
            client = availableClient
        case .unavailable(let reason):
            #expect(!configuration.required)
            print("ECIES Go oracle unavailable: \(reason)")
            return
        }
        defer { client.close() }

        let recipient = try PrivateKey(Self.scalar(13))
        let sender = try PrivateKey(Self.scalar(7))
        var sequence = 0

        for count in [0, 16, 17, 80] {
            let plaintext = Self.message(count)
            let swiftEnvelope = try ElectrumECIES.encryptCompatibility(
                plaintext,
                to: recipient.publicKey,
                from: sender,
                senderPublicKeyPlacement: .embedded
            )
            let goEncryption = try client.request(
                id: "ecies-electrum-embedded-encrypt-\(sequence)",
                operation: "ecies.electrum.encrypt",
                arguments: [
                    "plaintext": .string(Hex.encode(plaintext)),
                    "recipientPublicKey": .string(
                        Hex.encode(recipient.publicKey.compressedBytes)
                    ),
                    "senderPrivateKey": .string(Hex.encode(sender.bytes)),
                    "omitSenderPublicKey": .bool(false),
                ]
            )
            #expect(goEncryption.result == .object([
                "envelope": .string(Hex.encode(swiftEnvelope)),
            ]))
            let goEnvelope = try Self.bytes(
                from: goEncryption,
                field: "envelope",
                maximumByteCount: swiftEnvelope.count
            )
            #expect(
                try ElectrumECIES.decrypt(goEnvelope, with: recipient) == plaintext
            )

            let goDecryption = try client.request(
                id: "ecies-electrum-embedded-decrypt-\(sequence)",
                operation: "ecies.electrum.decrypt",
                arguments: [
                    "envelope": .string(Hex.encode(swiftEnvelope)),
                    "recipientPrivateKey": .string(Hex.encode(recipient.bytes)),
                    "senderPublicKey": .string(""),
                ]
            )
            #expect(goDecryption.result == .object([
                "plaintext": .string(Hex.encode(plaintext)),
            ]))
            sequence += 1
        }

        // Pinned Go's external-key length heuristic is valid through 31-byte
        // plaintexts. The 17- and 31-byte cases both exercise multiblock CBC.
        for count in [0, 16, 17, 31] {
            let plaintext = Self.message(count)
            let swiftEnvelope = try ElectrumECIES.encryptCompatibility(
                plaintext,
                to: recipient.publicKey,
                from: sender,
                senderPublicKeyPlacement: .omitted
            )
            let goEncryption = try client.request(
                id: "ecies-electrum-omitted-encrypt-\(sequence)",
                operation: "ecies.electrum.encrypt",
                arguments: [
                    "plaintext": .string(Hex.encode(plaintext)),
                    "recipientPublicKey": .string(
                        Hex.encode(recipient.publicKey.compressedBytes)
                    ),
                    "senderPrivateKey": .string(Hex.encode(sender.bytes)),
                    "omitSenderPublicKey": .bool(true),
                ]
            )
            #expect(goEncryption.result == .object([
                "envelope": .string(Hex.encode(swiftEnvelope)),
            ]))
            let goEnvelope = try Self.bytes(
                from: goEncryption,
                field: "envelope",
                maximumByteCount: swiftEnvelope.count
            )
            #expect(
                try ElectrumECIES.decrypt(
                    goEnvelope,
                    with: recipient,
                    sender: .external(sender.publicKey)
                ) == plaintext
            )

            let goDecryption = try client.request(
                id: "ecies-electrum-omitted-decrypt-\(sequence)",
                operation: "ecies.electrum.decrypt",
                arguments: [
                    "envelope": .string(Hex.encode(swiftEnvelope)),
                    "recipientPrivateKey": .string(Hex.encode(recipient.bytes)),
                    "senderPublicKey": .string(
                        Hex.encode(sender.publicKey.compressedBytes)
                    ),
                ]
            )
            #expect(goDecryption.result == .object([
                "plaintext": .string(Hex.encode(plaintext)),
            ]))
            sequence += 1
        }

        try checkOmittedLayoutArtifact(
            client: client,
            recipient: recipient,
            sender: sender,
            sequence: sequence
        )
        sequence += 1

        let initializationVector = Array(0 ..< 16).map(UInt8.init)
        for count in [0, 16, 17, 80] {
            try checkBitcoreParity(
                client: client,
                plaintext: Self.message(count),
                recipient: recipient,
                sender: sender,
                initializationVector: initializationVector,
                sequence: sequence
            )
            sequence += 1
        }

        let leadingZeroRecipient = try PrivateKey(Self.scalar(1))
        var leadingZeroSender: PrivateKey?
        for candidate in 1 ... 2_048 {
            let privateKey = try PrivateKey(Self.scalar(candidate))
            if privateKey.publicKey.compressedBytes[1] == 0 {
                leadingZeroSender = privateKey
                break
            }
        }
        let constructedSender = try #require(leadingZeroSender)
        let sharedPoint = try leadingZeroRecipient.sharedSecret(
            with: constructedSender.publicKey
        )
        #expect(sharedPoint.compressedBytes[1] == 0)
        try checkBitcoreParity(
            client: client,
            plaintext: Self.message(33),
            recipient: leadingZeroRecipient,
            sender: constructedSender,
            initializationVector: [UInt8](repeating: 0x5a, count: 16),
            sequence: sequence
        )
    }

    private func checkOmittedLayoutArtifact(
        client: GoOracleClient,
        recipient: PrivateKey,
        sender: PrivateKey,
        sequence: Int
    ) throws {
        let plaintext = Self.message(33)
        let swiftEnvelope = try ElectrumECIES.encryptCompatibility(
            plaintext,
            to: recipient.publicKey,
            from: sender,
            senderPublicKeyPlacement: .omitted
        )
        #expect(
            try ElectrumECIES.decrypt(
                swiftEnvelope,
                with: recipient,
                sender: .external(sender.publicKey)
            ) == plaintext
        )

        let goEncryption = try client.request(
            id: "ecies-electrum-artifact-encrypt-\(sequence)",
            operation: "ecies.electrum.encrypt",
            arguments: [
                "plaintext": .string(Hex.encode(plaintext)),
                "recipientPublicKey": .string(
                    Hex.encode(recipient.publicKey.compressedBytes)
                ),
                "senderPrivateKey": .string(Hex.encode(sender.bytes)),
                "omitSenderPublicKey": .bool(true),
            ]
        )
        #expect(goEncryption.result == .object([
            "envelope": .string(Hex.encode(swiftEnvelope)),
        ]))

        let goDecryption = try client.request(
            id: "ecies-electrum-artifact-decrypt-\(sequence)",
            operation: "ecies.electrum.decrypt",
            arguments: [
                "envelope": .string(Hex.encode(swiftEnvelope)),
                "recipientPrivateKey": .string(Hex.encode(recipient.bytes)),
                "senderPublicKey": .string(
                    Hex.encode(sender.publicKey.compressedBytes)
                ),
            ]
        )
        #expect(!goDecryption.ok)
        #expect(goDecryption.error?.category == "invalidLength")
        #expect(goDecryption.result == nil)
    }

    private func checkBitcoreParity(
        client: GoOracleClient,
        plaintext: [UInt8],
        recipient: PrivateKey,
        sender: PrivateKey,
        initializationVector: [UInt8],
        sequence: Int
    ) throws {
        let swiftEnvelope = try BitcoreECIES.encryptCompatibility(
            plaintext,
            to: recipient.publicKey,
            from: sender,
            initializationVector: initializationVector
        )
        let goEncryption = try client.request(
            id: "ecies-bitcore-encrypt-\(sequence)",
            operation: "ecies.bitcore.encrypt",
            arguments: [
                "plaintext": .string(Hex.encode(plaintext)),
                "recipientPublicKey": .string(
                    Hex.encode(recipient.publicKey.compressedBytes)
                ),
                "senderPrivateKey": .string(Hex.encode(sender.bytes)),
                "initializationVector": .string(Hex.encode(initializationVector)),
            ]
        )
        #expect(goEncryption.result == .object([
            "envelope": .string(Hex.encode(swiftEnvelope)),
        ]))
        let goEnvelope = try Self.bytes(
            from: goEncryption,
            field: "envelope",
            maximumByteCount: swiftEnvelope.count
        )
        #expect(try BitcoreECIES.decrypt(goEnvelope, with: recipient) == plaintext)

        let goDecryption = try client.request(
            id: "ecies-bitcore-decrypt-\(sequence)",
            operation: "ecies.bitcore.decrypt",
            arguments: [
                "envelope": .string(Hex.encode(swiftEnvelope)),
                "recipientPrivateKey": .string(Hex.encode(recipient.bytes)),
            ]
        )
        #expect(goDecryption.result == .object([
            "plaintext": .string(Hex.encode(plaintext)),
        ]))
    }

    private static func bytes(
        from response: GoOracleResponse,
        field: String,
        maximumByteCount: Int
    ) throws -> [UInt8] {
        guard response.ok,
              case .object(let object) = response.result,
              case .string(let encoded) = object[field]
        else {
            throw ECIESConformanceError.unexpectedOracleResult
        }
        return try Hex.decode(encoded, maximumDecodedByteCount: maximumByteCount)
    }

    private static func scalar(_ value: Int) -> [UInt8] {
        precondition((0 ... 65_535).contains(value))
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[30] = UInt8(value >> 8)
        bytes[31] = UInt8(value & 0xff)
        return bytes
    }

    private static func message(_ count: Int) -> [UInt8] {
        (0 ..< count).map { UInt8(($0 * 29 + 7) & 0xff) }
    }
}

private enum ECIESConformanceError: Error {
    case unexpectedOracleResult
}
