import BSVCore
import BSVCrypto
import BSVKeys
import BSVScript
import BSVTransaction
import Testing

@testable import BSVOverlay

/// Overlay names, advertisements, discovery, and broadcast policy checked
/// against `@bsv/sdk` 4.1.1 (ts-stack `3b1abc569`, `packages/sdk/src/overlay-tools`).
@Suite("Overlay policy matches @bsv/sdk")
struct OverlayTSParityTests {
    // MARK: O11 names

    static let assetID = String(repeating: "0123456789abcdef", count: 4) + "_0"

    @Test("O11: topic and service names follow the @bsv/sdk grammar")
    func nameGrammar() throws {
        // `__tests/OverlayNames.test.ts:20-60`.
        let acceptedTopics = [
            "tm_uhrp_files", "tm_a", "tm_2", "tm_color_\(Self.assetID)",
            "tm_color_" + String(repeating: "ff", count: 32) + "_4294967295",
            "tm_" + String(repeating: "a", count: 253),
        ]
        for name in acceptedTopics {
            #expect(try OverlayTopic(rawValue: name).rawValue == name)
            #expect(throws: (any Error).self) { _ = try OverlayService(rawValue: name) }
        }
        let acceptedServices = [
            "ls_uhrp_files", "ls_a", "ls_color_\(Self.assetID)",
            "ls_" + String(repeating: "a", count: 253),
        ]
        for name in acceptedServices {
            #expect(try OverlayService(rawValue: name).rawValue == name)
            #expect(throws: (any Error).self) { _ = try OverlayTopic(rawValue: name) }
        }
        let rejected: [(String, String)] = [
            ("tm_", "ls_"),
            ("tm__x", "ls__x"),
            ("tm_x_", "ls_x_"),
            ("tm_x__y", "ls_x__y"),
            ("tm_Color", "ls_Color"),
            ("tm_color_\(Self.assetID.uppercased())", "ls_color_\(Self.assetID.uppercased())"),
            ("tm_" + String(repeating: "a", count: 254), "ls_" + String(repeating: "a", count: 254)),
            ("tm_" + String(repeating: "a", count: 297), "ls_" + String(repeating: "a", count: 297)),
            ("color_\(Self.assetID)", "color_\(Self.assetID)"),
            ("tm-x", "ls-x"),
            ("tm_x-y", "ls_x-y"),
            ("tm_x\n", "ls_x\n"),
            ("tm_é", "ls_é"),
            ("", ""),
        ]
        for (topic, service) in rejected {
            #expect(throws: (any Error).self) { _ = try OverlayTopic(rawValue: topic) }
            #expect(throws: (any Error).self) { _ = try OverlayService(rawValue: service) }
        }
        // The 256-byte cap is part of the grammar, whatever the caller's limit.
        let roomy = try overlayLimits(maximumNameBytes: 1_024)
        #expect(throws: OverlayError.invalidTopic) {
            _ = try OverlayTopic(rawValue: "tm_" + String(repeating: "a", count: 254), limits: roomy)
        }
    }

    // MARK: O10 advertisements

    // `OverlayAdminTokenTemplate.lock` output (`OverlayAdminTokenTemplate.ts:271-311`),
    // as in `__tests/OverlayAdminTokenTemplate.test.ts:50-84`: wallet key 1,
    // SHIP, `https://test.com`, `tm_tests`.
    static let tsSHIP =
        "2102d7245996c0abb8323c4780f4e7c5f7938e5498e35daa5325641df6fa5129f86bac0453484950210279"
        + "be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817981068747470733a2f2f746573"
        + "742e636f6d08746d5f7465737473473045022100dcc586bd746d81c0df35ad821673c7575b7e79a031bc6e"
        + "0320781244b372588f0220633d47d958badcddb81589eb45558822586e9f8091eeb83b98355fe728174573"
        + "6d6d75"
    // Wallet key 2, SLAP, `https://lookup.example/`, `ls_records`.
    static let tsSLAP =
        "2102b67adb75684410fd113d58fe263bcc9f14123330ccea191bbb565c258c6d7452ac04534c41502102c6"
        + "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51768747470733a2f2f6c6f6f"
        + "6b75702e6578616d706c652f0a6c735f7265636f726473473045022100c4b361ad7c52ad91803a51db51dc"
        + "08041c29d0be83d056854f034e6ee96a6e6702206678c37d871e7793054c24605453c57c372d08a44d91d5"
        + "fc108cef76ad9056896d6d75"
    // A legacy SDK advertisement: protocol `[2, "Service Host Interconnect"]`,
    // counterparty "self", wallet key 3 (`__tests/OverlayAdminTokenTemplate.test.ts:143-160`).
    static let tsLegacy =
        "2102c7219533e42d5406f71551bf7256b94bd4237c75d52a35542ad455925c162a86ac04534849502102f9"
        + "308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f91668747470733a2f2f6c6567"
        + "6163792e6578616d706c6509746d5f6c65676163794630440220447a527e4fca3f8f8556d1565ec2f06e3e"
        + "cbff940f9eb69e4bc92e8bdb92b9280220155ad4a39dd7bdc05569d32e2a8c4d029386649226020a936082"
        + "061818330e286d6d75"

    @Test("O10: advertisements written by @bsv/sdk decode and verify")
    func tsAdvertisements() throws {
        let ship = try OverlayAdminTokenCodec.decode(try script(Self.tsSHIP))
        #expect(ship.identityPublicKey == (try privateKey(1)).publicKey)
        #expect(ship.host.rawValue == "https://test.com")
        #expect(ship.subject == .ship(try OverlayTopic(rawValue: "tm_tests")))

        let slap = try OverlayAdminTokenCodec.decode(try script(Self.tsSLAP))
        #expect(slap.identityPublicKey == (try privateKey(2)).publicKey)
        #expect(slap.host.rawValue == "https://lookup.example/")
        #expect(slap.subject == .slap(try OverlayService(rawValue: "ls_records")))
    }

    @Test("O10: legacy advertisements are not authenticated")
    func legacyAdvertisement() throws {
        #expect(throws: OverlayAdminTokenError.invalidSignature) {
            _ = try OverlayAdminTokenCodec.decode(try script(Self.tsLegacy))
        }
    }

    @Test("O10: the locking key must be derived from the stated identity key")
    func identityLinkage() throws {
        let identity = try privateKey(24)
        // Signed by its own locking key, which is not the identity's child.
        // The decoder used to accept this and report an unauthenticated identity.
        let unrelated = try privateKey(99)
        let forged = try advertisementScript(
            protocolText: "SHIP", identity: identity, host: "https://ship.example",
            subject: "tm_security", lockingKey: unrelated
        )
        #expect(throws: OverlayAdminTokenError.invalidSignature) {
            _ = try OverlayAdminTokenCodec.decode(forged)
        }

        // `OverlayAdminTokenTemplate.boundaries.test.ts:73-88`: a correct
        // signature, but the locking key belongs to another identity.
        let canonical = try advertisementScript(
            protocolText: "SHIP", identity: identity, host: "https://ship.example",
            subject: "tm_security"
        )
        let decoded = try PushDrop.decode(canonical, lockPosition: .beforeCompatibility)
        let swapped = try PushDrop.lockingScript(
            fields: decoded.fields,
            publicKey: try linkedKey(try privateKey(25), protocolText: "SHIP").publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: OverlayAdminTokenError.unlinkedLockingKey) {
            _ = try OverlayAdminTokenCodec.decode(swapped)
        }

        // A SLAP-derived key does not authenticate a SHIP advertisement.
        let crossProtocol = try advertisementScript(
            protocolText: "SHIP", identity: identity, host: "https://ship.example",
            subject: "tm_security", lockingKey: try linkedKey(identity, protocolText: "SLAP")
        )
        #expect(throws: OverlayAdminTokenError.invalidSignature) {
            _ = try OverlayAdminTokenCodec.decode(crossProtocol)
        }
    }

    @Test("O10: advertised URIs follow the @bsv/sdk rules")
    func advertisementURIs() throws {
        let identity = try privateKey(21)
        // `OverlayAdminTokenTemplate.boundaries.test.ts:7-29,40-52`.
        let invalid = [
            "overlay.example",
            "http://test.com",
            "https://localhost",
            "https://xn--bcher-kva.example",
            "https://user:secret@example.com",
            "https://example.com/path",
            "https://example.com/#fragment",
            "https://[",
            "wss://localhost/socket",
            "wss://user:secret@example.com/socket",
            "wss://example.com/socket#fragment",
            "wss://[",
            "js8c+bsvauth+smf:",
            "js8c+bsvauth+smf:?lat=1&long=2&freq=7MHz&radius=10km&extra=1",
            "js8c+bsvauth+smf:?lat=1&lat=2&long=2&freq=7MHz&radius=10km",
            "js8c+bsvauth+smf:?lat=1e1&long=2&freq=7MHz&radius=10km",
            "js8c+bsvauth+smf:?lat=91&long=2&freq=7MHz&radius=10km",
            "js8c+bsvauth+smf:?lat=1&long=-181&freq=7MHz&radius=10km",
            "js8c+bsvauth+smf:?lat=1&long=2&freq=0MHz&radius=10km",
            "js8c+bsvauth+smf:?lat=1&long=2&freq=\(String(repeating: "9", count: 400))MHz&radius=10km",
            "js8c+bsvauth+smf:?lat=1&long=2&freq=7MHz&radius=none",
            "https://example.com/\u{0000}",
            "https://example.com/\u{0085}",
        ]
        for uri in invalid {
            #expect(throws: OverlayAdminTokenError.invalidHost, "\(uri)") {
                _ = try OverlayAdminTokenCodec.decode(
                    try advertisementScript(
                        protocolText: "SHIP", identity: identity, host: uri, subject: "tm_security"
                    ))
            }
        }
        // `OverlayAdminTokenTemplate.boundaries.test.ts:54-71`, plus forms the
        // WHATWG parser normalizes to the same origin.
        let valid = [
            "https://example.com",
            "https+bsvauth://example.com",
            "https+bsvauth+smf://example.com",
            "https+bsvauth+scrypt-offchain://example.com",
            "https+rtt://example.com",
            "wss://example.com/socket",
            "js8c+bsvauth+smf:?lat=41.88&long=-87.63&freq=7.078MHz&radius=10km",
            "https://example.com/",
            "https://Example.COM:443/",
            "https://example.com:8443",
            "https://example.com/?",
            "https://example.com/#",
        ]
        for uri in valid {
            let token = try OverlayAdminTokenCodec.decode(
                try advertisementScript(
                    protocolText: "SHIP", identity: identity, host: uri, subject: "tm_security"
                ))
            #expect(token.host.rawValue == uri)
        }
    }

    @Test("O10: field and signature sizes follow @bsv/sdk")
    func fieldBounds() throws {
        #expect(OverlayAdminTokenLimits.standard.maximumFieldByteCount == 4_096)
        let identity = try privateKey(26)
        let canonical = try advertisementScript(
            protocolText: "SLAP", identity: identity, host: "https://lookup.example",
            subject: "ls_security"
        )
        // `OverlayAdminTokenTemplate.boundaries.test.ts:90-100`: a 1-byte signature field.
        let decoded = try PushDrop.decode(canonical, lockPosition: .beforeCompatibility)
        let truncated = try PushDrop.lockingScript(
            fields: Array(decoded.fields.dropLast()) + [[1]],
            publicKey: decoded.publicKey,
            lockPosition: .beforeCompatibility
        )
        #expect(throws: OverlayAdminTokenError.invalidSignature) {
            _ = try OverlayAdminTokenCodec.decode(truncated)
        }
        // A 4097-byte host field exceeds `MAX_DISCOVERY_FIELD_BYTES` even with roomier limits.
        let roomy = try OverlayAdminTokenLimits(
            maximumScriptByteCount: 64 * 1_024,
            maximumFieldByteCount: 16 * 1_024,
            overlayLimits: try overlayLimits(maximumNameBytes: 256, maximumHostBytes: 8_192)
        )
        let longHost = "https://" + String(repeating: "a", count: 4_085) + ".com"
        #expect(longHost.utf8.count == 4_097)
        #expect(throws: OverlayAdminTokenError.invalidPushDrop) {
            _ = try OverlayAdminTokenCodec.decode(
                try advertisementScript(
                    protocolText: "SLAP", identity: identity, host: longHost,
                    subject: "ls_security"
                ),
                limits: roomy
            )
        }
    }

    // MARK: Discovery (O10 one satoshi, O14 origins)

    @Test("O10 and O14: SLAP discovery needs one satoshi and normalizes advertised origins")
    func slapDiscovery() async throws {
        let tracker = try OverlayHost(rawValue: "https://tracker.example")
        let service = try OverlayService(rawValue: "ls_records")
        let outputs = [
            // Two advertisements for the same origin, one with a trailing slash.
            try advertisementItem("SLAP", host: "https://service.example/", subject: service.rawValue, key: 30),
            try advertisementItem("SLAP", host: "https://SERVICE.example:443", subject: service.rawValue, key: 31),
            // Two satoshis: skipped, as `LookupResolver.ts:2219` does.
            try advertisementItem("SLAP", host: "https://rich.example", subject: service.rawValue, key: 32, satoshis: 2),
            // Not an HTTPS origin: nothing the HTTPS facilitators can call.
            try advertisementItem("SLAP", host: "wss://socket.example/feed", subject: service.rawValue, key: 33),
            // Signed by an unlinked key.
            try advertisementItem("SLAP", host: "https://forged.example", subject: service.rawValue, key: 34, linked: false),
        ]
        let resolver = try LookupResolver(
            facilitator: ParityLookupMock(responses: [tracker: try LookupAnswer(outputList: outputs)]),
            slapTrackers: [tracker],
            beefLimits: try beefLimits()
        )
        #expect(
            try await resolver.competentHosts(for: service)
                == [try OverlayHost(rawValue: "https://service.example")]
        )
    }

    // MARK: O15 answers

    @Test("O15: output lists win over freeform answers; all failures still throw")
    func mixedAnswers() async throws {
        let service = try OverlayService(rawValue: "ls_records")
        let a = try OverlayHost(rawValue: "https://a.example")
        let b = try OverlayHost(rawValue: "https://b.example")
        let c = try OverlayHost(rawValue: "https://c.example")
        let item = try advertisementItem("SLAP", host: "https://x.example", subject: service.rawValue, key: 40)
        let mixed = try LookupResolver(
            facilitator: ParityLookupMock(responses: [
                a: try LookupAnswer(freeform: [1]),
                b: try LookupAnswer(outputList: [item]),
            ]),
            slapTrackers: [],
            hostOverrides: [service: [a, b, c]],
            beefLimits: try beefLimits()
        )
        // `LookupResolver.ts:1508-1528`: the freeform answer is counted and left out.
        #expect(try await mixed.resolve(LookupQuestion(service: service, query: [])) == .outputList([item]))

        let failing = try LookupResolver(
            facilitator: ParityLookupMock(responses: [:]),
            slapTrackers: [],
            hostOverrides: [service: [a, b]],
            beefLimits: try beefLimits()
        )
        await #expect(throws: OverlayPolicyError.noSuccessfulResponses) {
            _ = try await failing.resolve(LookupQuestion(service: service, query: []))
        }
    }

    // MARK: O7 per-host topics

    @Test("O7: each host is sent only the topics it advertised")
    func perHostTopics() async throws {
        let topicA = try OverlayTopic(rawValue: "tm_a")
        let topicB = try OverlayTopic(rawValue: "tm_b")
        let h1 = try OverlayHost(rawValue: "https://h1.example")
        let h2 = try OverlayHost(rawValue: "https://h2.example")
        let discovery = try LookupAnswer(outputList: [
            advertisementItem("SHIP", host: "https://h1.example/", subject: "tm_a", key: 50),
            advertisementItem("SHIP", host: "https://h2.example", subject: "tm_a", key: 51),
            advertisementItem("SHIP", host: "https://h2.example", subject: "tm_b", key: 52),
        ])
        let both = try AdmittanceInstructions(outputsToAdmit: [0])
        let facilitator = ParityTopicMock(steaks: [
            h1: try Steak(instructions: [topicA: both]),
            h2: try Steak(instructions: [topicA: both, topicB: both]),
        ])
        let limits = try beefLimits()
        let broadcaster = try OverlayTopicBroadcaster(
            topics: [topicB, topicA],
            facilitator: facilitator,
            resolver: ParityResolverMock(answer: discovery),
            acknowledgmentByHost: [
                try OverlayHost(rawValue: "https://h1.example/"): try AckFrom(
                    requirement: .some, topics: [topicA])
            ],
            beefLimits: limits
        )
        _ = try await broadcaster.broadcast(try atomicBEEF(limits: limits))
        #expect(await facilitator.topics(for: h1) == [topicA])
        #expect(await facilitator.topics(for: h2) == [topicA, topicB])
    }

    @Test("O7: a host that acknowledges a topic it was not sent fails the broadcast")
    func unexpectedTopicAcknowledgment() async throws {
        let topicA = try OverlayTopic(rawValue: "tm_a")
        let topicB = try OverlayTopic(rawValue: "tm_b")
        let h1 = try OverlayHost(rawValue: "https://h1.example")
        let discovery = try LookupAnswer(outputList: [
            advertisementItem("SHIP", host: h1.rawValue, subject: "tm_a", key: 60)
        ])
        let instructions = try AdmittanceInstructions(outputsToAdmit: [0])
        let facilitator = ParityTopicMock(steaks: [
            h1: try Steak(instructions: [topicA: instructions, topicB: instructions])
        ])
        let limits = try beefLimits()
        let broadcaster = try OverlayTopicBroadcaster(
            topics: [topicA, topicB],
            facilitator: facilitator,
            resolver: ParityResolverMock(answer: discovery),
            acknowledgmentFromAnyHost: try AckFrom(requirement: .any),
            beefLimits: limits
        )
        await #expect(throws: OverlayPolicyError.uncertainDelivery) {
            _ = try await broadcaster.broadcast(try atomicBEEF(limits: limits))
        }
    }

    // MARK: S5 URI hosts

    @Test("S5: advertised IP hosts are parsed and written as WHATWG URL does")
    func whatwgHosts() throws {
        // `new URL(uri).origin` in Bun, the parser `@bsv/sdk` uses
        // (`OverlayAdminTokenTemplate.ts:81-95`, `SHIPBroadcaster.ts:102-125`).
        let origins: [(String, String?)] = [
            ("https://1.2.3.4.5/", nil),
            ("https://256.1.1.1/", nil),
            ("https://a.b.c.1/", nil),
            ("https://09.1.1.1/", nil),
            ("https://1.2.3.08/", nil),
            ("https://example.0x10/", nil),
            ("https://4294967296/", nil),
            ("https://[1::2::3]/", nil),
            ("https://[1:2:3:4:5:6:7:8:9]/", nil),
            ("https://2130706433/", "https://127.0.0.1"),
            ("https://0x7f.1/", "https://127.0.0.1"),
            ("https://0x/", "https://0.0.0.0"),
            ("https://1.2.3/", "https://1.2.0.3"),
            ("https://010.0.0.1/", "https://8.0.0.1"),
            ("https://0300.0250.1.1/", "https://192.168.1.1"),
            ("https://8.8.8.8./", "https://8.8.8.8"),
            ("https://4294967295/", "https://255.255.255.255"),
            ("https://[0:0:0:0:0:0:0:1]/", "https://[::1]"),
            ("https://[::FFFF:1.2.3.4]/", "https://[::ffff:102:304]"),
            ("https://[2001:db8:0:0:1:0:0:1]/", "https://[2001:db8::1:0:0:1]"),
            ("https://[1:0:0:2:0:0:0:3]/", "https://[1:0:0:2::3]"),
            ("https://[::]/", "https://[::]"),
            ("https://[::1.2.3.4]/", "https://[::102:304]"),
        ]
        for (uri, origin) in origins {
            #expect(OverlayAdvertisementURI.httpsOrigin(uri) == origin, "\(uri)")
            #expect(OverlayAdvertisementURI.isValid(uri) == (origin != nil), "\(uri)")
        }
        // The same rules hold for every scheme with a host.
        #expect(!OverlayAdvertisementURI.isValid("wss://256.1.1.1/socket"))
        #expect(!OverlayAdvertisementURI.isValid("https+bsvauth://[1::2::3]"))
    }

    // MARK: S6 public hosts

    @Test("S6: only public network addresses pass the discovered-host filter")
    func publicAddresses() throws {
        // `isPublicNetworkAddress` in `@bsv/sdk`, run in Bun
        // (`storage/PublicHTTPSFetch.ts:114-158`).
        let verdicts: [(String, Bool)] = [
            ("127.0.0.1", false), ("192.168.1.1", false), ("10.1.2.3", false),
            ("100.64.0.1", false), ("169.254.1.1", false), ("172.16.0.1", false),
            ("224.0.0.1", false), ("198.18.0.1", false), ("203.0.113.1", false),
            ("0.0.0.0", false), ("8.8.8.8", true), ("1.1.1.1", true),
            ("[::1]", false), ("[::]", false), ("[fe80::1]", false), ("[fd00::1]", false),
            ("[::ffff:7f00:1]", false), ("[64:ff9b::a00:1]", false),
            ("[2002:c0a8:101::]", false), ("[2001:db8::1]", false), ("[ff02::1]", false),
            ("[3ff0::1]", false), ("[2001:100::1]", false), ("[::102:304]", false),
            ("[2606:4700::1111]", true), ("[2001:4860:4860::8888]", true),
        ]
        for (host, isPublic) in verdicts {
            #expect(
                OverlayAdvertisementURI.isPublicHTTPSOrigin("https://\(host)") == isPublic,
                "\(host)")
        }
        for name in ["printer.local", "db.internal", "box.home.arpa", "a.localhost", "localhost."] {
            #expect(!OverlayAdvertisementURI.isPublicHTTPSOrigin("https://\(name)"), "\(name)")
        }
        #expect(OverlayAdvertisementURI.isPublicHTTPSOrigin("https://overlay.example"))
        // A numeric alias of a private address is caught after canonicalization.
        #expect(!OverlayAdvertisementURI.isPublicHTTPSOrigin("https://2130706433/"))
    }

    @Test("S6 and S7: discovery skips private hosts and merges with caller hosts")
    func discoveryHostPolicy() async throws {
        let tracker = try OverlayHost(rawValue: "https://tracker.example")
        let service = try OverlayService(rawValue: "ls_records")
        var key: UInt8 = 70
        func ad(_ host: String) throws -> OutputListItem {
            key += 1
            return try advertisementItem("SLAP", host: host, subject: service.rawValue, key: key)
        }
        let outputs = try [
            ad("https://127.0.0.1"), ad("https://2130706433/"), ad("https://192.168.1.1"),
            ad("https://[::1]"), ad("https://printer.local"), ad("https://8.8.8.8"),
            ad("https://service.example/"),
        ]
        let facilitator = ParityLookupMock(responses: [
            tracker: try LookupAnswer(outputList: outputs)
        ])
        let publicOnly = try LookupResolver(
            facilitator: facilitator,
            slapTrackers: [tracker],
            additionalHosts: [service: [try OverlayHost(rawValue: "https://Service.example:443/")]],
            beefLimits: try beefLimits()
        )
        #expect(
            try await publicOnly.competentHosts(for: service) == [
                try OverlayHost(rawValue: "https://8.8.8.8"),
                try OverlayHost(rawValue: "https://service.example"),
            ])

        let any = try LookupResolver(
            facilitator: facilitator,
            slapTrackers: [tracker],
            beefLimits: try beefLimits(),
            discoveredHostPolicy: .anyHTTPSOrigin
        )
        #expect(
            try await any.competentHosts(for: service).map(\.rawValue) == [
                "https://127.0.0.1", "https://192.168.1.1", "https://8.8.8.8",
                "https://[::1]", "https://printer.local", "https://service.example",
            ])
    }

    @Test("S7: caller hosts are normalized, and one origin twice in a list is a duplicate")
    func callerHostNormalization() async throws {
        let service = try OverlayService(rawValue: "ls_records")
        let item = try advertisementItem("SLAP", host: "https://x.example", subject: service.rawValue, key: 80)
        let host = try OverlayHost(rawValue: "https://a.example")
        let facilitator = ParityLookupMock(responses: [host: try LookupAnswer(outputList: [item])])
        let resolver = try LookupResolver(
            facilitator: facilitator,
            slapTrackers: [],
            hostOverrides: [service: [try OverlayHost(rawValue: "https://A.example/")]],
            additionalHosts: [service: [host]],
            beefLimits: try beefLimits()
        )
        #expect(try await resolver.competentHosts(for: service) == [host])
        _ = try await resolver.resolve(LookupQuestion(service: service, query: []))
        #expect(await facilitator.requestCount() == 1)

        // `configuredHosts` in `@bsv/sdk` (`LookupResolver.ts:551-568`).
        #expect(throws: OverlayError.duplicateValue(name: "hosts")) {
            _ = try LookupResolver(
                facilitator: facilitator,
                slapTrackers: [],
                hostOverrides: [
                    service: [try OverlayHost(rawValue: "https://a.example/"), host]
                ],
                beefLimits: try beefLimits()
            )
        }
    }

    // MARK: S3 bad outputs

    @Test("S3: one host's unreadable output is left out, with its reason")
    func badOutputIsSkipped() async throws {
        let service = try OverlayService(rawValue: "ls_records")
        let a = try OverlayHost(rawValue: "https://a.example")
        let b = try OverlayHost(rawValue: "https://b.example")
        let good = try advertisementItem("SLAP", host: "https://x.example", subject: service.rawValue, key: 90)
        // Its `txid` names a transaction its BEEF does not hold, which
        // `resolveTxIdForOutput` in `@bsv/sdk` skips.
        let wrongID = try OutputListItem(
            beef: good.beef, outputIndex: 0,
            transactionID: try TransactionID(displayHex: String(repeating: "ab", count: 32)))
        let outOfRange = try OutputListItem(beef: good.beef, outputIndex: 9)
        let unreadable = try OutputListItem(beef: [1, 2, 3], outputIndex: 0)
        let resolver = try LookupResolver(
            facilitator: ParityLookupMock(responses: [
                a: try LookupAnswer(outputList: [wrongID, outOfRange, unreadable]),
                b: try LookupAnswer(outputList: [good]),
            ]),
            slapTrackers: [],
            hostOverrides: [service: [a, b, try OverlayHost(rawValue: "https://c.example")]],
            beefLimits: try beefLimits()
        )
        let question = try LookupQuestion(service: service, query: [])
        #expect(try await resolver.resolve(question) == .outputList([good]))

        let detailed = try await resolver.resolveDetailed(question)
        #expect(detailed.answer == .outputList([good]))
        #expect(detailed.rejectedOutputs.map(\.host) == [a, a, a])
        #expect(detailed.rejectedOutputs.map(\.output) == [wrongID, outOfRange, unreadable])
        #expect(detailed.rejectedOutputs[0].error as? OverlayPolicyError == .invalidLookupOutput)
        #expect(detailed.rejectedOutputs[2].error is BEEFError)
        #expect(detailed.hostFailures.map(\.host.rawValue) == ["https://c.example"])

        // When every output is unreadable there is no answer.
        let allBad = try LookupResolver(
            facilitator: ParityLookupMock(responses: [a: try LookupAnswer(outputList: [unreadable])]),
            slapTrackers: [],
            hostOverrides: [service: [a]],
            beefLimits: try beefLimits()
        )
        await #expect(throws: OverlayPolicyError.invalidLookupOutput) {
            _ = try await allBad.resolve(question)
        }
        #expect(try await allBad.resolveDetailed(question).answer == nil)
    }

    // MARK: Broadcast acknowledgment

    @Test("A failed host does not fail a broadcast another host acknowledged")
    func failedHostIsTolerated() async throws {
        let topic = try OverlayTopic(rawValue: "tm_a")
        let good = try OverlayHost(rawValue: "https://good.example")
        let down = try OverlayHost(rawValue: "https://down.example")
        let empty = try OverlayHost(rawValue: "https://empty.example")
        let discovery = try LookupAnswer(outputList: [
            advertisementItem("SHIP", host: good.rawValue, subject: "tm_a", key: 100),
            advertisementItem("SHIP", host: down.rawValue, subject: "tm_a", key: 101),
            advertisementItem("SHIP", host: empty.rawValue, subject: "tm_a", key: 102),
        ])
        let facilitator = ParityTopicMock(steaks: [
            good: try Steak(instructions: [topic: try AdmittanceInstructions(outputsToAdmit: [0])]),
            empty: try Steak(),
        ])
        let limits = try beefLimits()
        let atomic = try atomicBEEF(limits: limits)
        func broadcaster(
            every: AckFrom? = nil, byHost: [OverlayHost: AckFrom] = [:]
        ) throws -> OverlayTopicBroadcaster {
            try OverlayTopicBroadcaster(
                topics: [topic], facilitator: facilitator,
                resolver: ParityResolverMock(answer: discovery),
                acknowledgmentFromEveryHost: every, acknowledgmentByHost: byHost,
                beefLimits: limits)
        }

        // `SHIPBroadcaster` defaults: some host must acknowledge every topic.
        let result = try await broadcaster().broadcast(atomic)
        #expect(result.transactionID == atomic.subjectTransactionID)
        let report = try await broadcaster().broadcastDetailed(atomic)
        #expect(report.failure == nil)
        #expect(report.acknowledgedTopics == [good: [topic]])
        #expect(report.hostFailures.map(\.host) == [down, empty])
        #expect(report.hostFailures[1].error as? OverlayPolicyError == .invalidSteak)

        // A requirement on every host, or on the failed host, is not met, and
        // the failed host's delivery is uncertain.
        await #expect(throws: OverlayPolicyError.uncertainDelivery) {
            _ = try await broadcaster(every: try AckFrom(requirement: .all)).broadcast(atomic)
        }
        await #expect(throws: OverlayPolicyError.uncertainDelivery) {
            _ = try await broadcaster(byHost: [down: try AckFrom(requirement: .any)])
                .broadcast(atomic)
        }
    }

    @Test("Discovered lookup hosts past the host limit are left out, not an error")
    func discoveredHostLimitTruncates() async throws {
        let limits = try overlayLimits(maximumNameBytes: 256, maximumHosts: 2)
        let tracker = try OverlayHost(rawValue: "https://tracker.example")
        let service = try OverlayService(rawValue: "ls_records")
        let caller = try OverlayHost(rawValue: "https://caller.example")
        let outputs = try [
            advertisementItem("SLAP", host: "https://a.example", subject: service.rawValue, key: 120),
            advertisementItem("SLAP", host: "https://caller.example", subject: service.rawValue, key: 121),
            advertisementItem("SLAP", host: "https://b.example", subject: service.rawValue, key: 122),
            advertisementItem("SLAP", host: "https://c.example", subject: service.rawValue, key: 123),
        ]
        let resolver = try LookupResolver(
            facilitator: ParityLookupMock(responses: [tracker: try LookupAnswer(outputList: outputs)]),
            slapTrackers: [tracker],
            additionalHosts: [service: [caller]],
            beefLimits: try beefLimits(),
            limits: limits
        )
        #expect(
            try await resolver.competentHosts(for: service).map(\.rawValue) == [
                "https://a.example", "https://caller.example",
            ])
    }

    @Test("Hosts past the host limit are left out, not an error")
    func hostLimitTruncates() async throws {
        let topic = try OverlayTopic(rawValue: "tm_a")
        let first = try OverlayHost(rawValue: "https://first.example")
        let discovery = try LookupAnswer(outputList: [
            advertisementItem("SHIP", host: first.rawValue, subject: "tm_a", key: 110),
            advertisementItem("SHIP", host: "https://second.example", subject: "tm_a", key: 111),
        ])
        let acknowledged = try Steak(
            instructions: [topic: try AdmittanceInstructions(outputsToAdmit: [0])])
        let facilitator = ParityTopicMock(steaks: [
            first: acknowledged, try OverlayHost(rawValue: "https://second.example"): acknowledged,
        ])
        let limits = try beefLimits()
        let broadcaster = try OverlayTopicBroadcaster(
            topics: [topic], facilitator: facilitator,
            resolver: ParityResolverMock(answer: discovery),
            beefLimits: limits,
            limits: try overlayLimits(maximumNameBytes: 256, maximumHosts: 1)
        )
        let report = try await broadcaster.broadcastDetailed(try atomicBEEF(limits: limits))
        #expect(report.acknowledgedTopics.keys.map(\.rawValue) == [first.rawValue])
    }

    @Test("N3: an acknowledgment host that is not an https origin is rejected up front")
    func acknowledgmentHostMustBeOrigin() throws {
        let topic = try OverlayTopic(rawValue: "tm_a")
        for raw in ["overlay.example", "https://overlay.example/path", "http://overlay.example"] {
            #expect(throws: OverlayError.invalidHost, "\(raw)") {
                _ = try OverlayTopicBroadcaster(
                    topics: [topic],
                    facilitator: ParityTopicMock(steaks: [:]),
                    resolver: ParityResolverMock(answer: try LookupAnswer(outputList: [])),
                    acknowledgmentByHost: [try OverlayHost(rawValue: raw): try AckFrom(requirement: .any)],
                    beefLimits: try beefLimits()
                )
            }
        }
    }

    // MARK: Helpers

    private func privateKey(_ value: UInt8) throws -> PrivateKey {
        try PrivateKey(Array(repeating: 0, count: 31) + [value])
    }

    private func linkedKey(_ identity: PrivateKey, protocolText: String) throws -> PrivateKey {
        let protocolID = protocolText == "SLAP"
            ? "service lookup availability" : "service host interconnect"
        return try identity.derivedChild(
            with: try privateKey(1).publicKey,
            invoiceNumber: "2-\(protocolID)-1"
        )
    }

    private func script(_ hex: String) throws -> Script {
        try Script(hex: hex, maximumByteCount: 64 * 1_024)
    }

    private func advertisementScript(
        protocolText: String,
        identity: PrivateKey,
        host: String,
        subject: String,
        lockingKey: PrivateKey? = nil
    ) throws -> Script {
        let key = try lockingKey ?? linkedKey(identity, protocolText: protocolText)
        let fields = [
            Array(protocolText.utf8),
            identity.publicKey.compressedBytes,
            Array(host.utf8),
            Array(subject.utf8),
        ]
        let signature = try key.sign(digest: BSVHashing.sha256(fields.flatMap { $0 }))
        return try PushDrop.lockingScript(
            fields: fields + [signature.derBytes],
            publicKey: key.publicKey,
            lockPosition: .beforeCompatibility
        )
    }

    private func advertisementItem(
        _ protocolText: String,
        host: String,
        subject: String,
        key: UInt8,
        satoshis: UInt64 = 1,
        linked: Bool = true
    ) throws -> OutputListItem {
        let identity = try privateKey(key)
        let script = try advertisementScript(
            protocolText: protocolText,
            identity: identity,
            host: host,
            subject: subject,
            lockingKey: linked ? nil : try privateKey(key &+ 100)
        )
        let transaction = Transaction(
            outputs: [TransactionOutput(satoshis: satoshis, lockingScript: script)]
        )
        let limits = try beefLimits()
        let beef = try BEEF(
            version: .v2, merklePaths: [], transactions: [.raw(transaction)], limits: limits
        )
        return try OutputListItem(beef: beef.serialized(limits: limits), outputIndex: 0)
    }

    private func atomicBEEF(limits: BEEFLimits) throws -> AtomicBEEF {
        let transaction = Transaction(
            outputs: [
                TransactionOutput(
                    satoshis: 1, lockingScript: try Script(bytes: [0x51], maximumByteCount: 1))
            ]
        )
        return try AtomicBEEF(
            subjectTransactionID: try transaction.transactionID(limits: limits.transactionLimits),
            beef: try BEEF(
                version: .v2, merklePaths: [], transactions: [.raw(transaction)], limits: limits
            ),
            limits: limits
        )
    }

    private func beefLimits() throws -> BEEFLimits {
        try BEEFLimits(
            maximumByteCount: 32 * 1_024 * 1_024,
            maximumMerklePathCount: 1_000,
            maximumTransactionCount: 1_000,
            transactionLimits: try TransactionLimits(
                maximumTransactionByteCount: 1_000_000,
                maximumInputCount: 1_000,
                maximumOutputCount: 1_000,
                maximumScriptByteCount: 100_000
            ),
            merklePathLimits: try MerklePathLimits(
                maximumByteCount: 1_000_000,
                maximumLeavesPerLevel: 1_000,
                maximumTotalLeaves: 1_000
            )
        )
    }

    private func overlayLimits(
        maximumNameBytes: Int,
        maximumHostBytes: Int = 2_048,
        maximumHosts: Int = 64
    ) throws -> OverlayLimits {
        try OverlayLimits(
            maximumTaggedBEEFByteCount: 1_024,
            maximumOffChainValueByteCount: 1_024,
            maximumTopicCount: 16,
            maximumTopicUTF8ByteCount: maximumNameBytes,
            maximumServiceUTF8ByteCount: maximumNameBytes,
            maximumHostUTF8ByteCount: maximumHostBytes,
            maximumMetadataUTF8ByteCount: 1_024,
            maximumLookupQueryByteCount: 1_024,
            maximumLookupOutputCount: 16,
            maximumLookupOutputBEEFByteCount: 1_024,
            maximumFreeformByteCount: 1_024,
            maximumResolutionHostCount: maximumHosts
        )
    }
}

private enum ParityMockError: Error {
    case failed
}

private actor ParityLookupMock: LookupFacilitator {
    private let responses: [OverlayHost: LookupAnswer]

    init(responses: [OverlayHost: LookupAnswer]) {
        self.responses = responses
    }

    private var count = 0

    func lookup(question: LookupQuestion, at host: OverlayHost) async throws -> LookupAnswer {
        count += 1
        guard let answer = responses[host] else { throw ParityMockError.failed }
        return answer
    }

    func requestCount() -> Int { count }
}

private struct ParityResolverMock: OverlayLookupResolving {
    let answer: LookupAnswer

    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer { answer }
}

private actor ParityTopicMock: TopicFacilitator {
    private let steaks: [OverlayHost: Steak]
    private var sent: [OverlayHost: [OverlayTopic]] = [:]

    init(steaks: [OverlayHost: Steak]) {
        self.steaks = steaks
    }

    func submit(_ taggedBEEF: TaggedBEEF, to host: OverlayHost) async throws -> Steak {
        sent[host] = taggedBEEF.topics
        guard let steak = steaks[host] else { throw ParityMockError.failed }
        return steak
    }

    func topics(for host: OverlayHost) -> [OverlayTopic]? { sent[host] }
}
