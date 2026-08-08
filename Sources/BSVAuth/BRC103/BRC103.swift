import BSVCore
import BSVCrypto
import BSVKeys
import BSVWallet
import Foundation

/// Strict JSON codec for the bounded BRC-103 envelope.
public enum AuthMessageCodec {
    public static func encode(_ message: AuthMessage, limits: AuthLimits = .standard) throws
        -> [UInt8]
    {
        try validate(message, limits: limits)
        var object: [String: Any] = [
            "version": message.version, "messageType": message.messageType.rawValue,
            "identityKey": Hex.encode(message.identityKey.compressedBytes),
        ]
        if let nonce = message.nonce { object["nonce"] = nonce }
        if let initial = message.initialNonce { object["initialNonce"] = initial }
        if let yours = message.yourNonce { object["yourNonce"] = yours }
        // Empty Go-form request sets are read for interoperability but never emitted.
        if message.hasCertificates { object["certificates"] = [] }
        if message.hasRequestedCertificates {
            object["requestedCertificates"] = ["Certifiers": [], "CertificateTypes": [:]]
        }
        let baseData = try JSONSerialization.data(
            withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        var estimatedByteCount = baseData.count
        if let payload = message.payload {
            estimatedByteCount = try checkedJSONByteCount(
                estimatedByteCount,
                #","payload":"#.utf8.count,
                byteArrayJSONByteCount(payload),
                maximum: limits.maximumJSONBytes
            )
        }
        if let signature = message.signature {
            estimatedByteCount = try checkedJSONByteCount(
                estimatedByteCount,
                #","signature":"#.utf8.count,
                byteArrayJSONByteCount(signature),
                maximum: limits.maximumJSONBytes
            )
        }
        guard estimatedByteCount <= limits.maximumJSONBytes else {
            throw AuthError.resourceLimit
        }
        if let payload = message.payload { object["payload"] = payload.map(Int.init) }
        if let signature = message.signature { object["signature"] = signature.map(Int.init) }
        let data = try JSONSerialization.data(
            withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard data.count <= limits.maximumJSONBytes else { throw AuthError.resourceLimit }
        return [UInt8](data)
    }
    public static func decode(_ bytes: [UInt8], limits: AuthLimits = .standard) throws
        -> AuthMessage
    {
        guard bytes.count <= limits.maximumJSONBytes else { throw AuthError.resourceLimit }
        guard StrictAuthJSONPreflight.accepts(bytes),
            let object = try JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any]
        else { throw AuthError.invalidMessage }
        let permitted: Set<String> = [
            "version", "messageType", "identityKey", "nonce", "initialNonce", "yourNonce",
            "certificates",
            "requestedCertificates", "payload", "signature",
        ]
        guard Set(object.keys).isSubset(of: permitted), let version = object["version"] as? String,
            let rawType = object["messageType"] as? String,
            let type = AuthMessageType(rawValue: rawType),
            let textKey = object["identityKey"] as? String, textKey.utf8.count == 66,
            let keyBytes = try? Hex.decode(textKey, maximumDecodedByteCount: 33),
            Hex.encode(keyBytes) == textKey, let identity = try? PublicKey(keyBytes)
        else { throw AuthError.invalidMessage }
        func optionalString(_ name: String) throws -> String? {
            guard let value = object[name] else { return nil }
            guard let string = value as? String else { throw AuthError.invalidMessage }
            return string
        }
        func optionalBytes(_ name: String, maximum: Int) throws -> [UInt8]? {
            guard let value = object[name] else { return nil }
            guard let array = value as? [Any], array.count <= maximum else {
                throw AuthError.invalidMessage
            }
            var bytes: [UInt8] = []
            bytes.reserveCapacity(array.count)
            for item in array {
                guard !(item is Bool), let number = item as? NSNumber, number.doubleValue.isFinite,
                    number.doubleValue.rounded(.towardZero) == number.doubleValue,
                    number.doubleValue >= 0,
                    number.doubleValue <= 255
                else { throw AuthError.invalidMessage }
                bytes.append(UInt8(number.uint8Value))
            }
            return bytes
        }
        let certs = object["certificates"] != nil
        if certs {
            guard let values = object["certificates"] as? [Any], values.isEmpty else {
                throw AuthError.certificateExchangeUnavailable
            }
        }
        var requested = false
        if let request = object["requestedCertificates"] {
            guard let dictionary = request as? [String: Any],
                Set(dictionary.keys) == ["Certifiers", "CertificateTypes"]
                    || Set(dictionary.keys) == ["certifiers", "certificateTypes"]
            else { throw AuthError.invalidMessage }
            let certifiers = dictionary["Certifiers"] ?? dictionary["certifiers"]
            let types = dictionary["CertificateTypes"] ?? dictionary["certificateTypes"]
            let emptyCertifiers = certifiers is NSNull || (certifiers as? [Any])?.isEmpty == true
            let emptyTypes = types is NSNull || (types as? [String: Any])?.isEmpty == true
            guard emptyCertifiers && emptyTypes else {
                throw AuthError.certificateExchangeUnavailable
            }
            requested = true
        }
        let result = AuthMessage(
            version: version, messageType: type, identityKey: identity,
            nonce: try optionalString("nonce"), initialNonce: try optionalString("initialNonce"),
            yourNonce: try optionalString("yourNonce"),
            payload: try optionalBytes("payload", maximum: limits.maximumPayloadBytes),
            signature: try optionalBytes("signature", maximum: 72), hasCertificates: certs,
            hasRequestedCertificates: requested)
        try validate(result, limits: limits)
        return result
    }
    static func validate(_ message: AuthMessage, limits: AuthLimits) throws {
        guard message.version == "0.1", message.payload?.count ?? 0 <= limits.maximumPayloadBytes
        else {
            throw AuthError.invalidMessage
        }
        if let signature = message.signature {
            guard (8...72).contains(signature.count),
                (try? ECDSASignature(derBytes: signature)) != nil,
                lowS(signature)
            else { throw AuthError.invalidSignature }
        }
        switch message.messageType {
        case .initialRequest:
            guard message.initialNonce.map(validSessionNonce) == true, message.signature == nil,
                message.payload == nil
            else { throw AuthError.invalidMessage }
        case .initialResponse:
            guard message.nonce.map(validSessionNonce) == true,
                message.initialNonce.map(validSessionNonce) == true,
                message.initialNonce == message.nonce,
                message.yourNonce.map(validSessionNonce) == true, message.signature != nil
            else { throw AuthError.invalidMessage }
        case .general:
            guard message.nonce.map(validMessageNonce) == true,
                message.yourNonce.map(validSessionNonce) == true, message.payload != nil,
                message.signature != nil
            else { throw AuthError.invalidMessage }
        case .certificateRequest, .certificateResponse:
            throw AuthError.certificateExchangeUnavailable
        }
    }
    static func validSessionNonce(_ text: String) -> Bool {
        guard let bytes = try? Base64Encoding.decode(text, maximumDecodedByteCount: 48) else {
            return false
        }
        return (bytes.count == 32 || bytes.count == 48) && Base64Encoding.encode(bytes) == text
    }
    static func validMessageNonce(_ text: String) -> Bool {
        guard let bytes = try? Base64Encoding.decode(text, maximumDecodedByteCount: 32) else {
            return false
        }
        return bytes.count == 32 && Base64Encoding.encode(bytes) == text
    }
    static func lowS(_ der: [UInt8]) -> Bool {
        guard let signature = try? ECDSASignature(derBytes: der) else { return false }
        let s = Array(signature.compactBytes[32...])
        let half: [UInt8] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff,
            0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68,
            0x1b,
            0x20, 0xa0,
        ]
        for index in s.indices { if s[index] != half[index] { return s[index] < half[index] } }
        return true
    }

    private static func byteArrayJSONByteCount(_ bytes: [UInt8]) -> Int {
        guard !bytes.isEmpty else { return 2 }
        return 2 + bytes.count - 1
            + bytes.reduce(into: 0) { count, byte in
                count += byte < 10 ? 1 : byte < 100 ? 2 : 3
            }
    }

    private static func checkedJSONByteCount(
        _ values: Int...,
        maximum: Int
    ) throws -> Int {
        var total = 0
        for value in values {
            let (next, overflow) = total.addingReportingOverflow(value)
            guard !overflow, next <= maximum else { throw AuthError.resourceLimit }
            total = next
        }
        return total
    }
}

public actor PeerAuthenticator {
    private struct Session {
        var id: AuthSessionID
        var state: AuthSessionState
        var peer: PublicKey?
        var ownNonce: String
        var peerNonce: String?
        var deadline: ContinuousClock.Instant?
        var seen: Set<String> = []
        var messageCount = 0
    }
    private let wallet: any AuthenticationWallet
    private let limits: AuthLimits
    private let randomSource: any SecureRandomSource
    private let clock = ContinuousClock()
    private var sessions: [AuthSessionID: Session] = [:]
    private var inFlightNonces: Set<String> = []
    public init(
        wallet: any AuthenticationWallet, limits: AuthLimits = .standard,
        randomSource: any SecureRandomSource = SystemSecureRandomSource()
    ) {
        self.wallet = wallet
        self.limits = limits
        self.randomSource = randomSource
    }
    public func beginAuthentication(with expectedPeer: PublicKey? = nil) async throws -> (
        sessionID: AuthSessionID, actions: [AuthPeerAction]
    ) {
        try Task.checkCancellation()
        purgeExpired()
        try requireSessionCapacity(for: expectedPeer)
        let own = try await identity()
        try Task.checkCancellation()
        purgeExpired()
        try requireSessionCapacity(for: expectedPeer)
        let nonce = try makeUniqueNonce()
        let id = AuthSessionID()
        sessions[id] = .init(
            id: id, state: .challengeSent, peer: expectedPeer, ownNonce: nonce, peerNonce: nil,
            deadline: clock.now + limits.handshakeTimeout)
        return (
            id, [.send(.init(messageType: .initialRequest, identityKey: own, initialNonce: nonce))]
        )
    }
    public func receive(_ message: AuthMessage) async throws -> [AuthPeerAction] {
        try AuthMessageCodec.validate(message, limits: limits)
        purgeExpired()
        switch message.messageType {
        case .initialRequest: return try await receiveRequest(message)
        case .initialResponse: return try await receiveResponse(message)
        case .general: return try await receiveGeneral(message)
        case .certificateRequest, .certificateResponse:
            throw AuthError.certificateExchangeUnavailable
        }
    }
    public func makeGeneralMessage(payload: [UInt8], using sessionID: AuthSessionID) async throws
        -> AuthPeerAction
    {
        try Task.checkCancellation()
        purgeExpired()
        guard payload.count <= limits.maximumPayloadBytes, let session = sessions[sessionID],
            session.state == .authenticated, let peer = session.peer,
            let peerNonce = session.peerNonce
        else { throw AuthError.notAuthenticated }
        guard session.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        let nonce = try reserveUniqueNonce()
        defer { inFlightNonces.remove(nonce) }
        let own = try await identity()
        try Task.checkCancellation()
        let signature = try await sign(payload, keyID: nonce + " " + peerNonce, peer: peer)
        try Task.checkCancellation()
        guard var current = sessions[sessionID], current.state == .authenticated,
            current.peer == peer, current.peerNonce == peerNonce
        else { throw AuthError.sessionNotFound }
        guard current.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        current.messageCount += 1
        current.seen.insert(nonce)
        sessions[sessionID] = current
        return .send(
            .init(
                messageType: .general, identityKey: own, nonce: nonce, yourNonce: peerNonce,
                payload: payload, signature: signature))
    }
    public func session(_ id: AuthSessionID) -> AuthSessionSnapshot? {
        guard let s = sessions[id] else { return nil }
        return .init(id: id, state: s.state, peer: s.peer, sessionNonce: s.ownNonce)
    }
    public func close(_ id: AuthSessionID) { sessions.removeValue(forKey: id) }

    private func receiveRequest(_ message: AuthMessage) async throws -> [AuthPeerAction] {
        try Task.checkCancellation()
        guard let incoming = message.initialNonce else { throw AuthError.invalidNonce }
        try requireSessionCapacity(for: message.identityKey)
        let own = try await identity()
        try Task.checkCancellation()
        purgeExpired()
        try reserve(new: incoming, peer: message.identityKey)
        try requireSessionCapacity(for: message.identityKey)
        let ownNonce = try makeUniqueNonce(excluding: [incoming])
        let id = AuthSessionID()
        sessions[id] = .init(
            id: id, state: .responseSentAwaitingPeerProof, peer: message.identityKey,
            ownNonce: ownNonce,
            peerNonce: incoming, deadline: clock.now + limits.handshakeTimeout, seen: [incoming])
        let signature: [UInt8]
        do {
            signature = try await sign(
                (try nonceBytes(incoming)) + (try nonceBytes(ownNonce)),
                keyID: ownNonce + " " + incoming,
                peer: message.identityKey)
            try Task.checkCancellation()
        } catch {
            sessions.removeValue(forKey: id)
            throw error
        }
        return [
            .send(
                .init(
                    messageType: .initialResponse, identityKey: own, nonce: ownNonce,
                    initialNonce: ownNonce,
                    yourNonce: incoming, signature: signature))
        ]
    }
    private func receiveResponse(_ message: AuthMessage) async throws -> [AuthPeerAction] {
        try Task.checkCancellation()
        guard let ownNonce = message.yourNonce, let peerNonce = message.nonce,
            message.initialNonce == peerNonce, let signature = message.signature,
            let candidate = sessions.first(where: {
                $0.value.state == .challengeSent && $0.value.ownNonce == ownNonce
            })
        else { throw AuthError.sessionNotFound }
        let index = candidate.key
        guard candidate.value.peer == nil || candidate.value.peer == message.identityKey else {
            throw AuthError.peerMismatch
        }
        guard
            try await verify(
                signature, data: (try nonceBytes(ownNonce)) + (try nonceBytes(peerNonce)),
                keyID: peerNonce + " " + ownNonce, peer: message.identityKey)
        else { throw AuthError.invalidSignature }
        try Task.checkCancellation()
        guard var session = sessions[index], session.state == .challengeSent,
            session.ownNonce == ownNonce,
            session.peer == nil || session.peer == message.identityKey
        else { throw AuthError.sessionNotFound }
        session.peer = message.identityKey
        session.peerNonce = peerNonce
        session.state = .authenticated
        session.deadline = nil
        session.seen.insert(peerNonce)
        sessions[index] = session
        return []
    }
    private func receiveGeneral(_ message: AuthMessage) async throws -> [AuthPeerAction] {
        try Task.checkCancellation()
        guard let target = message.yourNonce, let nonce = message.nonce,
            let payload = message.payload,
            let signature = message.signature,
            let index = sessions.first(where: {
                $0.value.ownNonce == target && $0.value.peer == message.identityKey
            })?.key, let session = sessions[index], session.peerNonce != nil
        else { throw AuthError.sessionNotFound }
        guard !session.seen.contains(nonce) else { throw AuthError.replay }
        guard inFlightNonces.insert(nonce).inserted else { throw AuthError.replay }
        defer { inFlightNonces.remove(nonce) }
        guard
            try await verify(
                signature, data: payload, keyID: nonce + " " + target, peer: message.identityKey)
        else { throw AuthError.invalidSignature }
        try Task.checkCancellation()
        guard var current = sessions[index], current.ownNonce == target,
            current.peer == message.identityKey, !current.seen.contains(nonce)
        else { throw AuthError.replay }
        guard current.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: index)
            throw AuthError.resourceLimit
        }
        current.messageCount += 1
        current.seen.insert(nonce)
        // An unsigned initial request only establishes a pending session. The first signed general proof authenticates the responder.
        if current.state == .responseSentAwaitingPeerProof {
            current.state = .authenticated
            current.deadline = nil
        }
        guard current.state == .authenticated else { throw AuthError.notAuthenticated }
        sessions[index] = current
        return [.deliver(.init(sessionID: index, peer: message.identityKey, payload: payload))]
    }
    private func reserve(new nonce: String, peer: PublicKey) throws {
        if nonceIsInUse(nonce) {
            throw AuthError.replay
        }
        if sessions.values.filter({ $0.peer == peer }).count >= limits.maximumSessionsPerIdentity {
            throw AuthError.resourceLimit
        }
    }
    private func requireSessionCapacity(for peer: PublicKey?) throws {
        guard sessions.count < limits.maximumSessions,
            sessions.values.filter({ $0.peer == nil }).count < limits.maximumPendingSessions
        else { throw AuthError.resourceLimit }
        if let peer,
            sessions.values.filter({ $0.peer == peer }).count >= limits.maximumSessionsPerIdentity
        {
            throw AuthError.resourceLimit
        }
    }
    private func purgeExpired() {
        let now = clock.now
        let expired = sessions.filter { $0.value.deadline.map { $0 <= now } ?? false }.map(\.key)
        for id in expired { sessions.removeValue(forKey: id) }
    }
    private func makeUniqueNonce(excluding: Set<String> = []) throws -> String {
        for _ in 0..<4 {
            let nonce = try makeNonce()
            if !excluding.contains(nonce), !nonceIsInUse(nonce) { return nonce }
        }
        throw AuthError.randomGenerationFailed
    }
    private func reserveUniqueNonce(excluding: Set<String> = []) throws -> String {
        let nonce = try makeUniqueNonce(excluding: excluding)
        inFlightNonces.insert(nonce)
        return nonce
    }
    private func nonceIsInUse(_ nonce: String) -> Bool {
        inFlightNonces.contains(nonce)
            || sessions.values.contains {
                $0.ownNonce == nonce || $0.peerNonce == nonce || $0.seen.contains(nonce)
            }
    }
    private func makeNonce() throws -> String {
        do {
            let bytes = try randomSource.randomBytes(count: 32)
            guard bytes.count == 32 else { throw AuthError.randomGenerationFailed }
            return Base64Encoding.encode(bytes)
        } catch { throw AuthError.randomGenerationFailed }
    }
    private func nonceBytes(_ text: String) throws -> [UInt8] {
        guard let data = try? Base64Encoding.decode(text, maximumDecodedByteCount: 48),
            data.count == 32 || data.count == 48, Base64Encoding.encode(data) == text
        else { throw AuthError.invalidNonce }
        return data
    }
    private func identity() async throws -> PublicKey {
        try await wallet.getPublicKey(.init(selection: .identity)).publicKey
    }
    private func sign(_ data: [UInt8], keyID: String, peer: PublicKey) async throws -> [UInt8] {
        let result = try await wallet.createSignature(
            .init(
                protocolID: try authProtocol(), keyID: try WalletKeyID(keyID),
                counterparty: .publicKey(peer), payload: .data(data)))
        return result.signature.derBytes
    }
    private func verify(_ signature: [UInt8], data: [UInt8], keyID: String, peer: PublicKey)
        async throws -> Bool
    {
        guard let parsed = try? ECDSASignature(derBytes: signature),
            AuthMessageCodec.lowS(signature)
        else { return false }
        return try await wallet.verifySignature(
            .init(
                protocolID: try authProtocol(), keyID: try WalletKeyID(keyID),
                counterparty: .publicKey(peer), payload: .data(data), signature: parsed)
        ).valid
    }
    private func authProtocol() throws -> WalletProtocolID {
        try .init(securityLevel: .everyAppAndCounterparty, name: "auth message signature")
    }
}
