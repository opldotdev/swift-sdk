import BSVCore
import BSVCrypto
import BSVKeys
import BSVWallet
import CoreFoundation
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
        if let certificates = message.certificates {
            _ = try AuthCertificateJSON.response(certificates, limits: limits)
            object["certificates"] = try certificateObjects(certificates, limits: limits)
        }
        if let requested = message.requestedCertificates {
            _ = try AuthCertificateJSON.request(requested, limits: limits)
            object["requestedCertificates"] = try requestedCertificateObject(
                requested,
                limits: limits
            )
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
                guard let number = item as? NSNumber,
                    CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite,
                    number.doubleValue.rounded(.towardZero) == number.doubleValue,
                    number.doubleValue >= 0,
                    number.doubleValue <= 255
                else { throw AuthError.invalidMessage }
                bytes.append(UInt8(number.uint8Value))
            }
            return bytes
        }
        let certificates = try decodeCertificates(object["certificates"], limits: limits)
        let requested = try decodeRequestedCertificates(
            object["requestedCertificates"],
            limits: limits
        )
        let result = AuthMessage(
            version: version, messageType: type, identityKey: identity,
            nonce: try optionalString("nonce"), initialNonce: try optionalString("initialNonce"),
            yourNonce: try optionalString("yourNonce"),
            payload: try optionalBytes("payload", maximum: limits.maximumPayloadBytes),
            signature: try optionalBytes("signature", maximum: 72),
            certificates: certificates,
            requestedCertificates: requested)
        try validate(result, limits: limits)
        return result
    }
    static func validate(_ message: AuthMessage, limits: AuthLimits) throws {
        guard message.version == "0.1", message.payload?.count ?? 0 <= limits.maximumPayloadBytes,
            message.certificates?.count ?? 0 <= limits.maximumCertificateCount
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
                message.nonce == nil, message.yourNonce == nil, message.payload == nil,
                message.certificates == nil, message.requestedCertificates == nil
            else { throw AuthError.invalidMessage }
        case .initialResponse:
            // The responder's own nonce travels as `initialNonce`; `nonce` is not sent. The
            // TypeScript reference builds this message with `initialNonce`, `yourNonce`,
            // `certificates` and `requestedCertificates`, and no `nonce` at all — so requiring
            // one rejects every conforming peer. When a sender does include it, it names the same
            // nonce and must agree.
            guard message.initialNonce.map(validSessionNonce) == true,
                message.nonce == nil || message.nonce == message.initialNonce,
                message.yourNonce.map(validSessionNonce) == true, message.signature != nil,
                message.payload == nil
            else { throw AuthError.invalidMessage }
        case .general:
            guard message.nonce.map(validMessageNonce) == true,
                message.yourNonce.map(validSessionNonce) == true, message.payload != nil,
                message.signature != nil, message.initialNonce == nil,
                message.certificates == nil, message.requestedCertificates == nil
            else { throw AuthError.invalidMessage }
        case .certificateRequest:
            guard message.nonce.map(validMessageNonce) == true,
                message.yourNonce.map(validSessionNonce) == true,
                message.requestedCertificates != nil, message.certificates == nil,
                message.initialNonce == nil, message.payload == nil, message.signature != nil
            else { throw AuthError.invalidMessage }
        case .certificateResponse:
            guard message.nonce.map(validMessageNonce) == true,
                message.yourNonce.map(validSessionNonce) == true,
                message.certificates?.isEmpty == false, message.requestedCertificates == nil,
                message.initialNonce == nil, message.payload == nil, message.signature != nil
            else { throw AuthError.invalidMessage }
        }
    }

    package static func certificateRequestSigningBytes(
        _ request: AuthRequestedCertificateSet,
        limits: AuthLimits
    ) throws -> [UInt8] {
        try AuthCertificateJSON.request(request, limits: limits)
    }

    package static func certificateResponseSigningBytes(
        _ certificates: [VerifiableCertificate],
        limits: AuthLimits
    ) throws -> [UInt8] {
        try AuthCertificateJSON.response(certificates, limits: limits)
    }

    static func requestedCertificateObject(
        _ request: AuthRequestedCertificateSet,
        limits: AuthLimits
    ) throws -> [String: Any] {
        _ = try AuthRequestedCertificateSet(
            certifiers: request.certifiers,
            certificateTypes: request.certificateTypes,
            limits: limits
        )
        var types: [String: [String]] = [:]
        for (type, fields) in request.certificateTypes {
            types[type.base64] = fields.map(\.value)
        }
        return [
            "certifiers": request.certifiers.map { Hex.encode($0.compressedBytes) },
            "types": types,
        ]
    }

    static func decodeRequestedCertificates(
        _ value: Any?,
        limits: AuthLimits
    ) throws -> AuthRequestedCertificateSet? {
        guard let value else { return nil }
        guard let object = value as? [String: Any],
            Set(object.keys) == ["certifiers", "types"]
        else { throw AuthError.invalidCertificateRequest }
        let rawCertifiers = object["certifiers"]
        let rawTypes = object["types"]

        if rawCertifiers is NSNull || (rawCertifiers as? [Any])?.isEmpty == true,
            rawTypes is NSNull || (rawTypes as? [String: Any])?.isEmpty == true
        {
            return nil
        }
        guard let certifierValues = rawCertifiers as? [Any],
            certifierValues.count <= limits.maximumCertificateCertifierCount,
            let typeValues = rawTypes as? [String: Any],
            typeValues.count <= limits.maximumCertificateTypeCount
        else { throw AuthError.invalidCertificateRequest }

        var certifiers: [PublicKey] = []
        certifiers.reserveCapacity(certifierValues.count)
        for value in certifierValues {
            guard let text = value as? String,
                let bytes = try? Hex.decode(text, maximumDecodedByteCount: 33),
                bytes.count == 33, Hex.encode(bytes) == text,
                let key = try? PublicKey(bytes)
            else { throw AuthError.invalidCertificateRequest }
            certifiers.append(key)
        }

        var types: [CertificateTypeID: [CertificateFieldName]] = [:]
        for (typeText, rawFields) in typeValues {
            guard let type = try? CertificateTypeID(base64: typeText),
                let fieldValues = rawFields as? [Any],
                fieldValues.count <= limits.maximumCertificateFieldCount
            else { throw AuthError.invalidCertificateRequest }
            var fields: [CertificateFieldName] = []
            fields.reserveCapacity(fieldValues.count)
            for rawField in fieldValues {
                guard let text = rawField as? String,
                    let field = try? CertificateFieldName(
                        text,
                        limits: limits.certificateLimits
                    )
                else { throw AuthError.invalidCertificateRequest }
                fields.append(field)
            }
            guard types[type] == nil else { throw AuthError.invalidCertificateRequest }
            types[type] = fields
        }
        return try AuthRequestedCertificateSet(
            certifiers: certifiers,
            certificateTypes: types,
            limits: limits
        )
    }

    private static func certificateObjects(
        _ certificates: [VerifiableCertificate],
        limits: AuthLimits
    ) throws -> [[String: Any]] {
        guard !certificates.isEmpty,
            certificates.count <= limits.maximumCertificateCount
        else { throw AuthError.certificateValidationFailed }
        var result: [[String: Any]] = []
        result.reserveCapacity(certificates.count)
        var aggregate = 0
        for verifiable in certificates {
            let certificate = verifiable.certificate
            guard let signature = certificate.signature else {
                throw AuthError.certificateValidationFailed
            }
            let binary = try verifiable.binary(limits: limits.certificateLimits)
            let (next, overflow) = aggregate.addingReportingOverflow(binary.count)
            guard !overflow, next <= limits.maximumCertificateAggregateBytes else {
                throw AuthError.resourceLimit
            }
            aggregate = next
            var fields: [String: String] = [:]
            for (name, value) in certificate.fields { fields[name.value] = value.base64 }
            var keyring: [String: String] = [:]
            for (name, value) in verifiable.keyring.entries { keyring[name.value] = value.base64 }
            result.append([
                "type": certificate.type.base64,
                "serialNumber": certificate.serialNumber.base64,
                "subject": Hex.encode(certificate.subject.compressedBytes),
                "certifier": Hex.encode(certificate.certifier.compressedBytes),
                "revocationOutpoint": certificate.revocationOutpoint.description,
                "fields": fields,
                "signature": Hex.encode(signature.derBytes),
                "keyring": keyring,
            ])
        }
        return result
    }

    private static func decodeCertificates(
        _ value: Any?,
        limits: AuthLimits
    ) throws -> [VerifiableCertificate]? {
        guard let value else { return nil }
        guard let values = value as? [Any],
            values.count <= limits.maximumCertificateCount
        else { throw AuthError.certificateValidationFailed }
        if values.isEmpty { return nil }

        var result: [VerifiableCertificate] = []
        result.reserveCapacity(values.count)
        var aggregate = 0
        for rawValue in values {
            guard var object = rawValue as? [String: Any],
                Set(object.keys) == [
                    "type", "serialNumber", "subject", "certifier", "revocationOutpoint",
                    "fields", "signature", "keyring",
                ],
                let rawKeyring = object.removeValue(forKey: "keyring") as? [String: Any]
            else { throw AuthError.certificateValidationFailed }

            let certificateData = try JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
            let certificate: Certificate
            do {
                certificate = try Certificate(
                    json: certificateData,
                    limits: limits.certificateLimits
                )
            } catch {
                throw AuthError.certificateValidationFailed
            }
            guard certificate.signature != nil,
                rawKeyring.count <= limits.maximumCertificateFieldCount
            else { throw AuthError.certificateValidationFailed }
            var entries: [CertificateFieldName: CertificateCiphertext] = [:]
            for (nameText, rawCiphertext) in rawKeyring {
                guard let ciphertextText = rawCiphertext as? String,
                    let name = try? CertificateFieldName(
                        nameText,
                        limits: limits.certificateLimits
                    ),
                    let ciphertext = try? CertificateCiphertext(
                        base64: ciphertextText,
                        maximumByteCount: limits.certificateLimits.maximumKeyringCiphertextByteCount
                    )
                else { throw AuthError.certificateValidationFailed }
                guard entries[name] == nil else { throw AuthError.certificateValidationFailed }
                entries[name] = ciphertext
            }
            let verifiable = try VerifiableCertificate(
                certificate: certificate,
                keyring: CertificateKeyring(entries, limits: limits.certificateLimits)
            )
            let binary = try verifiable.binary(limits: limits.certificateLimits)
            let (next, overflow) = aggregate.addingReportingOverflow(binary.count)
            guard !overflow, next <= limits.maximumCertificateAggregateBytes else {
                throw AuthError.resourceLimit
            }
            aggregate = next
            result.append(verifiable)
        }
        return result
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
        var pendingCertificateRequest: AuthRequestedCertificateSet?
        var receivedCertificateRequest: AuthRequestedCertificateSet?
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
        case .certificateRequest: return try await receiveCertificateRequest(message)
        case .certificateResponse: return try await receiveCertificateResponse(message)
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
    public func makeCertificateRequest(
        _ request: AuthRequestedCertificateSet,
        using sessionID: AuthSessionID
    ) async throws -> AuthPeerAction {
        try Task.checkCancellation()
        purgeExpired()
        guard let session = sessions[sessionID], session.state == .authenticated,
            let peer = session.peer, let peerNonce = session.peerNonce
        else { throw AuthError.notAuthenticated }
        guard session.pendingCertificateRequest == nil else {
            throw AuthError.unexpectedMessage
        }
        guard session.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        let data = try AuthMessageCodec.certificateRequestSigningBytes(request, limits: limits)
        let nonce = try reserveUniqueNonce()
        defer { inFlightNonces.remove(nonce) }
        let own = try await identity()
        try Task.checkCancellation()
        let signature = try await sign(data, keyID: nonce + " " + peerNonce, peer: peer)
        try Task.checkCancellation()
        guard var current = sessions[sessionID], current.state == .authenticated,
            current.peer == peer, current.peerNonce == peerNonce,
            current.pendingCertificateRequest == nil
        else { throw AuthError.sessionNotFound }
        guard current.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        current.messageCount += 1
        current.seen.insert(nonce)
        current.pendingCertificateRequest = request
        sessions[sessionID] = current
        return .send(
            AuthMessage(
                messageType: .certificateRequest,
                identityKey: own,
                nonce: nonce,
                yourNonce: peerNonce,
                signature: signature,
                requestedCertificates: request
            )
        )
    }

    public func makeCertificateResponse(
        _ certificates: [VerifiableCertificate],
        using sessionID: AuthSessionID
    ) async throws -> AuthPeerAction {
        try Task.checkCancellation()
        purgeExpired()
        guard let session = sessions[sessionID], session.state == .authenticated,
            let peer = session.peer, let peerNonce = session.peerNonce,
            let request = session.receivedCertificateRequest
        else { throw AuthError.notAuthenticated }
        guard session.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        let data = try AuthMessageCodec.certificateResponseSigningBytes(
            certificates,
            limits: limits
        )
        let nonce = try reserveUniqueNonce()
        defer { inFlightNonces.remove(nonce) }
        let own = try await identity()
        try Task.checkCancellation()
        try requireCertificateMatch(certificates, request: request, peer: own)
        let signature = try await sign(data, keyID: nonce + " " + peerNonce, peer: peer)
        try Task.checkCancellation()
        guard var current = sessions[sessionID], current.state == .authenticated,
            current.peer == peer, current.peerNonce == peerNonce,
            current.receivedCertificateRequest == request
        else { throw AuthError.sessionNotFound }
        guard current.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        current.messageCount += 1
        current.seen.insert(nonce)
        current.receivedCertificateRequest = nil
        sessions[sessionID] = current
        return .send(
            AuthMessage(
                messageType: .certificateResponse,
                identityKey: own,
                nonce: nonce,
                yourNonce: peerNonce,
                signature: signature,
                certificates: certificates
            )
        )
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
        return [
            .deliver(.init(sessionID: index, peer: message.identityKey, payload: payload))
        ]
    }

    private func receiveCertificateRequest(_ message: AuthMessage) async throws
        -> [AuthPeerAction]
    {
        try Task.checkCancellation()
        guard let target = message.yourNonce, let nonce = message.nonce,
            let request = message.requestedCertificates, let signature = message.signature,
            let index = authenticatedSessionIndex(target: target, peer: message.identityKey),
            let session = sessions[index]
        else { throw AuthError.sessionNotFound }
        guard !session.seen.contains(nonce) else { throw AuthError.replay }
        guard inFlightNonces.insert(nonce).inserted else { throw AuthError.replay }
        defer { inFlightNonces.remove(nonce) }
        let data = try AuthMessageCodec.certificateRequestSigningBytes(request, limits: limits)
        guard
            try await verify(
                signature,
                data: data,
                keyID: nonce + " " + target,
                peer: message.identityKey
            )
        else { throw AuthError.invalidSignature }
        try Task.checkCancellation()
        guard var current = sessions[index], current.state == .authenticated,
            current.ownNonce == target, current.peer == message.identityKey,
            !current.seen.contains(nonce)
        else { throw AuthError.replay }
        guard current.receivedCertificateRequest == nil else {
            throw AuthError.unexpectedMessage
        }
        try consumeMessage(on: index, session: &current)
        current.seen.insert(nonce)
        current.receivedCertificateRequest = request
        sessions[index] = current
        return [
            .certificateRequest(
                .init(sessionID: index, peer: message.identityKey, request: request)
            )
        ]
    }

    private func receiveCertificateResponse(_ message: AuthMessage) async throws
        -> [AuthPeerAction]
    {
        try Task.checkCancellation()
        guard let target = message.yourNonce, let nonce = message.nonce,
            let certificates = message.certificates, let signature = message.signature,
            let index = authenticatedSessionIndex(target: target, peer: message.identityKey),
            let session = sessions[index]
        else { throw AuthError.sessionNotFound }
        guard !session.seen.contains(nonce) else { throw AuthError.replay }
        guard let request = session.pendingCertificateRequest else {
            throw AuthError.unexpectedMessage
        }
        try requireCertificateMatch(certificates, request: request, peer: message.identityKey)
        guard inFlightNonces.insert(nonce).inserted else { throw AuthError.replay }
        defer { inFlightNonces.remove(nonce) }
        let data = try AuthMessageCodec.certificateResponseSigningBytes(
            certificates,
            limits: limits
        )
        guard
            try await verify(
                signature,
                data: data,
                keyID: nonce + " " + target,
                peer: message.identityKey
            )
        else { throw AuthError.invalidSignature }
        try Task.checkCancellation()
        guard var current = sessions[index], current.state == .authenticated,
            current.ownNonce == target, current.peer == message.identityKey,
            !current.seen.contains(nonce), current.pendingCertificateRequest == request
        else { throw AuthError.replay }
        try consumeMessage(on: index, session: &current)
        current.seen.insert(nonce)
        current.pendingCertificateRequest = nil
        sessions[index] = current
        return [
            .certificateResponse(
                .init(
                    sessionID: index,
                    peer: message.identityKey,
                    requested: request,
                    certificates: certificates
                )
            )
        ]
    }

    private func authenticatedSessionIndex(target: String, peer: PublicKey) -> AuthSessionID? {
        sessions.first {
            $0.value.ownNonce == target && $0.value.peer == peer
                && $0.value.state == .authenticated
        }?.key
    }

    private func consumeMessage(on id: AuthSessionID, session: inout Session) throws {
        guard session.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: id)
            throw AuthError.resourceLimit
        }
        session.messageCount += 1
    }

    private func requireCertificateMatch(
        _ certificates: [VerifiableCertificate],
        request: AuthRequestedCertificateSet,
        peer: PublicKey
    ) throws {
        guard !certificates.isEmpty,
            certificates.count <= limits.maximumCertificateCount
        else { throw AuthError.certificateValidationFailed }
        var foundTypes = Set<CertificateTypeID>()
        for verifiable in certificates {
            let certificate = verifiable.certificate
            guard certificate.subject == peer,
                request.certifiers.contains(certificate.certifier),
                let fields = request.certificateTypes[certificate.type],
                Set(verifiable.keyring.entries.keys) == Set(fields)
            else { throw AuthError.certificateValidationFailed }
            foundTypes.insert(certificate.type)
        }
        guard foundTypes == Set(request.certificateTypes.keys) else {
            throw AuthError.certificateValidationFailed
        }
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
