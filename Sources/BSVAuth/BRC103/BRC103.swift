import BSVCore
import BSVCrypto
import BSVKeys
import BSVWallet
import CoreFoundation
import Foundation

/// Strict JSON codec for the bounded BRC-103 envelope.
public enum AuthMessageCodec {
    /// Writes the envelope by hand. Certificate members are written from the
    /// exact bytes their signatures cover, because a TypeScript verifier signs
    /// `JSON.stringify` of the parsed members in wire order (`Peer.ts:1070`,
    /// `Peer.ts:1205`). Foundation's `.sortedKeys` order is not byte order, so
    /// it cannot be used for these members.
    public static func encode(_ message: AuthMessage, limits: AuthLimits = .standard) throws
        -> [UInt8]
    {
        try validate(message, limits: limits)
        var estimatedByteCount = 0
        if let payload = message.payload {
            estimatedByteCount = try checkedJSONByteCount(
                estimatedByteCount, #","payload":"#.utf8.count, byteArrayJSONByteCount(payload),
                maximum: limits.maximumJSONBytes)
        }
        if let signature = message.signature {
            estimatedByteCount = try checkedJSONByteCount(
                estimatedByteCount, #","signature":"#.utf8.count,
                byteArrayJSONByteCount(signature), maximum: limits.maximumJSONBytes)
        }
        var writer = AuthJSONWriter(maximumByteCount: limits.maximumJSONBytes)
        try writer.append(#"{"version":"#)
        try writer.appendString(message.version)
        try writer.append(#","messageType":"#)
        try writer.appendString(message.messageType.rawValue)
        try writer.append(#","identityKey":"#)
        try writer.appendString(Hex.encode(message.identityKey.compressedBytes))
        for (name, value) in [
            ("nonce", message.nonce), ("initialNonce", message.initialNonce),
            ("yourNonce", message.yourNonce),
        ] {
            guard let value else { continue }
            try writer.append(",")
            try writer.appendString(name)
            try writer.append(":")
            try writer.appendString(value)
        }
        if let certificates = message.certificates {
            try writer.append(#","certificates":"#)
            try writer.append(AuthCertificateJSON.response(certificates, limits: limits))
        }
        if let requested = message.requestedCertificates {
            try writer.append(#","requestedCertificates":"#)
            try writer.append(AuthCertificateJSON.request(requested, limits: limits))
        }
        _ = try checkedJSONByteCount(
            writer.bytes.count, estimatedByteCount, 1, maximum: limits.maximumJSONBytes)
        if let payload = message.payload {
            try writer.append(#","payload":"#)
            try writer.append(byteArrayJSON(payload))
        }
        if let signature = message.signature {
            try writer.append(#","signature":"#)
            try writer.append(byteArrayJSON(signature))
        }
        try writer.append("}")
        return writer.bytes
    }
    /// Decodes a message and keeps the bytes its signature covers. Encoding
    /// the result writes members in this SDK's order, which can differ from
    /// the sender's, so a relay must forward the received bytes rather than
    /// re-encode a decoded certificate message.
    public static func decode(_ bytes: [UInt8], limits: AuthLimits = .standard) throws
        -> AuthMessage
    {
        guard bytes.count <= limits.maximumJSONBytes else { throw AuthError.resourceLimit }
        let retained = try AuthJSONParser.parseEnvelope(
            bytes, retaining: ["certificates", "requestedCertificates"])
        guard let object = try JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any]
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
        let certificates = try decodeCertificates(retained["certificates"], limits: limits)
        let requested = try decodeRequestedCertificates(
            retained["requestedCertificates"],
            limits: limits
        )
        var signingBytes: [UInt8]?
        switch type {
        case .certificateRequest:
            if let value = retained["requestedCertificates"], requested != nil {
                signingBytes = try AuthCertificateJSON.receivedRequest(value, limits: limits)
            }
        case .certificateResponse:
            if let value = retained["certificates"], certificates != nil {
                signingBytes = try AuthCertificateJSON.receivedResponse(value, limits: limits)
            }
        default:
            break
        }
        let result = AuthMessage(
            version: version, messageType: type, identityKey: identity,
            nonce: try optionalString("nonce"), initialNonce: try optionalString("initialNonce"),
            yourNonce: try optionalString("yourNonce"),
            payload: try optionalBytes("payload", maximum: limits.maximumPayloadBytes),
            signature: try optionalBytes("signature", maximum: 72),
            certificates: certificates,
            requestedCertificates: requested,
            receivedSigningBytes: signingBytes)
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
        let noCertificates = message.certificates?.isEmpty ?? true
        switch message.messageType {
        case .initialRequest:
            // `@bsv/sdk` sends its handshake certificate policy here
            // (`Peer.ts:635-641`). It is unsigned; it is surfaced to the caller
            // as a request and never trusted.
            guard message.initialNonce.map(validSessionNonce) == true, message.signature == nil,
                message.nonce == nil, message.yourNonce == nil, message.payload == nil,
                noCertificates
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
                noCertificates
            else { throw AuthError.invalidMessage }
        case .certificateRequest:
            // `initialNonce` is the sender's own session nonce and is required
            // (`AuthMessageValidation.ts:404`, sent at `Peer.ts:467`).
            guard message.nonce.map(validMessageNonce) == true,
                message.initialNonce.map(validSessionNonce) == true,
                message.yourNonce.map(validSessionNonce) == true,
                message.requestedCertificates != nil, noCertificates,
                message.payload == nil, message.signature != nil
            else { throw AuthError.invalidMessage }
        case .certificateResponse:
            // An empty list is a valid answer (`AuthMessageValidation.ts:417`,
            // sent at `Peer.ts:1117`). `initialNonce` is required
            // (`AuthMessageValidation.ts:415`, sent at `Peer.ts:1156`).
            guard message.nonce.map(validMessageNonce) == true,
                message.initialNonce.map(validSessionNonce) == true,
                message.yourNonce.map(validSessionNonce) == true,
                message.certificates != nil, message.requestedCertificates == nil,
                message.payload == nil, message.signature != nil
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

    static func decodeRequestedCertificates(
        _ value: AuthJSONValue?,
        limits: AuthLimits
    ) throws -> AuthRequestedCertificateSet? {
        guard let value else { return nil }
        guard case .object(let members) = value,
            Set(members.map(\.key)) == ["certifiers", "types"],
            let rawCertifiers = value["certifiers"], let rawTypes = value["types"]
        else { throw AuthError.invalidCertificateRequest }

        func isEmptyOrNull(_ value: AuthJSONValue) -> Bool {
            switch value {
            case .null: return true
            case .array(let items): return items.isEmpty
            case .object(let items): return items.isEmpty
            default: return false
            }
        }
        // `null` certifiers with no types is the empty set Go writes into
        // every message. `@bsv/sdk` writes `{"certifiers":[],"types":{}}`,
        // which is kept: it is signed text in a certificateRequest.
        if case .null = rawCertifiers, isEmptyOrNull(rawTypes) { return nil }
        guard case .array(let certifierValues) = rawCertifiers,
            certifierValues.count <= limits.maximumCertificateCertifierCount,
            case .object(let typeValues) = rawTypes,
            typeValues.count <= limits.maximumCertificateTypeCount
        else { throw AuthError.invalidCertificateRequest }

        var certifiers: [PublicKey] = []
        certifiers.reserveCapacity(certifierValues.count)
        for value in certifierValues {
            guard case .string(let text) = value,
                let bytes = try? Hex.decode(text, maximumDecodedByteCount: 33),
                bytes.count == 33, Hex.encode(bytes) == text,
                let key = try? PublicKey(bytes)
            else { throw AuthError.invalidCertificateRequest }
            certifiers.append(key)
        }

        var types: [CertificateTypeID: [CertificateFieldName]] = [:]
        for member in typeValues {
            guard let type = try? CertificateTypeID(base64: member.key),
                case .array(let fieldValues) = member.value,
                fieldValues.count <= limits.maximumCertificateFieldCount
            else { throw AuthError.invalidCertificateRequest }
            var fields: [CertificateFieldName] = []
            fields.reserveCapacity(fieldValues.count)
            for rawField in fieldValues {
                guard case .string(let text) = rawField,
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

    private static func decodeCertificates(
        _ value: AuthJSONValue?,
        limits: AuthLimits
    ) throws -> [VerifiableCertificate]? {
        guard let value else { return nil }
        guard case .array(let values) = value,
            values.count <= limits.maximumCertificateCount
        else { throw AuthError.certificateValidationFailed }

        var result: [VerifiableCertificate] = []
        result.reserveCapacity(values.count)
        var aggregate = 0
        for rawValue in values {
            guard case .object(let members) = rawValue,
                Set(members.map(\.key)) == Set(AuthCertificateJSON.certificateMemberOrder),
                case .object(let rawKeyring)? = rawValue["keyring"]
            else { throw AuthError.certificateValidationFailed }

            let certificate: Certificate
            do {
                var writer = AuthJSONWriter(maximumByteCount: limits.maximumJSONBytes)
                try writer.appendValue(.object(members.filter { $0.key != "keyring" }))
                certificate = try Certificate(
                    json: writer.bytes,
                    limits: limits.certificateLimits
                )
            } catch {
                AuthLog.reported(
                    "AuthMessageCodec.decode certificate", error,
                    as: AuthError.certificateValidationFailed)
                throw AuthError.certificateValidationFailed
            }
            guard certificate.signature != nil,
                rawKeyring.count <= limits.maximumCertificateFieldCount
            else { throw AuthError.certificateValidationFailed }
            var entries: [CertificateFieldName: CertificateCiphertext] = [:]
            for member in rawKeyring {
                guard case .string(let ciphertextText) = member.value,
                    let name = try? CertificateFieldName(
                        member.key,
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

    private static func byteArrayJSON(_ bytes: [UInt8]) -> [UInt8] {
        var output: [UInt8] = []
        output.reserveCapacity(byteArrayJSONByteCount(bytes))
        output.append(0x5b)
        for index in bytes.indices {
            if index > 0 { output.append(0x2c) }
            let byte = bytes[index]
            if byte >= 100 { output.append(0x30 + byte / 100) }
            if byte >= 10 { output.append(0x30 + (byte / 10) % 10) }
            output.append(0x30 + byte % 10)
        }
        output.append(0x5d)
        return output
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
        /// Requests this side sent with certificateRequest messages and has
        /// not had answered, oldest first.
        var pendingCertificateRequests: [AuthRequestedCertificateSet] = []
        /// The policy this side sent in initialRequest or initialResponse,
        /// until a response settles it. Responses are matched with it only
        /// after `pendingCertificateRequests`, as `Peer.ts:1236-1241` does.
        var pendingHandshakeRequest: AuthRequestedCertificateSet? = nil
        /// Requests the peer sent with certificateRequest messages and this
        /// side has not answered, oldest first.
        var receivedCertificateRequests: [AuthRequestedCertificateSet] = []
        /// The policy the peer sent in initialRequest or initialResponse,
        /// until this side answers it.
        var receivedHandshakeRequest: AuthRequestedCertificateSet? = nil
    }
    /// The most certificate requests a session keeps open in each direction.
    /// `@bsv/sdk` keeps any number (`Peer.ts:474-478`); a bound keeps one
    /// peer from growing a session without limit.
    static let maximumOpenCertificateRequests = 16
    private let wallet: any AuthenticationWallet
    private let limits: AuthLimits
    private let randomSource: any SecureRandomSource
    private let certificatesToRequest: AuthRequestedCertificateSet?
    private let clock = ContinuousClock()
    private var sessions: [AuthSessionID: Session] = [:]
    private var inFlightNonces: Set<String> = []
    /// Creates an authenticator.
    ///
    /// `certificatesToRequest` is this side's certificate policy, as the
    /// `Peer` constructor takes it (`Peer.ts:139-159`). It is sent in every
    /// `initialResponse` this side writes (`Peer.ts:867-876`), so a TypeScript
    /// `AuthFetch` client answers it with a certificateResponse
    /// (`clients/AuthFetch.ts:496-511`), and in `initialRequest` when
    /// `beginAuthentication` is given no other policy. A policy with
    /// certifiers is then awaited like a request sent with
    /// `makeCertificateRequest`.
    public init(
        wallet: any AuthenticationWallet, limits: AuthLimits = .standard,
        randomSource: any SecureRandomSource = SystemSecureRandomSource(),
        certificatesToRequest: AuthRequestedCertificateSet? = nil
    ) {
        self.wallet = wallet
        self.limits = limits
        self.randomSource = randomSource
        self.certificatesToRequest = certificatesToRequest
    }
    /// Starts a handshake.
    ///
    /// `requesting` puts a certificate policy into `initialRequest`, as
    /// `@bsv/sdk` does with `certificatesToRequest` (`Peer.ts:627-650`). When
    /// it is `nil`, the policy given to `init` is sent, if any. A
    /// peer may answer it with certificates in `initialResponse`; those
    /// surface as `.certificateResponse` once the handshake verifies. They
    /// are not covered by the response signature, so validate them with
    /// `AuthCertificateExchange.validate` before relying on them, as
    /// `Peer.ts:960-982` does.
    public func beginAuthentication(
        with expectedPeer: PublicKey? = nil,
        requesting request: AuthRequestedCertificateSet? = nil
    ) async throws -> (
        sessionID: AuthSessionID, actions: [AuthPeerAction]
    ) {
        let request = request ?? certificatesToRequest
        if let request { _ = try AuthMessageCodec.certificateRequestSigningBytes(request, limits: limits) }
        try Task.checkCancellation()
        purgeExpired()
        try requireSessionCapacity(for: expectedPeer)
        let own = try await identity()
        try Task.checkCancellation()
        purgeExpired()
        try requireSessionCapacity(for: expectedPeer)
        let nonce = try makeUniqueSessionNonce()
        let id = AuthSessionID()
        sessions[id] = .init(
            id: id, state: .challengeSent, peer: expectedPeer, ownNonce: nonce, peerNonce: nil,
            deadline: clock.now + limits.handshakeTimeout)
        sessions[id]?.pendingHandshakeRequest = Self.askingRequest(request)
        return (
            id,
            [
                .send(
                    .init(
                        messageType: .initialRequest, identityKey: own, initialNonce: nonce,
                        requestedCertificates: request))
            ]
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
        guard session.pendingCertificateRequests.count < Self.maximumOpenCertificateRequests else {
            throw AuthError.resourceLimit
        }
        guard session.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        let data = try AuthMessageCodec.certificateRequestSigningBytes(request, limits: limits)
        let ownNonce = session.ownNonce
        let nonce = try reserveUniqueNonce()
        defer { inFlightNonces.remove(nonce) }
        let own = try await identity()
        try Task.checkCancellation()
        let signature = try await sign(data, keyID: nonce + " " + peerNonce, peer: peer)
        try Task.checkCancellation()
        guard var current = sessions[sessionID], current.state == .authenticated,
            current.peer == peer, current.peerNonce == peerNonce
        else { throw AuthError.sessionNotFound }
        guard current.pendingCertificateRequests.count < Self.maximumOpenCertificateRequests else {
            throw AuthError.resourceLimit
        }
        guard current.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        current.messageCount += 1
        current.seen.insert(nonce)
        // A request without certifiers asks for nothing, so no answer is
        // awaited (`Peer.ts:1097-1100`).
        // Several requests may be open at once (`Peer.ts:474-478`).
        if !request.certifiers.isEmpty { current.pendingCertificateRequests.append(request) }
        sessions[sessionID] = current
        return .send(
            AuthMessage(
                messageType: .certificateRequest,
                identityKey: own,
                nonce: nonce,
                initialNonce: ownNonce,
                yourNonce: peerNonce,
                signature: signature,
                requestedCertificates: request
            )
        )
    }

    /// Answers one of the peer's open certificate requests.
    ///
    /// The certificates may be any subset of the requested types, each
    /// revealing a nonempty subset of its requested fields, and may be empty,
    /// as `@bsv/sdk` 4.1.1 allows (`Peer.ts:359-389`, `Peer.ts:1117`). A
    /// request that arrived in `initialRequest` can be answered before the
    /// peer has sent its first signed message.
    ///
    /// `answering` names the request answered. When it is `nil`, the oldest
    /// certificateRequest the certificates fit is answered, and the
    /// handshake policy only if none fits, the order in which the peer
    /// matches the response (`Peer.ts:1236-1241`).
    ///
    /// `answering` settles a request on this side only. The response does
    /// not carry it, so the peer settles the oldest of its own requests that
    /// the certificates fit, which may be a different one.
    public func makeCertificateResponse(
        _ certificates: [VerifiableCertificate],
        using sessionID: AuthSessionID,
        answering answered: AuthRequestedCertificateSet? = nil
    ) async throws -> AuthPeerAction {
        try Task.checkCancellation()
        purgeExpired()
        guard let session = sessions[sessionID], Self.canExchangeCertificates(session),
            let peer = session.peer, let peerNonce = session.peerNonce,
            !Self.answerableRequests(session).isEmpty
        else { throw AuthError.notAuthenticated }
        let ownNonce = session.ownNonce
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
        let request: AuthRequestedCertificateSet
        if let answered {
            guard Self.answerableRequests(session).contains(answered) else {
                throw AuthError.unexpectedMessage
            }
            try requireCertificateMatch(
                certificates, request: answered, peer: own, operation: "makeCertificateResponse")
            request = answered
        } else {
            request = try firstMatchingRequest(
                certificates, in: Self.answerableRequests(session), peer: own,
                operation: "makeCertificateResponse")
        }
        let signature = try await sign(data, keyID: nonce + " " + peerNonce, peer: peer)
        try Task.checkCancellation()
        guard var current = sessions[sessionID], Self.canExchangeCertificates(current),
            current.peer == peer, current.peerNonce == peerNonce,
            Self.answerableRequests(current).contains(request)
        else { throw AuthError.sessionNotFound }
        guard current.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: sessionID)
            throw AuthError.resourceLimit
        }
        current.messageCount += 1
        current.seen.insert(nonce)
        if let answeredIndex = current.receivedCertificateRequests.firstIndex(of: request) {
            current.receivedCertificateRequests.remove(at: answeredIndex)
        } else {
            current.receivedHandshakeRequest = nil
        }
        sessions[sessionID] = current
        return .send(
            AuthMessage(
                messageType: .certificateResponse,
                identityKey: own,
                nonce: nonce,
                initialNonce: ownNonce,
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
        // `@bsv/sdk` 4.1.1 requires a 48-byte responder session nonce
        // (`AuthMessageValidation.ts:394`).
        let ownNonce = try makeUniqueSessionNonce(excluding: [incoming])
        let id = AuthSessionID()
        sessions[id] = .init(
            id: id, state: .responseSentAwaitingPeerProof, peer: message.identityKey,
            ownNonce: ownNonce,
            peerNonce: incoming, deadline: clock.now + limits.handshakeTimeout, seen: [incoming],
            pendingHandshakeRequest: Self.askingRequest(certificatesToRequest),
            receivedHandshakeRequest: Self.askingRequest(message.requestedCertificates))
        let signature: [UInt8]
        do {
            signature = try await sign(
                (try nonceBytes(incoming)) + (try nonceBytes(ownNonce)),
                keyID: incoming + " " + ownNonce,
                peer: message.identityKey)
            try Task.checkCancellation()
        } catch {
            sessions.removeValue(forKey: id)
            throw error
        }
        var actions: [AuthPeerAction] = [
            .send(
                .init(
                    messageType: .initialResponse, identityKey: own, nonce: ownNonce,
                    initialNonce: ownNonce,
                    yourNonce: incoming, signature: signature,
                    // This side's policy, as `Peer.ts:867-876` sends it. The
                    // signature covers only the nonces.
                    requestedCertificates: certificatesToRequest))
        ]
        if let request = Self.askingRequest(message.requestedCertificates) {
            actions.append(
                .certificateRequest(
                    .init(sessionID: id, peer: message.identityKey, request: request)))
        }
        return actions
    }
    private func receiveResponse(_ message: AuthMessage) async throws -> [AuthPeerAction] {
        try Task.checkCancellation()
        guard let ownNonce = message.yourNonce, let peerNonce = message.initialNonce,
            message.nonce == nil || message.nonce == peerNonce, let signature = message.signature,
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
                keyID: ownNonce + " " + peerNonce, peer: message.identityKey)
        else { throw AuthError.invalidSignature }
        try Task.checkCancellation()
        // As `Peer.ts:960-967`, certificates are looked at only when this side
        // asked for some and the peer sent at least one; otherwise they are
        // ignored and any pending request stays open.
        var answered: AuthRequestedCertificateSet?
        if let certificates = message.certificates, !certificates.isEmpty,
            let pending = sessions[index]?.pendingHandshakeRequest
        {
            answered = try firstMatchingRequest(
                certificates, in: [pending], peer: message.identityKey,
                operation: "receive initialResponse")
        }
        guard var session = sessions[index], session.state == .challengeSent,
            session.ownNonce == ownNonce,
            session.peer == nil || session.peer == message.identityKey
        else { throw AuthError.sessionNotFound }
        session.peer = message.identityKey
        session.peerNonce = peerNonce
        session.state = .authenticated
        session.deadline = nil
        session.seen.insert(peerNonce)
        // A responder with a certificate policy puts it here and then holds
        // general messages until it receives a matching certificateResponse
        // (`Peer.ts:840-850`, `Peer.ts:1326-1328`).
        let theirRequest = Self.askingRequest(message.requestedCertificates)
        session.receivedHandshakeRequest = theirRequest
        var actions: [AuthPeerAction] = []
        // A responder answers a handshake policy with certificates in
        // initialResponse (`Peer.ts:836-849`, `Peer.ts:872`). They are not
        // covered by the signature, which binds only the nonces; the initiator
        // validates them as `Peer.ts:960-982` does.
        if let certificates = message.certificates, let request = answered,
            session.pendingHandshakeRequest == request
        {
            session.pendingHandshakeRequest = nil
            actions.append(
                .certificateResponse(
                    .init(
                        sessionID: index, peer: message.identityKey, requested: request,
                        certificates: certificates)))
        }
        sessions[index] = session
        if let request = theirRequest {
            actions.append(
                .certificateRequest(
                    .init(sessionID: index, peer: message.identityKey, request: request)))
        }
        return actions
    }

    /// Requests this side is waiting on, in the order a response is matched
    /// with them: certificateRequests oldest first, then the handshake policy.
    private static func openRequests(_ session: Session) -> [AuthRequestedCertificateSet] {
        session.pendingCertificateRequests + (session.pendingHandshakeRequest.map { [$0] } ?? [])
    }

    /// Requests the peer is waiting on this side to answer, in matching
    /// order: certificateRequests oldest first, then the handshake policy.
    private static func answerableRequests(_ session: Session) -> [AuthRequestedCertificateSet] {
        session.receivedCertificateRequests + (session.receivedHandshakeRequest.map { [$0] } ?? [])
    }

    /// Refuses a received request that would be the seventeenth open one, is
    /// identical to one already open, or would take the open requests of the
    /// session past `maximumCertificateAggregateBytes` together. This bounds
    /// what one authenticated peer can keep in memory to what one request
    /// may hold.
    private func admitReceivedRequest(
        _ request: AuthRequestedCertificateSet,
        into session: Session
    ) throws {
        let open = Self.answerableRequests(session)
        guard session.receivedCertificateRequests.count < Self.maximumOpenCertificateRequests else {
            AuthLog.rejected(
                "receive certificateRequest",
                "\(session.receivedCertificateRequests.count) requests are already open",
                as: AuthError.resourceLimit)
            throw AuthError.resourceLimit
        }
        guard !open.contains(request) else {
            AuthLog.rejected(
                "receive certificateRequest", "an identical request is already open",
                as: AuthError.unexpectedMessage)
            throw AuthError.unexpectedMessage
        }
        let total = (open + [request]).reduce(0) { $0 + $1.accountedBytes }
        guard total <= limits.maximumCertificateAggregateBytes else {
            AuthLog.rejected(
                "receive certificateRequest",
                "open requests would hold \(total) bytes, over \(limits.maximumCertificateAggregateBytes)",
                as: AuthError.resourceLimit)
            throw AuthError.resourceLimit
        }
    }

    /// A requested set that asks for something. `@bsv/sdk` treats a set with
    /// no certifiers as no request (`Peer.ts:836-838`, `Peer.ts:1097-1100`).
    private static func askingRequest(
        _ request: AuthRequestedCertificateSet?
    ) -> AuthRequestedCertificateSet? {
        guard let request, !request.certifiers.isEmpty else { return nil }
        return request
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
            let index = certificateSessionIndex(target: target, peer: message.identityKey),
            let session = sessions[index]
        else { throw AuthError.sessionNotFound }
        guard message.initialNonce == session.peerNonce else { throw AuthError.invalidNonce }
        guard !session.seen.contains(nonce) else { throw AuthError.replay }
        guard inFlightNonces.insert(nonce).inserted else { throw AuthError.replay }
        defer { inFlightNonces.remove(nonce) }
        let data =
            try message.receivedSigningBytes
            ?? AuthMessageCodec.certificateRequestSigningBytes(request, limits: limits)
        guard
            try await verify(
                signature,
                data: data,
                keyID: nonce + " " + target,
                peer: message.identityKey
            )
        else { throw AuthError.invalidSignature }
        try Task.checkCancellation()
        guard var current = sessions[index], Self.canExchangeCertificates(current),
            current.ownNonce == target, current.peer == message.identityKey,
            !current.seen.contains(nonce)
        else { throw AuthError.replay }
        // A request without certifiers asks for nothing: it is verified and
        // authenticates the sender, and there is nothing to answer
        // (`Peer.ts:1092-1100`).
        // Several requests may be open at once (`Peer.ts:474-478`), within
        // `admitReceivedRequest`'s bounds.
        let asking = Self.askingRequest(request)
        if asking != nil {
            try admitReceivedRequest(request, into: current)
        }
        try consumeMessage(on: index, session: &current)
        current.seen.insert(nonce)
        if asking != nil { current.receivedCertificateRequests.append(request) }
        markAuthenticated(&current)
        sessions[index] = current
        guard asking != nil else { return [] }
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
            let index = certificateSessionIndex(target: target, peer: message.identityKey),
            let session = sessions[index]
        else { throw AuthError.sessionNotFound }
        guard message.initialNonce == session.peerNonce else { throw AuthError.invalidNonce }
        guard !session.seen.contains(nonce) else { throw AuthError.replay }
        guard !Self.openRequests(session).isEmpty else {
            throw AuthError.unexpectedMessage
        }
        guard inFlightNonces.insert(nonce).inserted else { throw AuthError.replay }
        defer { inFlightNonces.remove(nonce) }
        let data =
            try message.receivedSigningBytes
            ?? AuthMessageCodec.certificateResponseSigningBytes(certificates, limits: limits)
        guard
            try await verify(
                signature,
                data: data,
                keyID: nonce + " " + target,
                peer: message.identityKey
            )
        else { throw AuthError.invalidSignature }
        try Task.checkCancellation()
        guard var current = sessions[index], Self.canExchangeCertificates(current),
            current.ownNonce == target, current.peer == message.identityKey,
            !current.seen.contains(nonce)
        else { throw AuthError.replay }
        // The signature is verified first, as in `Peer.ts:1202-1217`. A
        // response does not name the request it answers, so it settles the
        // oldest certificateRequest it fits and only then the handshake
        // policy (`Peer.ts:1236-1241`). An empty response declines the oldest
        // open request in the same order.
        let request = try firstMatchingRequest(
            certificates, in: Self.openRequests(current), peer: message.identityKey,
            operation: "receive certificateResponse")
        try consumeMessage(on: index, session: &current)
        current.seen.insert(nonce)
        if let answeredIndex = current.pendingCertificateRequests.firstIndex(of: request) {
            current.pendingCertificateRequests.remove(at: answeredIndex)
        } else {
            current.pendingHandshakeRequest = nil
        }
        markAuthenticated(&current)
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

    /// A session that can send or receive signed certificate messages.
    ///
    /// `@bsv/sdk` 4.1.1 authenticates a responder session on a verified
    /// certificateRequest or certificateResponse as well as on a general
    /// message (`Peer.ts:1092`, `Peer.ts:1227`, `Peer.ts:1317`).
    private static func canExchangeCertificates(_ session: Session) -> Bool {
        session.peerNonce != nil
            && (session.state == .authenticated
                || session.state == .responseSentAwaitingPeerProof)
    }

    private func certificateSessionIndex(target: String, peer: PublicKey) -> AuthSessionID? {
        sessions.first {
            $0.value.ownNonce == target && $0.value.peer == peer
                && Self.canExchangeCertificates($0.value)
        }?.key
    }

    private func markAuthenticated(_ session: inout Session) {
        if session.state == .responseSentAwaitingPeerProof {
            session.state = .authenticated
            session.deadline = nil
        }
    }

    private func consumeMessage(on id: AuthSessionID, session: inout Session) throws {
        guard session.messageCount < limits.maximumMessages else {
            sessions.removeValue(forKey: id)
            throw AuthError.resourceLimit
        }
        session.messageCount += 1
    }

    /// The oldest of `requests` that `certificates` fit.
    private func firstMatchingRequest(
        _ certificates: [VerifiableCertificate],
        in requests: [AuthRequestedCertificateSet],
        peer: PublicKey,
        operation: String
    ) throws -> AuthRequestedCertificateSet {
        if let request = requests.first(where: {
            Self.certificateMismatch(certificates, request: $0, peer: peer, limits: limits) == nil
        }) {
            return request
        }
        let reason =
            requests.first.flatMap {
                Self.certificateMismatch(certificates, request: $0, peer: peer, limits: limits)
            } ?? "no request is open"
        AuthLog.rejected(
            operation, "certificates fit none of \(requests.count) open requests; oldest: \(reason)",
            as: AuthError.certificateValidationFailed)
        throw AuthError.certificateValidationFailed
    }

    private func requireCertificateMatch(
        _ certificates: [VerifiableCertificate],
        request: AuthRequestedCertificateSet,
        peer: PublicKey,
        operation: String
    ) throws {
        if let reason = Self.certificateMismatch(
            certificates, request: request, peer: peer, limits: limits)
        {
            AuthLog.rejected(operation, reason, as: AuthError.certificateValidationFailed)
            throw AuthError.certificateValidationFailed
        }
    }

    /// Why `certificates` do not fit `request`, or `nil` when they do.
    ///
    /// The request is an allowlist (`Peer.ts:359-389`): every certificate
    /// must be a requested certifier and type and reveal a nonempty subset of
    /// the requested fields. Completeness is caller policy, checked by
    /// `AuthCertificateExchange.validate`.
    private static func certificateMismatch(
        _ certificates: [VerifiableCertificate],
        request: AuthRequestedCertificateSet,
        peer: PublicKey,
        limits: AuthLimits
    ) -> String? {
        guard certificates.count <= limits.maximumCertificateCount else {
            return "\(certificates.count) certificates exceed the limit"
        }
        for (position, verifiable) in certificates.enumerated() {
            let certificate = verifiable.certificate
            guard certificate.subject == peer else {
                return "certificate \(position) names another subject"
            }
            guard request.certifiers.contains(certificate.certifier) else {
                return "certificate \(position) has a certifier that was not requested"
            }
            guard let fields = request.certificateTypes[certificate.type] else {
                return "certificate \(position) has a type that was not requested"
            }
            guard !verifiable.keyring.entries.isEmpty,
                Set(verifiable.keyring.entries.keys).isSubset(of: Set(fields))
            else {
                return "certificate \(position) reveals no field or a field that was not requested"
            }
        }
        return nil
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
    /// A session nonce is 48 bytes, not 32.
    ///
    /// The signed data is the two nonces' base64 **text** joined and then decoded, which is what
    /// the TypeScript peer does. A 32-byte nonce encodes with `=` padding, and a decoder handed
    /// `<padded><second>` stops at the padding and silently drops the second nonce — the two sides
    /// then sign different bytes and neither can say why. At 48 bytes there is no padding, joining
    /// is unambiguous, and both derivations agree.
    private func makeSessionNonce() throws -> String {
        do {
            let bytes = try randomSource.randomBytes(count: 48)
            guard bytes.count == 48 else { throw AuthError.randomGenerationFailed }
            return Base64Encoding.encode(bytes)
        } catch {
            AuthLog.reported(
                "PeerAuthenticator session nonce", error, as: AuthError.randomGenerationFailed)
            throw AuthError.randomGenerationFailed
        }
    }
    private func makeUniqueSessionNonce(excluding: Set<String> = []) throws -> String {
        for _ in 0..<4 {
            let nonce = try makeSessionNonce()
            if !excluding.contains(nonce), !nonceIsInUse(nonce) { return nonce }
        }
        throw AuthError.randomGenerationFailed
    }
    private func makeNonce() throws -> String {
        do {
            let bytes = try randomSource.randomBytes(count: 32)
            guard bytes.count == 32 else { throw AuthError.randomGenerationFailed }
            return Base64Encoding.encode(bytes)
        } catch {
            AuthLog.reported(
                "PeerAuthenticator message nonce", error, as: AuthError.randomGenerationFailed)
            throw AuthError.randomGenerationFailed
        }
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
