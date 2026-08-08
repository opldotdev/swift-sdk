import BSVCore
import BSVKeys

/// Stateless codecs for strict BRC-100 wallet-wire frames and the supported
/// key/query call subset. This namespace performs no transport or wallet work.
public enum WalletWireCodec {
    public static func encodeRequestFrame(
        _ frame: WalletWireRequestFrame,
        limits: WalletWireLimits = .standard
    ) throws -> [UInt8] {
        let originatorCount = frame.originator.utf8.count
        let originatorMaximum = min(
            limits.maximumOriginatorUTF8ByteCount,
            WalletWireLimits.hardMaximumOriginatorUTF8ByteCount
        )
        guard originatorCount <= originatorMaximum else {
            throw WalletWireError.byteLimitExceeded(
                kind: "originator",
                actual: originatorCount,
                maximum: originatorMaximum
            )
        }
        let originator = Array(frame.originator.utf8)
        try requireBytes(
            frame.parameters.count,
            maximum: limits.maximumPayloadByteCount,
            kind: "request parameters"
        )
        let (prefixCount, overflow1) = originator.count.addingReportingOverflow(2)
        let (frameCount, overflow2) = prefixCount.addingReportingOverflow(frame.parameters.count)
        guard !overflow1, !overflow2 else {
            throw WalletWireError.byteLimitExceeded(
                kind: "request frame",
                actual: Int.max,
                maximum: limits.maximumFrameByteCount
            )
        }
        try requireBytes(frameCount, maximum: limits.maximumFrameByteCount, kind: "request frame")

        var writer = WalletWireWriter()
        writer.writeByte(frame.call.rawValue)
        writer.writeByte(UInt8(originator.count))
        writer.writeBytes(originator)
        writer.writeBytes(frame.parameters)
        return writer.bytes
    }

    public static func decodeRequestFrame(
        _ bytes: [UInt8],
        limits: WalletWireLimits = .standard
    ) throws -> WalletWireRequestFrame {
        try requireBytes(bytes.count, maximum: limits.maximumFrameByteCount, kind: "request frame")
        var reader = WalletWireReader(bytes)
        let callByte = try reader.readByte()
        guard let call = WalletCall(rawValue: callByte) else {
            throw WalletWireError.invalidCall(callByte)
        }
        let originatorCount = Int(try reader.readByte())
        guard originatorCount <= limits.maximumOriginatorUTF8ByteCount else {
            throw WalletWireError.byteLimitExceeded(
                kind: "originator",
                actual: originatorCount,
                maximum: limits.maximumOriginatorUTF8ByteCount
            )
        }
        let originatorBytes = try reader.readBytes(count: originatorCount)
        guard let originator = String(bytes: originatorBytes, encoding: .utf8) else {
            throw WalletWireError.invalidUTF8(kind: "originator")
        }
        let parameters = try reader.readRemainder(
            maximum: limits.maximumPayloadByteCount,
            kind: "request parameters"
        )
        return WalletWireRequestFrame(call: call, originator: originator, parameters: parameters)
    }

    public static func encodeResultFrame(
        _ frame: WalletWireResultFrame,
        limits: WalletWireLimits = .standard
    ) throws -> [UInt8] {
        switch frame {
        case .success(let payload):
            try requireBytes(
                payload.count,
                maximum: limits.maximumPayloadByteCount,
                kind: "result payload"
            )
            _ = try walletWireCheckedByteCount(
                1,
                payload.count,
                maximum: limits.maximumFrameByteCount,
                kind: "result frame"
            )
            var writer = WalletWireWriter()
            writer.writeByte(0)
            writer.writeBytes(payload)
            return writer.bytes
        case .failure(let remote):
            guard remote.code != 0 else {
                throw WalletWireError.invalidDiscriminator(kind: "remote error code", value: 0)
            }
            try walletWireRequireText(
                remote.message,
                kind: "remote message",
                maximum: limits.maximumRemoteMessageUTF8ByteCount
            )
            try walletWireRequireText(
                remote.stack,
                kind: "remote stack",
                maximum: limits.maximumRemoteStackUTF8ByteCount
            )
            let messageCount = remote.message.utf8.count
            let stackCount = remote.stack.utf8.count
            var encodedCount = try walletWireCheckedByteCount(
                1,
                compactSizeByteCount(UInt64(messageCount)),
                maximum: limits.maximumFrameByteCount,
                kind: "result frame"
            )
            encodedCount = try walletWireCheckedByteCount(
                encodedCount,
                messageCount,
                maximum: limits.maximumFrameByteCount,
                kind: "result frame"
            )
            encodedCount = try walletWireCheckedByteCount(
                encodedCount,
                compactSizeByteCount(UInt64(stackCount)),
                maximum: limits.maximumFrameByteCount,
                kind: "result frame"
            )
            _ = try walletWireCheckedByteCount(
                encodedCount,
                stackCount,
                maximum: limits.maximumFrameByteCount,
                kind: "result frame"
            )
            var writer = WalletWireWriter()
            writer.writeByte(remote.code)
            try writer.writeString(remote.message)
            try writer.writeString(remote.stack)
            return writer.bytes
        }
    }

    public static func decodeResultFrame(
        _ bytes: [UInt8],
        limits: WalletWireLimits = .standard
    ) throws -> WalletWireResultFrame {
        try requireBytes(bytes.count, maximum: limits.maximumFrameByteCount, kind: "result frame")
        var reader = WalletWireReader(bytes)
        let code = try reader.readByte()
        if code == 0 {
            return .success(try reader.readRemainder(
                maximum: limits.maximumPayloadByteCount,
                kind: "result payload"
            ))
        }
        let message = try reader.readString(
            maximum: limits.maximumRemoteMessageUTF8ByteCount,
            kind: "remote message"
        )
        let stack = try reader.readString(
            maximum: limits.maximumRemoteStackUTF8ByteCount,
            kind: "remote stack"
        )
        try reader.requireEnd()
        return .failure(try WalletWireRemoteError(
            code: code,
            message: message,
            stack: stack,
            limits: limits
        ))
    }

    public static func encodeKeyQueryRequest(
        _ request: WalletWireKeyQueryRequest,
        originator: String,
        limits: WalletWireLimits = .standard
    ) throws -> [UInt8] {
        let originatorCount = originator.utf8.count
        let maximum = min(
            limits.maximumOriginatorUTF8ByteCount,
            WalletWireLimits.hardMaximumOriginatorUTF8ByteCount
        )
        guard originatorCount <= maximum else {
            throw WalletWireError.byteLimitExceeded(
                kind: "originator",
                actual: originatorCount,
                maximum: maximum
            )
        }
        let parameters = try encodeParameters(request, limits: limits)
        return try encodeRequestFrame(
            WalletWireRequestFrame(call: request.call, originator: originator, parameters: parameters),
            limits: limits
        )
    }

    public static func decodeKeyQueryRequest(
        _ bytes: [UInt8],
        limits: WalletWireLimits = .standard
    ) throws -> WalletWireDecodedKeyQueryRequest {
        let frame = try decodeRequestFrame(bytes, limits: limits)
        return WalletWireDecodedKeyQueryRequest(
            originator: frame.originator,
            request: try decodeParameters(frame.parameters, call: frame.call, limits: limits)
        )
    }

    public static func encodeKeyQueryResult(
        _ result: WalletWireKeyQueryResult,
        limits: WalletWireLimits = .standard
    ) throws -> [UInt8] {
        try encodeResultFrame(.success(encodeResultPayload(result, limits: limits)), limits: limits)
    }

    public static func decodeKeyQueryResult(
        _ bytes: [UInt8],
        expectedCall: WalletCall,
        limits: WalletWireLimits = .standard
    ) throws -> WalletWireKeyQueryResult {
        switch try decodeResultFrame(bytes, limits: limits) {
        case .failure(let remote): throw remote
        case .success(let payload):
            return try decodeResultPayload(payload, call: expectedCall, limits: limits)
        }
    }

    private static func encodeParameters(
        _ request: WalletWireKeyQueryRequest,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        var writer = WalletWireWriter(maximumByteCount: limits.maximumPayloadByteCount)
        switch request {
        case .getPublicKey(let value):
            switch value.selection {
            case .identity:
                writer.writeByte(1)
                try walletWireEncodeAccess(value.access, to: &writer, limits: limits)
            case .derived(let protocolID, let keyID, let counterparty, let forSelf):
                writer.writeByte(0)
                try walletWireEncodeKeyParameters(
                    protocolID: protocolID,
                    keyID: keyID,
                    counterparty: counterparty,
                    access: value.access,
                    to: &writer,
                    limits: limits
                )
                writer.writeOptionalBoolean(forSelf)
            }
            writer.writeOptionalBoolean(value.access.seekPermission)
        case .encrypt(let value):
            try walletWireEncodeKeyParameters(
                protocolID: value.protocolID, keyID: value.keyID,
                counterparty: value.counterparty, access: value.access,
                to: &writer, limits: limits
            )
            try requireBytes(
                value.plaintext.count,
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "plaintext"
            )
            try writer.writeVarBytes(value.plaintext)
            writer.writeOptionalBoolean(value.access.seekPermission)
        case .decrypt(let value):
            try walletWireEncodeKeyParameters(
                protocolID: value.protocolID, keyID: value.keyID,
                counterparty: value.counterparty, access: value.access,
                to: &writer, limits: limits
            )
            try requireBytes(
                value.ciphertext.count,
                maximum: limits.cryptoLimits.maximumCiphertextByteCount,
                kind: "ciphertext"
            )
            try writer.writeVarBytes(value.ciphertext)
            writer.writeOptionalBoolean(value.access.seekPermission)
        case .createHMAC(let value):
            try walletWireEncodeKeyParameters(
                protocolID: value.protocolID, keyID: value.keyID,
                counterparty: value.counterparty, access: value.access,
                to: &writer, limits: limits
            )
            try requireBytes(
                value.data.count,
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "HMAC data"
            )
            try writer.writeVarBytes(value.data)
            writer.writeOptionalBoolean(value.access.seekPermission)
        case .verifyHMAC(let value):
            try walletWireEncodeKeyParameters(
                protocolID: value.protocolID, keyID: value.keyID,
                counterparty: value.counterparty, access: value.access,
                to: &writer, limits: limits
            )
            writer.writeBytes(value.hmac.bytes)
            try requireBytes(
                value.data.count,
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "HMAC data"
            )
            try writer.writeVarBytes(value.data)
            writer.writeOptionalBoolean(value.access.seekPermission)
        case .createSignature(let value):
            try walletWireEncodeKeyParameters(
                protocolID: value.protocolID, keyID: value.keyID,
                counterparty: value.counterparty, access: value.access,
                to: &writer, limits: limits
            )
            switch value.payload {
            case .data(let bytes):
                try requireBytes(
                    bytes.count,
                    maximum: limits.cryptoLimits.maximumPayloadByteCount,
                    kind: "signature data"
                )
                writer.writeByte(1)
                try writer.writeVarBytes(bytes)
            case .digest(let digest):
                writer.writeByte(2)
                writer.writeBytes(digest.bytes)
            }
            writer.writeOptionalBoolean(value.access.seekPermission)
        case .verifySignature(let value):
            try walletWireRequireLowSSignature(value.signature)
            try walletWireEncodeKeyParameters(
                protocolID: value.protocolID, keyID: value.keyID,
                counterparty: value.counterparty, access: value.access,
                to: &writer, limits: limits
            )
            writer.writeOptionalBoolean(value.forSelf)
            try writer.writeVarBytes(value.signature.derBytes)
            switch value.payload {
            case .data(let bytes):
                guard !bytes.isEmpty else {
                    throw WalletWireError.nonRoundTrippableValue(kind: "empty verify-signature data")
                }
                try requireBytes(
                    bytes.count,
                    maximum: limits.cryptoLimits.maximumPayloadByteCount,
                    kind: "signature data"
                )
                writer.writeByte(1)
                try writer.writeVarBytes(bytes)
            case .digest(let digest):
                writer.writeByte(2)
                writer.writeBytes(digest.bytes)
            }
            writer.writeOptionalBoolean(value.access.seekPermission)
        case .isAuthenticated, .waitForAuthentication, .getHeight, .getNetwork, .getVersion:
            break
        case .getHeaderForHeight(let value):
            writer.writeCompactSize(UInt64(value.height))
        }
        try writer.requireWithinLimit(kind: "request parameters")
        try requireBytes(
            writer.bytes.count,
            maximum: limits.maximumPayloadByteCount,
            kind: "request parameters"
        )
        return writer.bytes
    }

    private static func decodeParameters(
        _ bytes: [UInt8],
        call: WalletCall,
        limits: WalletWireLimits
    ) throws -> WalletWireKeyQueryRequest {
        var reader = WalletWireReader(bytes)
        let decoded: WalletWireKeyQueryRequest
        switch call {
        case .getPublicKey:
            switch try reader.readByte() {
            case 1:
                let access = try walletWireDecodeAccess(from: &reader, limits: limits)
                let seek = try reader.readOptionalBoolean(kind: "seek permission") ?? false
                decoded = .getPublicKey(WalletGetPublicKeyRequest(
                    selection: .identity,
                    access: try walletWireAccessWithSeek(access, seek: seek)
                ))
            case 0:
                let key = try walletWireDecodeKeyParameters(from: &reader, limits: limits)
                let forSelf = try reader.readOptionalBoolean(kind: "for self") ?? false
                let seek = try reader.readOptionalBoolean(kind: "seek permission") ?? false
                decoded = .getPublicKey(WalletGetPublicKeyRequest(
                    selection: .derived(
                        protocolID: key.protocolID,
                        keyID: key.keyID,
                        counterparty: key.counterparty,
                        forSelf: forSelf
                    ),
                    access: try walletWireAccessWithSeek(key.access, seek: seek)
                ))
            case let flag:
                throw WalletWireError.invalidDiscriminator(kind: "identity key", value: flag)
            }
        case .encrypt:
            let key = try walletWireDecodeKeyParameters(from: &reader, limits: limits)
            let plaintext = try reader.readVarBytes(
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "plaintext"
            )
            let seek = try reader.readOptionalBoolean(kind: "seek permission") ?? false
            decoded = .encrypt(WalletEncryptRequest(
                protocolID: key.protocolID, keyID: key.keyID,
                counterparty: key.counterparty, plaintext: plaintext,
                access: try walletWireAccessWithSeek(key.access, seek: seek)
            ))
        case .decrypt:
            let key = try walletWireDecodeKeyParameters(from: &reader, limits: limits)
            let ciphertext = try reader.readVarBytes(
                maximum: limits.cryptoLimits.maximumCiphertextByteCount,
                kind: "ciphertext"
            )
            let seek = try reader.readOptionalBoolean(kind: "seek permission") ?? false
            decoded = .decrypt(WalletDecryptRequest(
                protocolID: key.protocolID, keyID: key.keyID,
                counterparty: key.counterparty, ciphertext: ciphertext,
                access: try walletWireAccessWithSeek(key.access, seek: seek)
            ))
        case .createHMAC:
            let key = try walletWireDecodeKeyParameters(from: &reader, limits: limits)
            let data = try reader.readVarBytes(
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "HMAC data"
            )
            let seek = try reader.readOptionalBoolean(kind: "seek permission") ?? false
            decoded = .createHMAC(WalletCreateHMACRequest(
                protocolID: key.protocolID, keyID: key.keyID,
                counterparty: key.counterparty, data: data,
                access: try walletWireAccessWithSeek(key.access, seek: seek)
            ))
        case .verifyHMAC:
            let key = try walletWireDecodeKeyParameters(from: &reader, limits: limits)
            let hmacBytes = try reader.readBytes(count: WalletHMAC.byteCount)
            let data = try reader.readVarBytes(
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "HMAC data"
            )
            let seek = try reader.readOptionalBoolean(kind: "seek permission") ?? false
            decoded = .verifyHMAC(WalletVerifyHMACRequest(
                protocolID: key.protocolID, keyID: key.keyID,
                counterparty: key.counterparty, data: data,
                hmac: try WalletHMAC(bytes: hmacBytes),
                access: try walletWireAccessWithSeek(key.access, seek: seek)
            ))
        case .createSignature:
            let key = try walletWireDecodeKeyParameters(from: &reader, limits: limits)
            let payload = try decodeSignaturePayload(
                from: &reader,
                rejectEmptyData: false,
                limits: limits
            )
            let seek = try reader.readOptionalBoolean(kind: "seek permission") ?? false
            decoded = .createSignature(WalletCreateSignatureRequest(
                protocolID: key.protocolID, keyID: key.keyID,
                counterparty: key.counterparty, payload: payload,
                access: try walletWireAccessWithSeek(key.access, seek: seek)
            ))
        case .verifySignature:
            let key = try walletWireDecodeKeyParameters(from: &reader, limits: limits)
            let forSelf = try reader.readOptionalBoolean(kind: "for self") ?? false
            let signatureBytes = try reader.readVarBytes(maximum: 72, kind: "signature")
            let signature: ECDSASignature
            do { signature = try ECDSASignature(derBytes: signatureBytes) }
            catch { throw WalletWireError.invalidSignature }
            try walletWireRequireLowSSignature(signature)
            let payload = try decodeSignaturePayload(
                from: &reader,
                rejectEmptyData: true,
                limits: limits
            )
            let seek = try reader.readOptionalBoolean(kind: "seek permission") ?? false
            decoded = .verifySignature(WalletVerifySignatureRequest(
                protocolID: key.protocolID, keyID: key.keyID,
                counterparty: key.counterparty, payload: payload,
                signature: signature, forSelf: forSelf,
                access: try walletWireAccessWithSeek(key.access, seek: seek)
            ))
        case .isAuthenticated:
            decoded = .isAuthenticated(WalletIsAuthenticatedRequest())
        case .waitForAuthentication:
            decoded = .waitForAuthentication(WalletWaitForAuthenticationRequest())
        case .getHeight:
            decoded = .getHeight(WalletGetHeightRequest())
        case .getHeaderForHeight:
            let value = try reader.readCompactSize()
            guard let height = UInt32(exactly: value) else { throw WalletWireError.uint32Overflow }
            decoded = .getHeaderForHeight(WalletGetHeaderRequest(height: height))
        case .getNetwork:
            decoded = .getNetwork(WalletGetNetworkRequest())
        case .getVersion:
            decoded = .getVersion(WalletGetVersionRequest())
        default:
            throw WalletWireError.invalidCall(call.rawValue)
        }
        try reader.requireEnd()
        return decoded
    }

    private static func decodeSignaturePayload(
        from reader: inout WalletWireReader,
        rejectEmptyData: Bool,
        limits: WalletWireLimits
    ) throws -> WalletSignaturePayload {
        switch try reader.readByte() {
        case 1:
            let data = try reader.readVarBytes(
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "signature data"
            )
            if rejectEmptyData, data.isEmpty {
                throw WalletWireError.nonRoundTrippableValue(kind: "empty verify-signature data")
            }
            return .data(data)
        case 2:
            return .digest(try Hash256(reader.readBytes(count: 32)))
        case let value:
            throw WalletWireError.invalidDiscriminator(kind: "signature payload", value: value)
        }
    }

    private static func encodeResultPayload(
        _ result: WalletWireKeyQueryResult,
        limits: WalletWireLimits
    ) throws -> [UInt8] {
        var writer = WalletWireWriter(maximumByteCount: limits.maximumPayloadByteCount)
        switch result {
        case .getPublicKey(let value):
            let bytes = value.publicKey.compressedBytes
            guard bytes.count == 33 else { throw WalletWireError.invalidPublicKey }
            writer.writeBytes(bytes)
        case .encrypt(let value):
            try requireBytes(
                value.ciphertext.count,
                maximum: limits.cryptoLimits.maximumCiphertextByteCount,
                kind: "ciphertext"
            )
            writer.writeBytes(value.ciphertext)
        case .decrypt(let value):
            try requireBytes(
                value.plaintext.count,
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "plaintext"
            )
            writer.writeBytes(value.plaintext)
        case .createHMAC(let value):
            writer.writeBytes(value.hmac.bytes)
        case .verifyHMAC(let value):
            guard value.valid else {
                throw WalletWireError.nonRoundTrippableValue(kind: "false verify-HMAC result")
            }
        case .createSignature(let value):
            try walletWireRequireLowSSignature(value.signature)
            writer.writeBytes(value.signature.derBytes)
        case .verifySignature(let value):
            guard value.valid else {
                throw WalletWireError.nonRoundTrippableValue(kind: "false verify-signature result")
            }
        case .isAuthenticated(let value):
            writer.writeByte(value.authenticated ? 1 : 0)
        case .waitForAuthentication(let value):
            guard value.authenticated else {
                throw WalletWireError.nonRoundTrippableValue(kind: "false wait-for-authentication result")
            }
        case .getHeight(let value):
            writer.writeCompactSize(UInt64(value.height))
        case .getHeaderForHeight(let value):
            guard value.header.count == WalletGetHeaderResult.byteCount else {
                throw WalletWireError.nonRoundTrippableValue(kind: "block header")
            }
            writer.writeBytes(value.header)
        case .getNetwork(let value):
            writer.writeByte(value.network == .mainnet ? 0 : 1)
        case .getVersion(let value):
            try walletWireRequireText(
                value.version,
                kind: "wallet version",
                maximum: walletWireMaximumText(limits)
            )
            writer.writeBytes(Array(value.version.utf8))
        }
        try writer.requireWithinLimit(kind: "result payload")
        try requireBytes(
            writer.bytes.count,
            maximum: limits.maximumPayloadByteCount,
            kind: "result payload"
        )
        return writer.bytes
    }

    private static func decodeResultPayload(
        _ bytes: [UInt8],
        call: WalletCall,
        limits: WalletWireLimits
    ) throws -> WalletWireKeyQueryResult {
        var reader = WalletWireReader(bytes)
        switch call {
        case .getPublicKey:
            guard bytes.count == 33 else { throw WalletWireError.invalidPublicKey }
            do {
                let key = try PublicKey(bytes)
                guard key.compressedBytes == bytes else { throw WalletWireError.invalidPublicKey }
                return .getPublicKey(WalletGetPublicKeyResult(publicKey: key))
            } catch {
                throw WalletWireError.invalidPublicKey
            }
        case .encrypt:
            return .encrypt(WalletEncryptResult(ciphertext: try reader.readRemainder(
                maximum: limits.cryptoLimits.maximumCiphertextByteCount,
                kind: "ciphertext"
            )))
        case .decrypt:
            return .decrypt(WalletDecryptResult(plaintext: try reader.readRemainder(
                maximum: limits.cryptoLimits.maximumPayloadByteCount,
                kind: "plaintext"
            )))
        case .createHMAC:
            guard bytes.count == WalletHMAC.byteCount else {
                throw WalletWireError.nonRoundTrippableValue(kind: "HMAC result length")
            }
            return .createHMAC(WalletCreateHMACResult(hmac: try WalletHMAC(bytes: bytes)))
        case .verifyHMAC:
            try reader.requireEnd()
            return .verifyHMAC(WalletVerifyHMACResult(valid: true))
        case .createSignature:
            let signature: ECDSASignature
            do { signature = try ECDSASignature(derBytes: bytes) }
            catch { throw WalletWireError.invalidSignature }
            try walletWireRequireLowSSignature(signature)
            return .createSignature(WalletCreateSignatureResult(signature: signature))
        case .verifySignature:
            try reader.requireEnd()
            return .verifySignature(WalletVerifySignatureResult(valid: true))
        case .isAuthenticated:
            guard bytes.count == 1 else {
                if bytes.isEmpty { throw WalletWireError.truncated }
                throw WalletWireError.trailingBytes
            }
            switch bytes[0] {
            case 0: return .isAuthenticated(WalletAuthenticatedResult(authenticated: false))
            case 1: return .isAuthenticated(WalletAuthenticatedResult(authenticated: true))
            case let value:
                throw WalletWireError.invalidDiscriminator(kind: "authentication result", value: value)
            }
        case .waitForAuthentication:
            try reader.requireEnd()
            return .waitForAuthentication(WalletAuthenticatedResult(authenticated: true))
        case .getHeight:
            let value = try reader.readCompactSize()
            guard let height = UInt32(exactly: value) else { throw WalletWireError.uint32Overflow }
            try reader.requireEnd()
            return .getHeight(WalletGetHeightResult(height: height))
        case .getHeaderForHeight:
            guard bytes.count == WalletGetHeaderResult.byteCount else {
                if bytes.count < WalletGetHeaderResult.byteCount { throw WalletWireError.truncated }
                throw WalletWireError.trailingBytes
            }
            return .getHeaderForHeight(try WalletGetHeaderResult(header: bytes))
        case .getNetwork:
            guard bytes.count == 1 else {
                if bytes.isEmpty { throw WalletWireError.truncated }
                throw WalletWireError.trailingBytes
            }
            switch bytes[0] {
            case 0: return .getNetwork(WalletGetNetworkResult(network: .mainnet))
            case 1: return .getNetwork(WalletGetNetworkResult(network: .testnet))
            case let value:
                throw WalletWireError.invalidDiscriminator(kind: "network", value: value)
            }
        case .getVersion:
            try requireBytes(
                bytes.count,
                maximum: walletWireMaximumText(limits),
                kind: "wallet version"
            )
            guard let version = String(bytes: bytes, encoding: .utf8) else {
                throw WalletWireError.invalidUTF8(kind: "wallet version")
            }
            return .getVersion(try WalletGetVersionResult(version: version, limits: limits.abiLimits))
        default:
            throw WalletWireError.invalidCall(call.rawValue)
        }
    }

    private static func requireBytes(_ count: Int, maximum: Int, kind: String) throws {
        guard count <= maximum else {
            throw WalletWireError.byteLimitExceeded(kind: kind, actual: count, maximum: maximum)
        }
    }

    private static func compactSizeByteCount(_ value: UInt64) -> Int {
        switch value {
        case 0...0xFC: 1
        case 0xFD...0xFFFF: 3
        case 0x1_0000...0xFFFF_FFFF: 5
        default: 9
        }
    }
}

func walletWireCheckedByteCount(
    _ lhs: Int,
    _ rhs: Int,
    maximum: Int,
    kind: String
) throws -> Int {
    let (total, overflow) = lhs.addingReportingOverflow(rhs)
    guard !overflow, total <= maximum else {
        throw WalletWireError.byteLimitExceeded(
            kind: kind,
            actual: overflow ? Int.max : total,
            maximum: maximum
        )
    }
    return total
}

func walletWireRequireLowSSignature(_ signature: ECDSASignature) throws {
    guard signature.isLowS else {
        throw WalletWireError.nonRoundTrippableValue(kind: "high-S signature")
    }
}
