import BSVCore
import BSVCrypto
import BSVScript

/// A one-byte legacy signature-hash flag was not one of the six canonical forms.
public enum LegacySignatureHashTypeError: Error, Equatable, Sendable {
    case invalidValue(UInt8)
}

/// A validated pre-ForkID Bitcoin signature-hash byte.
public struct LegacySignatureHashType: Hashable, Sendable {
    public static let anyoneCanPayMask: UInt8 = 0x80

    public let outputs: SignatureHashOutputs
    public let anyoneCanPay: Bool

    public init(
        outputs: SignatureHashOutputs = .all,
        anyoneCanPay: Bool = false
    ) {
        self.outputs = outputs
        self.anyoneCanPay = anyoneCanPay
    }

    /// Parses exactly ALL/NONE/SINGLE, optionally combined with ANYONECANPAY.
    public init(rawValue: UInt8) throws {
        let allowedBits = Self.anyoneCanPayMask | 0x1f
        guard rawValue & ~allowedBits == 0,
              let outputs = SignatureHashOutputs(rawValue: rawValue & 0x1f)
        else { throw LegacySignatureHashTypeError.invalidValue(rawValue) }
        self.init(
            outputs: outputs,
            anyoneCanPay: rawValue & Self.anyoneCanPayMask != 0
        )
    }

    public var rawValue: UInt8 {
        outputs.rawValue | (anyoneCanPay ? Self.anyoneCanPayMask : 0)
    }

    public static let all = Self(outputs: .all)
    public static let none = Self(outputs: .none)
    public static let single = Self(outputs: .single)
}

public extension Transaction {
    /// Builds the pre-ForkID serialization committed by one transaction signature.
    ///
    /// For the historical out-of-range SIGHASH_SINGLE case this returns the
    /// 32-byte little-endian integer one, matching the consensus bug rather
    /// than a serializable transaction preimage.
    func legacySignaturePreimage(
        inputIndex: Int,
        hashType: LegacySignatureHashType = .all,
        scriptCode: Script? = nil,
        limits: TransactionLimits
    ) throws -> [UInt8] {
        try legacySignatureMaterial(
            inputIndex: inputIndex,
            rawHashType: hashType.rawValue,
            scriptCode: scriptCode,
            limits: limits
        ).bytes
    }

    /// Returns the legacy transaction signature digest, including the
    /// un-hashed `uint256(1)` SIGHASH_SINGLE consensus result.
    func legacySignatureHash(
        inputIndex: Int,
        hashType: LegacySignatureHashType = .all,
        scriptCode: Script? = nil,
        limits: TransactionLimits
    ) throws -> Hash256 {
        let material = try legacySignatureMaterial(
            inputIndex: inputIndex,
            rawHashType: hashType.rawValue,
            scriptCode: scriptCode,
            limits: limits
        )
        return Self.digestLegacySignatureMaterial(material)
    }

    package func legacySignatureHash(
        inputIndex: Int,
        rawHashType: UInt8,
        scriptCode: Script,
        limits: TransactionLimits
    ) throws -> Hash256 {
        let material = try legacySignatureMaterial(
            inputIndex: inputIndex,
            rawHashType: rawHashType,
            scriptCode: scriptCode,
            limits: limits
        )
        return Self.digestLegacySignatureMaterial(material)
    }

    private static func digestLegacySignatureMaterial(
        _ material: LegacySignatureMaterial
    ) -> Hash256 {
        switch material {
        case .hashOne(let bytes):
            return Hash256(exactDigestBytesGuaranteed: bytes)
        case .preimage(let bytes):
            return BSVHashing.sha256d(bytes)
        }
    }

    private enum LegacySignatureMaterial {
        case preimage([UInt8])
        case hashOne([UInt8])

        var bytes: [UInt8] {
            switch self {
            case .preimage(let bytes), .hashOne(let bytes): bytes
            }
        }
    }

    private func legacySignatureMaterial(
        inputIndex: Int,
        rawHashType: UInt8,
        scriptCode: Script?,
        limits: TransactionLimits
    ) throws -> LegacySignatureMaterial {
        guard inputs.indices.contains(inputIndex) else {
            throw TransactionError.invalidInputIndex(inputIndex)
        }
        guard let sourceOutput = inputs[inputIndex].sourceOutput else {
            throw TransactionError.missingSourceOutput(inputIndex: inputIndex)
        }
        _ = try serializedByteCount(limits: limits)

        let committedScript = scriptCode ?? sourceOutput.lockingScript
        guard UInt64(committedScript.byteCount) <= limits.maximumScriptByteCount else {
            throw TransactionError.scriptTooLarge(
                actual: UInt64(committedScript.byteCount),
                maximum: limits.maximumScriptByteCount
            )
        }

        // Consensus masks only the low five bits. Noncanonical raw values are
        // intentionally handled here; strict policy is an interpreter concern.
        let outputMode = SignatureHashOutputs(rawValue: rawHashType & 0x1f) ?? .all
        if outputMode == .single, !outputs.indices.contains(inputIndex) {
            return .hashOne([1] + Array(repeating: 0, count: 31))
        }

        let anyoneCanPay = rawHashType & LegacySignatureHashType.anyoneCanPayMask != 0
        let inputIndices: [Int] = anyoneCanPay
            ? [inputIndex]
            : Array(inputs.indices)

        var writer = ByteWriter()
        writer.writeUInt32LE(version)
        writer.writeCompactSize(UInt64(inputIndices.count))
        for index in inputIndices {
            let input = inputs[index]
            writer.write(input.previousOutput.wireBytes)
            writer.writeVarBytes(index == inputIndex ? committedScript.bytes : [])
            let sequence = outputMode != .all && index != inputIndex
                ? UInt32.zero
                : input.sequence
            writer.writeUInt32LE(sequence)
        }

        switch outputMode {
        case .all:
            writer.writeCompactSize(UInt64(outputs.count))
            for output in outputs {
                Self.writeLegacySignatureOutput(output, to: &writer)
            }
        case .none:
            writer.writeCompactSize(0)
        case .single:
            writer.writeCompactSize(UInt64(inputIndex + 1))
            for _ in 0..<inputIndex {
                Self.writeLegacySignatureOutput(
                    TransactionOutput(
                        satoshis: .max,
                        lockingScript: try Script(bytes: [], maximumByteCount: 0)
                    ),
                    to: &writer
                )
            }
            Self.writeLegacySignatureOutput(outputs[inputIndex], to: &writer)
        }

        writer.writeUInt32LE(lockTime)
        writer.writeUInt32LE(UInt32(rawHashType))
        return .preimage(writer.bytes)
    }

    private static func writeLegacySignatureOutput(
        _ output: TransactionOutput,
        to writer: inout ByteWriter
    ) {
        writer.writeUInt64LE(output.satoshis)
        writer.writeVarBytes(output.lockingScript.bytes)
    }
}
