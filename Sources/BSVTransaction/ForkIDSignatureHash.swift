import BSVCore
import BSVCrypto
import BSVScript

/// Which transaction outputs a ForkID signature commits to.
public enum SignatureHashOutputs: UInt8, CaseIterable, Hashable, Sendable {
    case all = 0x01
    case none = 0x02
    case single = 0x03
}

/// A one-byte signature-hash flag was not a supported ForkID combination.
public enum SignatureHashTypeError: Error, Equatable, Sendable {
    case invalidForkIDValue(UInt8)
}

/// A validated Bitcoin SV ForkID signature-hash byte.
///
/// The replay-protection bit is always present. Constructing the value through
/// this type prevents undefined base modes and makes `ANYONECANPAY` explicit.
public struct ForkIDSignatureHashType: Hashable, Sendable {
    public static let forkIDMask: UInt8 = 0x40
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

    /// Parses exactly the six defined ForkID combinations.
    public init(rawValue: UInt8) throws {
        let allowedBits = Self.anyoneCanPayMask | Self.forkIDMask | 0x1f
        let baseValue = rawValue & 0x1f
        guard rawValue & Self.forkIDMask != 0,
              rawValue & ~allowedBits == 0,
              let outputs = SignatureHashOutputs(rawValue: baseValue)
        else { throw SignatureHashTypeError.invalidForkIDValue(rawValue) }
        self.init(
            outputs: outputs,
            anyoneCanPay: rawValue & Self.anyoneCanPayMask != 0
        )
    }

    /// The one-byte flag appended to a transaction signature.
    public var rawValue: UInt8 {
        outputs.rawValue
            | Self.forkIDMask
            | (anyoneCanPay ? Self.anyoneCanPayMask : 0)
    }

    public static let all = Self(outputs: .all)
    public static let none = Self(outputs: .none)
    public static let single = Self(outputs: .single)
}

public extension Transaction {
    /// Builds the replay-protected BSV signature preimage for one input.
    ///
    /// The input must carry its spent ``TransactionInput/sourceOutput``. The
    /// source amount and script code are consensus-committed fields and are
    /// never inferred from the unsigned transaction wire image. By default the
    /// source locking script is used, matching the Go SDK transaction façade.
    /// An interpreter that executed `OP_CODESEPARATOR` can supply the remaining
    /// script explicitly.
    func forkIDSignaturePreimage(
        inputIndex: Int,
        hashType: ForkIDSignatureHashType = .all,
        scriptCode: Script? = nil,
        limits: TransactionLimits
    ) throws -> [UInt8] {
        guard inputs.indices.contains(inputIndex) else {
            throw TransactionError.invalidInputIndex(inputIndex)
        }
        guard let sourceOutput = inputs[inputIndex].sourceOutput else {
            throw TransactionError.missingSourceOutput(inputIndex: inputIndex)
        }

        // This validates every collection/script against caller-selected
        // bounds before any aggregate serialization or hashing begins.
        _ = try serializedByteCount(limits: limits)
        let committedScript = scriptCode ?? sourceOutput.lockingScript
        guard UInt64(committedScript.byteCount) <= limits.maximumScriptByteCount else {
            throw TransactionError.scriptTooLarge(
                actual: UInt64(committedScript.byteCount),
                maximum: limits.maximumScriptByteCount
            )
        }

        let zeroHash = [UInt8](repeating: 0, count: 32)
        let hashPreviousOutputs: [UInt8]
        if hashType.anyoneCanPay {
            hashPreviousOutputs = zeroHash
        } else {
            let (capacity, overflow) = inputs.count.multipliedReportingOverflow(by: 36)
            guard !overflow else { throw TransactionError.serializedSizeOverflow }
            var writer = ByteWriter(capacity: capacity)
            for input in inputs {
                writer.write(input.previousOutput.wireBytes)
            }
            hashPreviousOutputs = BSVHashing.sha256d(writer.bytes).bytes
        }

        let hashSequences: [UInt8]
        if hashType.anyoneCanPay || hashType.outputs != .all {
            hashSequences = zeroHash
        } else {
            let (capacity, overflow) = inputs.count.multipliedReportingOverflow(by: 4)
            guard !overflow else { throw TransactionError.serializedSizeOverflow }
            var writer = ByteWriter(capacity: capacity)
            for input in inputs {
                writer.writeUInt32LE(input.sequence)
            }
            hashSequences = BSVHashing.sha256d(writer.bytes).bytes
        }

        let hashOutputs: [UInt8]
        switch hashType.outputs {
        case .all:
            var writer = ByteWriter()
            for output in outputs {
                Self.writeSignatureOutput(output, to: &writer)
            }
            hashOutputs = BSVHashing.sha256d(writer.bytes).bytes
        case .single where outputs.indices.contains(inputIndex):
            var writer = ByteWriter()
            Self.writeSignatureOutput(outputs[inputIndex], to: &writer)
            hashOutputs = BSVHashing.sha256d(writer.bytes).bytes
        case .single, .none:
            hashOutputs = zeroHash
        }

        let scriptLength = committedScript.byteCount
        let (fixedAndPrefix, fixedOverflow) = 156.addingReportingOverflow(
            CompactSize.encodedLength(of: UInt64(scriptLength))
        )
        let (capacity, scriptOverflow) = fixedAndPrefix.addingReportingOverflow(scriptLength)
        guard !fixedOverflow, !scriptOverflow else {
            throw TransactionError.serializedSizeOverflow
        }
        var writer = ByteWriter(capacity: capacity)
        writer.writeUInt32LE(version)
        writer.write(hashPreviousOutputs)
        writer.write(hashSequences)
        writer.write(inputs[inputIndex].previousOutput.wireBytes)
        writer.writeVarBytes(committedScript.bytes)
        writer.writeUInt64LE(sourceOutput.satoshis)
        writer.writeUInt32LE(inputs[inputIndex].sequence)
        writer.write(hashOutputs)
        writer.writeUInt32LE(lockTime)
        writer.writeUInt32LE(UInt32(hashType.rawValue))
        return writer.bytes
    }

    /// Double-SHA-256 digest of the corresponding ForkID signature preimage.
    func forkIDSignatureHash(
        inputIndex: Int,
        hashType: ForkIDSignatureHashType = .all,
        scriptCode: Script? = nil,
        limits: TransactionLimits
    ) throws -> Hash256 {
        BSVHashing.sha256d(try forkIDSignaturePreimage(
            inputIndex: inputIndex,
            hashType: hashType,
            scriptCode: scriptCode,
            limits: limits
        ))
    }

    private static func writeSignatureOutput(
        _ output: TransactionOutput,
        to writer: inout ByteWriter
    ) {
        writer.writeUInt64LE(output.satoshis)
        writer.writeVarBytes(output.lockingScript.bytes)
    }
}
