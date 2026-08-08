import BSVScript

package struct DecodedScriptInstruction: Sendable {
    let opcode: Opcode
    let data: [UInt8]?
    let offset: Int
}

package enum ScriptInstructionDecoder {
    static func next(
        bytes: [UInt8],
        offset: inout Int,
        phase: ScriptPhase,
        maximumConsensusPushByteCount: Int,
        maximumResourcePushByteCount: Int
    ) throws -> DecodedScriptInstruction {
        let opcodeOffset = offset
        let opcode = Opcode(rawValue: bytes[offset])
        offset += 1

        let length: Int
        switch opcode.rawValue {
        case 0x01...0x4b:
            length = Int(opcode.rawValue)
        case Opcode.pushData1.rawValue:
            guard bytes.count - offset >= 1 else {
                throw ScriptExecutionError.malformedScript(
                    phase: phase,
                    offset: opcodeOffset,
                    cause: .truncatedPushLength(
                        expected: 1,
                        remaining: bytes.count - offset
                    )
                )
            }
            length = Int(bytes[offset])
            offset += 1
        case Opcode.pushData2.rawValue:
            guard bytes.count - offset >= 2 else {
                throw ScriptExecutionError.malformedScript(
                    phase: phase,
                    offset: opcodeOffset,
                    cause: .truncatedPushLength(
                        expected: 2,
                        remaining: bytes.count - offset
                    )
                )
            }
            length = Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)
            offset += 2
        case Opcode.pushData4.rawValue:
            guard bytes.count - offset >= 4 else {
                throw ScriptExecutionError.malformedScript(
                    phase: phase,
                    offset: opcodeOffset,
                    cause: .truncatedPushLength(
                        expected: 4,
                        remaining: bytes.count - offset
                    )
                )
            }
            let declared = UInt32(bytes[offset])
                | (UInt32(bytes[offset + 1]) << 8)
                | (UInt32(bytes[offset + 2]) << 16)
                | (UInt32(bytes[offset + 3]) << 24)
            guard UInt64(declared) <= UInt64(Int.max) else {
                throw ScriptExecutionError.malformedScript(
                    phase: phase,
                    offset: opcodeOffset,
                    cause: .pushLengthNotRepresentable(declared)
                )
            }
            length = Int(declared)
            offset += 4
        default:
            return DecodedScriptInstruction(
                opcode: opcode,
                data: nil,
                offset: opcodeOffset
            )
        }

        if length > maximumConsensusPushByteCount {
            throw ScriptExecutionError.consensus(.pushDataTooLarge(
                actual: length,
                maximum: maximumConsensusPushByteCount
            ))
        }
        if length > maximumResourcePushByteCount {
            throw ScriptExecutionError.resourceBudgetExceeded(.pushDataByteCount(
                actual: length,
                maximum: maximumResourcePushByteCount
            ))
        }
        let remaining = bytes.count - offset
        guard length <= remaining else {
            throw ScriptExecutionError.malformedScript(
                phase: phase,
                offset: opcodeOffset,
                cause: .truncatedPushData(expected: length, remaining: remaining)
            )
        }
        let data = Array(bytes[offset..<(offset + length)])
        offset += length
        return DecodedScriptInstruction(opcode: opcode, data: data, offset: opcodeOffset)
    }
}
