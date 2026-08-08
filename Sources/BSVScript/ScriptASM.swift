import BSVCore

/// Text form used when formatting Bitcoin Script operations.
public enum ScriptASMStyle: Equatable, Sendable {
    /// BRC-106 `OP_*` names and lowercase hexadecimal pushed data.
    case canonical
    /// BRC-14 SASM names without the `OP_` prefix.
    case compact
    /// Canonical opcode names emitted by the pinned Go SDK v1.3.3.
    case goSDK
}

/// Opcode-name interpretation for the BRC-106/Go Chronicle naming conflict.
public enum ScriptASMDialect: Equatable, Sendable {
    case brc106
    case goSDK
}

extension Script {
    /// Parses bounded BRC ASM or compact SASM in an explicitly selected dialect.
    ///
    /// Requiring `dialect` prevents conflicting NOP names from silently changing
    /// bytes between BRC-106 and Go SDK text. Tokens must be separated by exactly
    /// one ASCII space. Opcode aliases are
    /// accepted, while hexadecimal tokens are encoded with the shortest push
    /// length prefix used by the Go SDK. Consequently, ASM preserves program
    /// meaning but does not preserve a non-minimal push opcode choice.
    public init(
        asm: String,
        dialect: ScriptASMDialect,
        maximumScriptByteCount: Int,
        maximumASMByteCount: Int
    ) throws {
        guard maximumScriptByteCount >= 0 else {
            throw ScriptError.invalidMaximumScriptByteCount(maximumScriptByteCount)
        }
        guard maximumASMByteCount >= 0 else {
            throw ScriptError.invalidMaximumASMByteCount(maximumASMByteCount)
        }

        var utf8Count = 0
        for _ in asm.utf8 {
            guard utf8Count < maximumASMByteCount else {
                let (next, overflow) = maximumASMByteCount.addingReportingOverflow(1)
                throw ScriptError.asmTooLarge(
                    observedAtLeast: overflow ? Int.max : next,
                    maximum: maximumASMByteCount
                )
            }
            utf8Count += 1
        }

        if asm.isEmpty {
            try self.init(bytes: [], maximumByteCount: maximumScriptByteCount)
            return
        }

        let utf8 = Array(asm.utf8)
        if utf8.first == 0x20 {
            throw ScriptError.invalidASMSpacing(byteOffset: 0)
        }
        if utf8.last == 0x20 {
            throw ScriptError.invalidASMSpacing(byteOffset: utf8.count - 1)
        }
        for index in utf8.indices {
            let byte = utf8[index]
            if byte == 0x20, index > 0, utf8[index - 1] == 0x20 {
                throw ScriptError.invalidASMSpacing(byteOffset: index)
            }
            if byte == 0x09 || byte == 0x0a || byte == 0x0b || byte == 0x0c || byte == 0x0d {
                throw ScriptError.invalidASMSpacing(byteOffset: index)
            }
        }

        var result = try Script(bytes: [], maximumByteCount: maximumScriptByteCount)
        for (tokenIndex, tokenBytes) in utf8.split(separator: 0x20).enumerated() {
            let token = String(decoding: tokenBytes, as: UTF8.self)
            if let opcode = Opcode(asmName: token, dialect: dialect) {
                guard !opcode.isDataPush else {
                    throw ScriptError.pushOpcodeRequiresData(opcode)
                }
                try result.append(opcode, maximumScriptByteCount: maximumScriptByteCount)
                continue
            }

            let data: [UInt8]
            do {
                data = try Hex.decode(
                    token,
                    maximumDecodedByteCount: maximumScriptByteCount
                )
            } catch let error as TextEncodingError {
                if case .invalidCharacter = error {
                    throw ScriptError.invalidASMToken(index: tokenIndex)
                }
                throw ScriptError.invalidASMData(index: tokenIndex, error)
            }
            try result.appendPushData(data, maximumScriptByteCount: maximumScriptByteCount)
        }
        self = result
    }

    /// Formats bounded BRC ASM or compact SASM.
    ///
    /// Pushed values are lowercase hexadecimal. Empty non-minimal pushes are
    /// normalized to `OP_FALSE`/`false`, matching their stack semantics.
    public func asm(
        style: ScriptASMStyle = .canonical,
        maximumPushDataByteCount: Int,
        maximumASMByteCount: Int
    ) throws -> String {
        guard maximumASMByteCount >= 0 else {
            throw ScriptError.invalidMaximumASMByteCount(maximumASMByteCount)
        }
        let operations = try operations(maximumPushDataByteCount: maximumPushDataByteCount)
        var tokens: [String] = []
        tokens.reserveCapacity(operations.count)
        var outputByteCount = 0

        for operation in operations {
            let token: String
            switch operation {
            case .opcode(let opcode):
                switch style {
                case .canonical: token = opcode.name
                case .compact: token = opcode.compactName
                case .goSDK: token = opcode.goSDKName
                }
            case .push(_, let data):
                if data.isEmpty {
                    switch style {
                    case .canonical: token = Opcode.zero.name
                    case .compact: token = Opcode.zero.compactName
                    case .goSDK: token = Opcode.zero.goSDKName
                    }
                } else {
                    token = Hex.encode(data)
                }
            }

            let separatorCount = tokens.isEmpty ? 0 : 1
            let (withSeparator, separatorOverflow) = outputByteCount.addingReportingOverflow(separatorCount)
            let (nextCount, tokenOverflow) = withSeparator.addingReportingOverflow(token.utf8.count)
            guard !separatorOverflow, !tokenOverflow, nextCount <= maximumASMByteCount else {
                throw ScriptError.asmOutputTooLarge(
                    actual: tokenOverflow || separatorOverflow ? Int.max : nextCount,
                    maximum: maximumASMByteCount
                )
            }
            outputByteCount = nextCount
            tokens.append(token)
        }
        return tokens.joined(separator: " ")
    }
}
