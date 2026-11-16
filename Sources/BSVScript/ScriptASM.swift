import BSVCore

/// Text form used when formatting Bitcoin Script operations.
public enum ScriptASMStyle: Equatable, Sendable {
    /// BRC-106 `OP_*` names and lowercase hexadecimal pushed data.
    case canonical
    /// BRC-14 SASM names without the `OP_` prefix.
    case compact
    /// Canonical opcode names emitted by the pinned Go SDK v1.3.3.
    case goSDK
    /// @bsv/sdk 4.1.1 `Script.toASM` opcode names (`OP_0`, `OP_1`,
    /// Chronicle names). Where 4.1.1 writes text it cannot read back (a
    /// top-level OP_RETURN, zero-length pushes), this follows the unmerged
    /// @bsv/sdk fixes: the OP_RETURN is named, the bytes after it are read
    /// leniently, and zero-length pushes are written as `OP_0`.
    case typeScript
}

/// Opcode-name interpretation for the BRC-106/Go/TypeScript naming conflicts.
public enum ScriptASMDialect: Equatable, Sendable {
    case brc106
    case goSDK
    /// The token rules of @bsv/sdk 4.1.1 `Script.fromASM`: its opcode table,
    /// `0` and `-1`, lowercase hexadecimal with odd lengths padded with a
    /// leading zero, and `OP_PUSHDATA1/2/4 <length> <hex>` with the push
    /// opcode kept. Swift also requires that length to be the data's byte
    /// count, written in plain decimal.
    case typeScript
}

extension Script {
    /// Parses bounded ASM in the selected dialect.
    ///
    /// The default `.typeScript` dialect reads what @bsv/sdk 4.1.1 `fromASM`
    /// reads, so ASM written by Swift keeps its bytes in @bsv/sdk. Empty text
    /// is an empty script (4.1.1 reads it as `00`). `.brc106` reads
    /// BRC-106 ASM and compact SASM; `.goSDK` reads the pinned Go SDK's
    /// names. The dialects disagree on some NOP names, so pick the one that
    /// wrote the text. Tokens must be separated by exactly one ASCII space.
    /// Hexadecimal tokens are encoded with the shortest push length prefix.
    /// Consequently, ASM preserves program meaning but does not preserve a
    /// non-minimal push opcode choice, except for the `.typeScript` form
    /// `OP_PUSHDATA1 <length> <hex>` (and its PUSHDATA2/4 forms), whose
    /// decimal length must equal the data's byte count. A trailing
    /// `OP_PUSHDATA1` (or `OP_PUSHDATA1 0`) with no data token is an empty
    /// push, as in @bsv/sdk.
    public init(
        asm: String,
        dialect: ScriptASMDialect = .typeScript,
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
        let tokens = utf8.split(separator: 0x20).map { String(decoding: $0, as: UTF8.self) }
        let padsOddHex = dialect == .typeScript
        var tokenIndex = 0
        while tokenIndex < tokens.count {
            let token = tokens[tokenIndex]
            if let opcode = Opcode(asmName: token, dialect: dialect) {
                guard opcode.isDataPush else {
                    try result.append(opcode, maximumScriptByteCount: maximumScriptByteCount)
                    tokenIndex += 1
                    continue
                }
                // Only the TypeScript table names push opcodes, and only
                // OP_PUSHDATA1/2/4: those take a length and a data token.
                guard dialect == .typeScript else {
                    throw ScriptError.pushOpcodeRequiresData(opcode)
                }
                let data: [UInt8]
                if tokenIndex + 2 < tokens.count {
                    // @bsv/sdk decodes this token without its raw-token
                    // check, so uppercase hexadecimal is accepted here.
                    data = try Self.asmData(
                        tokens[tokenIndex + 2],
                        index: tokenIndex + 2,
                        padsOddLength: true,
                        requiresLowercase: false,
                        maximumByteCount: maximumScriptByteCount
                    )
                } else {
                    // @bsv/sdk reads a missing data token as no data, so a
                    // trailing `OP_PUSHDATA1` or `OP_PUSHDATA1 0` is `4c00`.
                    data = []
                }
                if tokenIndex + 1 < tokens.count {
                    let lengthToken = tokens[tokenIndex + 1]
                    guard lengthToken == String(data.count) else {
                        throw ScriptError.invalidASMPushDataLength(index: tokenIndex + 1)
                    }
                }
                try result.appendPushData(
                    data,
                    using: opcode,
                    maximumScriptByteCount: maximumScriptByteCount
                )
                tokenIndex += min(3, tokens.count - tokenIndex)
                continue
            }

            let data = try Self.asmData(
                token,
                index: tokenIndex,
                padsOddLength: padsOddHex,
                requiresLowercase: dialect == .typeScript,
                maximumByteCount: maximumScriptByteCount
            )
            try result.appendPushData(data, maximumScriptByteCount: maximumScriptByteCount)
            tokenIndex += 1
        }
        self = result
    }

    private static func asmData(
        _ token: String,
        index: Int,
        padsOddLength: Bool,
        requiresLowercase: Bool,
        maximumByteCount: Int
    ) throws -> [UInt8] {
        // @bsv/sdk re-encodes a raw data token and rejects it unless the
        // text is unchanged, so it refuses uppercase hexadecimal.
        if requiresLowercase, token.utf8.contains(where: { (0x41...0x46).contains($0) }) {
            throw ScriptError.invalidASMToken(index: index)
        }
        let hex = padsOddLength && token.utf8.count % 2 == 1 ? "0" + token : token
        do {
            return try Hex.decode(hex, maximumDecodedByteCount: maximumByteCount)
        } catch let error as TextEncodingError {
            if case .invalidCharacter = error {
                throw ScriptError.invalidASMToken(index: index)
            }
            throw ScriptError.invalidASMData(index: index, error)
        }
    }

    /// Formats bounded ASM in the selected style.
    ///
    /// The default `.typeScript` style writes @bsv/sdk 4.1.1 opcode names and
    /// follows the unmerged @bsv/sdk fixes where 4.1.1 text cannot be read
    /// back (see `ScriptASMStyle.typeScript`). Pushed values are lowercase
    /// hexadecimal. Empty non-minimal pushes are normalized to the style's
    /// name for OP_0, matching their stack semantics.
    ///
    /// Malformed pushes are errors, except in the `.typeScript` style after
    /// an OP_RETURN outside any conditional, where @bsv/sdk keeps the
    /// remaining bytes as data: a truncated push there is written as the
    /// bytes that remain, or `OP_0` when none remain. That text is lossy: it
    /// reads back as a different, well-formed script (`6a056869` is written
    /// `OP_RETURN 6869`, which reads as `6a026869`). Do not use it as a
    /// script's identity or as a well-formedness check; `style: .canonical`
    /// or `operations(maximumPushDataByteCount:)` reject malformed pushes.
    public func asm(
        style: ScriptASMStyle = .typeScript,
        maximumPushDataByteCount: Int,
        maximumASMByteCount: Int
    ) throws -> String {
        guard maximumASMByteCount >= 0 else {
            throw ScriptError.invalidMaximumASMByteCount(maximumASMByteCount)
        }
        let operations = try operations(
            maximumPushDataByteCount: maximumPushDataByteCount,
            lenientAfterTopLevelReturn: style == .typeScript
        )
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
                case .typeScript: token = opcode.typeScriptName
                }
            case .push(_, let data):
                if data.isEmpty {
                    switch style {
                    case .canonical: token = Opcode.zero.name
                    case .compact: token = Opcode.zero.compactName
                    case .goSDK: token = Opcode.zero.goSDKName
                    case .typeScript: token = Opcode.zero.typeScriptName
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
