# COMP-022: Script ASM normalization and malformed programs

## Context

Bitcoin ASM describes operations rather than preserving their original byte
encoding. Go SDK v1.3.3 formats pushed bytes without their length opcode, so
parsing that text emits the SDK's shortest push-length form. Its formatter also
returns an empty string for malformed push programs, and its parser silently
ignores an error when a standalone push opcode name is supplied.

The SDKs also disagree on opcode names. BRC-106 prints 0xb6...0xbc as
`OP_NOP4`...`OP_NOP10`. @bsv/sdk 4.x prints the restored Chronicle names at
0xb3...0xb7 and reads `OP_NOP4`...`OP_NOP8` as their aliases, prints 0xb8 and
0xb9 as `OP_NOP9`/`OP_NOP10`, and names 0xba...0xf8 `OP_NOP11`...`OP_NOP73`,
0xf9 `OP_SMALLDATA` and 0xfc `OP_NOP77`. Go names 0x50 `OP_BASE` and the high
bytes `OP_UNKNOWNn`. The same text can therefore mean different bytes in
different SDKs: BRC-106 `OP_NOP4` (0xb6) is 0xb3 in @bsv/sdk, and @bsv/sdk
`OP_NOP9` (0xb8) is 0xbb in BRC-106.

## Ruling

Swift ASM parsing and formatting are explicitly byte-bounded and take a named
dialect. Three dialects exist:

- `.typeScript` (the default for both parsing and formatting) reads what
  @bsv/sdk 4.1.1 `Script.fromASM` reads and writes its opcode names: its
  opcode table and first-listed output names (`OP_0`, `OP_1`, Chronicle names,
  `OP_NOP9`...`OP_NOP77`, `OP_SMALLDATA`), the bare tokens `0` and `-1`,
  lowercase hexadecimal with odd lengths padded with a leading zero (`3` is
  the byte 0x03, and `1` is data, not OP_1), and `OP_PUSHDATA1/2/4 <length>
  <hex>`, which keeps the named push opcode. Where 4.1.1 `toASM` is not
  reversible (a top-level OP_RETURN, zero-length pushes, empty input) Swift
  follows the two unmerged @bsv/sdk fixes (`cursor/script-op-return-asm-954d`,
  `cursor/script-fromasm-empty-09e9`): a zero-length push prints as `OP_0`,
  empty text is the empty script, and an OP_RETURN outside any
  OP_IF/OP_NOTIF/OP_VERIF/OP_VERNOTIF block is printed by name, followed by
  the remaining bytes read leniently, as @bsv/sdk keeps them as one data
  chunk. A truncated push there prints as the bytes that remain (`OP_0` when
  none remain).
- `.brc106` formats BRC-106 names (`OP_FALSE` and `OP_TRUE`); compact output
  follows BRC-14 SASM. It accepts common unambiguous aliases.
- `.goSDK` preserves the pinned Go SDK's conflicting Chronicle/NOP map for
  exact interop.

Text Swift writes reads back to the same bytes in @bsv/sdk 4.1.1. The reverse
does not hold where 4.1.1 output cannot be read back by 4.1.1 either:

| Script bytes | @bsv/sdk 4.1.1 | Swift default (and the unmerged fixes) |
|---|---|---|
| `006a0568656c6c6f` | `toASM`: `OP_0 0568656c6c6f` (reads back as `00060568656c6c6f`) | `OP_0 OP_RETURN 68656c6c6f` |
| `6a` | `toASM`: empty string | `OP_RETURN` |
| `4c00` | `toASM`: a blank token | `OP_0` |
| `00634c006851` | `toASM`: `OP_0 OP_IF  OP_ENDIF OP_1` (two spaces) | `OP_0 OP_IF OP_0 OP_ENDIF OP_1` |
| empty | `fromASM("")`: script `00` | empty script |

Swift rejects 4.1.1's blank tokens with `invalidASMSpacing`.

The lenient OP_RETURN tail is lossy for malformed pushes: `6a056869` (a push
of five bytes with two present) prints as `OP_RETURN 6869`, which reads back
as `6a026869`; `6a4d01` prints as `OP_RETURN OP_0`, which reads back as
`6a00`. The unmerged @bsv/sdk fix behaves the same way. Do not use default ASM
as a script's identity or as a well-formedness check: `style: .canonical` and
`operations(maximumPushDataByteCount:)` reject malformed pushes.

Differences from 4.1.1 `fromASM` kept on purpose:

- The `OP_PUSHDATA*` length must be the data's byte count in plain decimal
  (`5`, not `05`). @bsv/sdk ignores it, and silently writes a wrong length
  byte when the data does not fit the named opcode; Swift throws
  `invalidASMPushDataLength` or `dataTooLargeForPush`.
- A trailing `OP_PUSHDATA1` (or `OP_PUSHDATA1 0`) with no data token is an
  empty push (`4c00`), as in @bsv/sdk. `OP_PUSHDATA1 5` with no data token is
  `4c00` in @bsv/sdk; Swift throws `invalidASMPushDataLength`, because the
  length does not match.
- Like @bsv/sdk, raw data tokens must be lowercase (`ABCD` throws
  `invalidASMToken`), while the data token of `OP_PUSHDATA*` accepts either
  case. The other dialects accept uppercase data.

The TypeScript dialect is the default because the package has no callers that
depend on BRC-106 or Go output, and it is the one whose text @bsv/sdk reads
back to the same bytes. BRC-106 and Go output remain available by
passing `style: .canonical` or `.goSDK`, and their parsers by passing
`dialect: .brc106` or `.goSDK`. The default output therefore spells OP_0 and
OP_1 as `OP_0`/`OP_1`, not the BRC-106 `OP_FALSE`/`OP_TRUE`; both parse in
every dialect.

Pushed data is lowercase hexadecimal and non-minimal push forms normalize on
reassembly, except the TypeScript `OP_PUSHDATA*` form above. Standalone push
opcodes, malformed or truncated programs (outside the TypeScript OP_RETURN
tail), ambiguous spacing, a wrong `OP_PUSHDATA*` length, and exhausted
resource limits return typed errors instead of an empty result or partial
script. An empty string is the empty script in every dialect.

Changing the default from `.canonical`/`.brc106` to `.typeScript` changes the
output of `asm()` and the reading of `Script(asm:)` without a compile error:
`OP_FALSE`/`OP_TRUE` print as `OP_0`/`OP_1`, 0xb6 prints as `OP_LSHIFTNUM`
(was `OP_NOP4`), 0xb8 as `OP_NOP9` (was `OP_NOP6`), malformed pushes after a
top-level OP_RETURN print instead of throwing, and `1` reads as data.

BRC-14's compact spelling is ambiguous for `OP_10` through `OP_16`, because
bare `10` through `16` are also valid pushed-data hex. Swift always interprets
the bare forms as data, matching Go ASM, and retains `OP_10`...`OP_16` in
compact output so formatting and parsing cannot silently change the program.
The TypeScript dialect accepts no compact names at all: like @bsv/sdk, it reads
any token outside its `OP_*` table, `0` and `-1` as hexadecimal.

## Consequences

Use raw script bytes or hexadecimal when exact push-opcode preservation matters.
Use ASM for readable semantic interchange, and parse text with the dialect of
the SDK that wrote it. Differential tests cover the stable Go behavior; the
TypeScript dialect is pinned against every name in @bsv/sdk `OP.ts` and the
`Script.test.ts` vectors, and focused Swift tests pin the deliberate
error-policy changes.
