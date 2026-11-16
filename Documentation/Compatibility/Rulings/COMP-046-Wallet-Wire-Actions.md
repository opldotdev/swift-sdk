# COMP-046: Wallet-wire action calls follow TypeScript 4.1.1

Status: Accepted. Revised: calls 1 through 7 now use the `@bsv/sdk` 4.1.1
layouts instead of pinned Go v1.3.3.

## Why the wire follows TypeScript

TypeScript wallets and apps are the 1Sat wallet's peers (COMP-045). The
two-step `createAction` and `signAction` flow, paged history and BRC-112
balances must cross the wire between Swift and TypeScript in both directions.

## Ruling

- **createAction result.** Txid flag and display-order txid, tx flag and
  Atomic BEEF, `noSendChange` count or `-1` and outpoints, `sendWithResults`
  count or `-1` with display-order txid and status byte, then the signable
  flag with transaction and reference. There is no extra leading byte. The
  txid and the signable transaction may each be absent.
- **signAction result.** Txid flag and display-order txid, tx flag and Atomic
  BEEF, `sendWithResults` as above. Either part may be absent.
- **Transaction IDs** in results, `knownTxids` and `sendWith` use display
  order, as TypeScript writes `toArray(txid, 'hex')`.
- **abortAction refusal.** `aborted: false` is the error frame with code 8 and
  `The wallet refused to abort this action because it has already been
  broadcast`. The transceiver reads code 8 as `aborted: false`.
- **List totals.** `totalActions` and `totalOutputs` count every match. The
  page follows the total with no record count and ends at the end of the
  frame. A page may be shorter than its total. A Swift processor checks a
  wallet's page in TypeScript order and with its text: more records than the
  total (`Invalid listOutputs result totalOutputs: expected at least N`), more
  than the request's limit, BRC-100 default 10 (`... expected at most the
  requested limit of N`, `wallet/WalletResultValidation.ts:1932-1951`), then a
  total above UInt32 (`Invalid listOutputs result total: expected an integer
  from 0 to 4294967295, received N`, `WalletWireProcessor.ts:178-191`). A
  transceiver stops reading at the request's limit.
- **createAction options.** `noSendChange` is accepted with or without
  `noSend`, as TypeScript validates and reads it
  (`wallet/validationHelpers.ts:680`, `WalletWireProcessor.ts:539-556`).
- **BRC-112 balance.** For a basket matching `^(?:balance |p [^ ]+ balance )`,
  `totalOutputs` is a UInt64 balance with no outputs and no BEEF
  (`walletIsBalanceBasket`). Other totals stay within UInt32.
- **Spendable listOutputs extension.** A request may end with one `01` byte.
  The answer then starts with a `-1` marker and each record carries a
  spendable byte after its locking script. Without the extension a
  non-spendable output is refused with the TypeScript message.
- **Optional values.** Empty `createAction` inputs (count 0) and absent inputs
  (`-1`) are distinct and both allowed. An absent tag or label list reads as
  empty. listActions input and output scripts may be absent. Spend indexes may
  arrive in any order; duplicates are rejected.

Swift keeps explicit BEEF limits, payload-bounded writing, checked arithmetic,
exact discriminators and full consumption.

## Divergence from pinned Go v1.3.3

Go uses its own createAction and signAction result layouts and wire-order
txids there, requires list totals to equal the record count, and rejects
absent result parts, unsorted spends, empty inputs and zero-length list
entries. `WalletWireActionGoOracleTests` asserts that pinned Go cannot read
the TypeScript createAction and signAction results. All other canonical action
frames still match Go byte for byte.

## Tests

`WalletWireActionAdversarialTests`, `WalletWireActionTests` and
`WalletWireTypeScript41VectorTests` cover the layouts with TypeScript source
citations. `WalletWireTypeScriptOracleTests` replays live TypeScript frames.
