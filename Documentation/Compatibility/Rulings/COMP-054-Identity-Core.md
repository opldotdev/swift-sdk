# COMP-054: Bounded transport-neutral identity core

## Decision

`BSVIdentity` provides immutable display models, the nine pinned identity-type
identifiers, bounded identity parsing and resolution, and public certificate
disclosure through an injected wallet and broadcaster.

The client is generic over `WalletInterface`. It does not erase the wallet
type. The disclosure operation is generic over `Broadcaster` and uses the exact
value supplied by the caller. The wallet must already carry its originator
scope. The identity layer does not duplicate or silently replace that scope.

Every operation requires `IdentityLimits`. The limits cap identity count,
revealed field count, each display string, aggregate display data, disclosure
JSON, certificate work, wallet values, PushDrop construction, BEEF, and the
subject transaction. The disclosure JSON writer checks capacity before each
append and writes large Base64 values directly under the limit.

## Go differences

Swift requires a wallet. It does not create a random fallback wallet. Swift
proves the disclosure keyring to the fixed "anyone" verifier and checks that
the wallet returns exactly the requested proved-keyring fields. It verifies the certificate
signature before any disclosure wallet call.

Swift uses canonical lowercase compressed-key hex for display identity keys.
It treats every unrecognized certificate type as unknown. It accepts only
output index zero because the action contains one output.

The Swift client uses a caller-supplied broadcaster. It does not create an HTTP
client, select an overlay host, infer a network, or perform an automatic retry.
Cancellation remains cancellation. Other wallet and broadcaster failures map
to bounded errors that do not retain source diagnostics.

The exported Go testable client, mock verifier, transaction-creator seam, and
completed-wallet fallback are not part of the Swift product. Tests use typed
capability implementations around the production client.

## Compatibility

The known certificate identifiers, display labels, default images, URLs,
PushDrop lock-before layout, action descriptions, token amount, and canonical
disclosure JSON schema match pinned Go v1.3.3 where Go behavior is valid.
GO-011 through GO-020 record confirmed defects that Swift does not reproduce.

## TypeScript 4.1.1 alignment (2026-11-16)

Live overlay hosts run the TypeScript `tm_identity` topic manager
(`packages/overlays/topics/src/identity/identityTokenValidation.ts`). It
admits a token only when the locking key is the "anyone" key's BRC-42 view of
the certificate subject under protocol `[1, "identity"]`, key ID `"1"`, the
token has exactly two fields in a five-chunk script, the signature verifies
under the same key, and the keyring decrypts with the "anyone" key.

- The default `IdentityClientOptions.protocolID` is now `[1, "identity"]`
  (TypeScript `identity/types/index.ts` `DEFAULT_IDENTITY_CLIENT_OPTIONS`).
  The previous Swift default, `[2, "identity"]`, locked to a key the topic
  manager refuses.
- `publiclyRevealAttributes` and `publiclyRevealAttributesSimple` no longer
  take a `verifier`. They always prove to the "anyone" public key
  (`IdentityPublicReveal.verifierPublicKeyHex`), as TypeScript
  `IdentityClient.publiclyRevealAttributes` does. A keyring for any other
  verifier produced a token the overlay refuses.
- Badge links for the registrant, anyone, self, and unknown identities use the
  TypeScript URL `https://bsv-blockchain.github.io/ts-sdk/reference/identity/`.

Tests build the expected locking key by hand from the subject key and invoice
`1-identity-1`, check the five-chunk script, verify the signature, and check
that the previous `2-identity-1` key is not used.
