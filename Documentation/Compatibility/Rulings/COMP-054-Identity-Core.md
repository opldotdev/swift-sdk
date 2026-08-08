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
also requires the disclosure verifier key and checks that the wallet returns
exactly the requested proved-keyring fields. It verifies the certificate
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
