# COMP-024: Checked transaction fees and change

## Context

Go SDK v1.3.3 estimates transaction size using a signed input's actual
unlocking script or an unsigned input's unlocking-template estimate, then
rounds `bytes / 1000 * rate` upward through floating-point arithmetic. Its
change mutator has incidental failure behavior: totals can wrap, a transaction
without change outputs can divide by zero, and random change distribution is
declared but returns “not implemented.”

## Ruling

Swift preserves the valid size model and decimal 1,000-byte kilobyte. It uses
checked integer arithmetic, actual nonempty unlocking scripts in preference to
explicit unsigned estimates, and caller-selected transaction/script limits.
Missing or invalid estimates, overflows, overspending, and underfunding are
typed errors.

Change markers and unsigned-script estimates are construction metadata. They
do not alter transaction wire bytes, equality, hashing, or the transaction ID.
Equal distribution is atomic. If the available remainder cannot give every
change output one satoshi, change outputs are removed and the remainder is
paid as additional miner fee. Division dust is also additional fee. A
transaction with no marked change output is left unchanged once it is proven
to pay at least the required fee.

## Consequences

Valid fees match the pinned Go SDK when both are given the same explicit
projection. Swift's compressed P2PKH convenience uses the safe 107-byte
maximum: libsecp256k1 guarantees low-S but not low-R, so strict DER can occupy
71 bytes. Go's fixed 106-byte estimate can therefore undercount a rare
signature by one byte. Floating-point precision, unsigned underflow,
divide-by-zero, and an unusable random mode are not compatibility promises.
Additional distribution policies require a complete deterministic or
randomness-injected design and their own tests before becoming public API.
