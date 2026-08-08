# ADR-0002: Convenience umbrella with stable feature imports

- Status: Accepted
- Date: 2026-08-07
- Owners: Open Protocol Labs

## Context

Swift has no supported general-purpose module re-export declaration. Typealias
facades cannot re-export top-level functions and operators cleanly.

## Decision

Feature modules are the stable import surface. The `BSV` convenience module uses
`@_exported import`, confined to `Sources/BSV/Exports.swift`. It re-exports only
the modern feature modules, including `BSVMessage`. `BSVCompat` is a public
opt-in feature module and is not a `BSV` dependency or re-export.

## Consequences

Consumers can use `import BSV`, narrower modern feature imports, or the separate
`import BSVCompat` compatibility surface. The underscored attribute is isolated
to each module's export file and may be replaced if Swift adds a supported
mechanism.
