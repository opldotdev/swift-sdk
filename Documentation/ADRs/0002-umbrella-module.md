# ADR-0002: Convenience umbrella with stable feature imports

- Status: Accepted
- Date: 2026-08-07
- Owners: Open Protocol Labs

## Context

Swift has no supported general-purpose module re-export declaration. Typealias
facades cannot re-export top-level functions and operators cleanly.

## Decision

Feature modules are the stable import surface. The `BSV` convenience module uses
`@_exported import`, confined to `Sources/BSV/Exports.swift`.

## Consequences

Consumers can use `import BSV` or narrower feature imports. The underscored
attribute is isolated and may be replaced without changing feature modules if
Swift adds a supported mechanism.
