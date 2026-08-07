# Fixture manifest fragments

Conformance packets add one uniquely named `*.json` fragment per fixture group
according to `Documentation/Compatibility/FixtureSources.md`. The directory may
be empty only in a newly bootstrapped package; the loader also supports that
state so provenance infrastructure can land before the first primitive.
Every fragment must include the lowercase SHA-256 of its referenced license or
notice bytes as `license.sha256`.
