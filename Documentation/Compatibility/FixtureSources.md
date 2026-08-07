# Fixture sources and manifests

Static conformance fixtures are admitted only from an identified permissive or
public-domain source. Every fixture group has one provenance fragment under
`Tests/BSVConformanceTests/Fixtures/Manifests/` and its governing notice or
license under `Tests/BSVConformanceTests/Fixtures/Licenses/`.

## Fragment schema

Each immediate `Manifests/*.json` child represents one group and uses the
strict schema `bsv-fixture-manifest/1`:

```json
{
  "schema": "bsv-fixture-manifest/1",
  "id": "source-family-version",
  "source": {
    "url": "https://example.invalid/upstream",
    "revision": "exact-tag-or-commit"
  },
  "license": {
    "identifier": "SPDX-or-source-identifier",
    "file": "Licenses/source-family.txt",
    "sha256": "64-character-lowercase-sha256"
  },
  "notes": "optional group notes",
  "files": [
    {
      "originalPath": "upstream/path/vector.json",
      "localPath": "Permissive/Source/vector.json",
      "sha256": "64-character-lowercase-sha256",
      "transformation": "verbatim copy or an exact transformation description",
      "notes": "optional file notes"
    }
  ]
}
```

Fields not shown above are rejected. Paths are relative, forward-slash paths;
absolute paths, empty components, `.` or `..` components, backslashes, and
symlinks are forbidden. Fixture and license hashes describe the committed local
bytes, are required, and must be lowercase SHA-256. Fragment filenames determine deterministic merge order, and
group IDs and local paths must be unique across the merged set.

## Reserved metadata

`README.md` at the fixture root, `Manifests/**`, and `Licenses/**` are metadata,
not fixture data. Every other regular file below the fixture root must be
declared by exactly one fragment, and every declaration must resolve to a
regular file below that root. An empty `Manifests/` fragment set is valid while
the conformance foundation is bootstrapping.

## Adding a fixture group

Each later work packet adds one uniquely named manifest fragment, the referenced
license or notice, and only the data files declared by that fragment. Record the
original upstream path and exact revision, hash the final fixture and license bytes, and state
whether the file is verbatim or precisely how it changed. Run the fixture
manifest tests before submitting the packet.

Do not copy or mechanically reshape Open BSV Go SDK fixtures or unlicensed BRC
examples. The pinned Go SDK remains an external differential oracle; its output
is not committed as golden data. See the repository
[fixture license policy](../Planning/FixtureLicensePolicy.md) and
[vector inventory](VectorInventory.md) for the source boundary and approved
families.
