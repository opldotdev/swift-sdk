# COMP-047: Strict Script JSON

## Context

Go v1.3.3 marshals a Script as one quoted lowercase hexadecimal string. Its
exported `Script.UnmarshalJSON` method does not parse one JSON string token. It
removes quote bytes from both ends and sends the remaining bytes to the
hexadecimal decoder.

This method accepts uppercase hexadecimal, an unquoted hexadecimal token, and
extra quote bytes at an end. These inputs are not one canonical Script JSON
value. A later marshal operation emits a different lowercase quoted document.
The method rejects JSON escape sequences because it sends the backslash and
escape bytes to the hexadecimal decoder.

## Ruling

Swift accepts exactly one unescaped lowercase hexadecimal JSON string. It can
have RFC JSON space, tab, carriage return, or line feed bytes before or after
the string. Swift rejects uppercase hexadecimal, escape sequences, non-string
tokens, non-JSON whitespace, and trailing data.

Callers must provide separate maximum JSON and Script byte counts. Swift checks
the JSON limit before it scans the document. It checks the decoded Script size
before it creates the Script value. Serialization uses checked size arithmetic
and emits only the canonical lowercase quoted form.

The differential oracle calls the pinned marshal and unmarshal methods
directly. It transports each inner JSON document as lowercase hexadecimal so
the outer oracle protocol cannot change it. The adapter limits Script input to
128 KiB and JSON document input to 256 KiB plus two quote bytes.

## Consequences

Canonical Script JSON documents have the same bytes in Swift and Go v1.3.3.
Swift does not import the pinned unmarshal method's invalid or lossy token
forms. Tests cover canonical data in both directions, empty and all-byte
Scripts, uppercase normalization, escaped strings, non-string tokens, trailing
quote bytes, exact limits, and maximum plus one failures.
