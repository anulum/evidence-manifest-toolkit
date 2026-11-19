<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance
-->

# Changelog

## [Unreleased]

Initial local repository metadata, deterministic infrastructure guards, safe workflow preparation, locked development tools, native documentation and public-boundary conformance tests. No runtime package or public release is declared.

The conformance vectors gain their signed-statement part: real envelopes
from the repository's verification fixture, changed copies of them, and
the two published test-vector public keys. Its cases cover key identity,
the scope digest with claim ids in UTF-16 order, envelope parsing and its
refusals, the domain-prefixed message and Ed25519 verification. No
private key is part of the pack.

The evidence core conformance vectors, version 1, are one language-neutral
JSON pack of 118 cases: the admission order the contract states and the
reference cases for canonical bytes and both byte-reference bases. Each
case is bytes, limits and the expected result, and the pack states its own
case semantics, so another implementation can run it. A runner checks the
pack's digest and its sources and runs every case through the public
operations.

The evidence core contract, version 1, states the canonical form, byte
identity, the evidence-manifest schema and the legacy signed-statement
profile as the source implements them. A contract test binds every value
the page states to its source. The page is a specification only; it
changes no inventory and claims no capability.

The workflow guard accepts an optional bounded local six-role outcome file.
Passing requires both the complete static graph and six successful outcomes;
adverse states emit the existing refusal report. Other guards retain their
existing invocation contracts.

Bounded input reads retain one descriptor owner through cancellation, preserving
the interruption result while closing the file exactly once.

The dependency guard reports parsed TOML container drift with its authored
policy reason, including scalar and array values for `tool` and `mypy`.

The prepared test workflow acquires its pinned native fixtures, original
interpreter wheels and real strict audit input before invoking tests.

The provenance guard runs the installed REUSE tool in isolated Python mode,
so a received repository module cannot replace or execute as that producer.


Native licence checking now receives a complete byte-verified public tree, so
ignored cache discovery cannot consume the licence deadline and received Git
ignore rules cannot conceal public files. Global licences, sidecars, nested
policies, native findings and the existing time limit remain enforced.
