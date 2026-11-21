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

A self-bound launch builds a whole unsigned V2 request inside the
process that verifies it, since a request binds the process that built
it and refuses in any other. `verify_self_bound` reads the launcher's
declaration (`evidence_manifest_toolkit.self_bound_declaration.v1`:
the policy's rules and claims, and every number, rule reference and
check result an `unsigned_declared` caller states about its Clock). It
then captures this process's identity with the native entry method, a
fresh acceptance from an NTP reply taken before its samples, the first
sample, and the later reply and samples, builds every record from them,
and verifies in the same process. A declared check names its evidence
by a store reference or by one of twelve closed roles, the records
stored before the acceptance body. Nothing is written until verification
returns. Then the new records are linked into the store under their
digests, never replacing a file, and a fresh request directory receives
`policy.json` and `trust.json`, as `emt verify` takes them, and
`request.json`, which states that the acceptance holds for this boot
only. Replaying the request from another process refuses. The NTP reply
comes from one fixed `/usr/bin/busctl` call with standard input from
/dev/null, an environment of `LC_ALL=C` alone, a 10 s bound and a real
4096-byte output bound. The static security gate admits its subprocess
import and that one call at their exact lines, while the module matches
its reviewed digest.

An unsigned V2 caller's evaluation time can now be qualified without
authority, by the consistency of its own NTP records. For an
`unsigned_declared` acceptance that names no issuer, the class's
authority and time holds when synchronization and the uncertainty
budget both hold as recomputed; other classes keep it unavailable. With
all six checks holding, the verdict is accepted, the report drops the
evaluation-time refusal and states instead, as `time_consistency_only`,
that the time is qualified only by that consistency, with no authority
and no server identity shown. That reason, like `historical_only` and
`domain_verifier_required`, is stated after common eligibility is
decided, so the common mode is eligible and `verify` exits 0, while
authenticity stays unsigned and current eligibility refused. The CLI
documentation lists the three reasons that do not refuse.

The Clock verdict now reads synchronization and the uncertainty budget
from the Clock calculation. Synchronization and mapping holds once that
calculation completes, since it already refuses every inconsistent
exchange, sample claim and window; the server's identity is not
captured, so it shows that the recorded exchange is consistent, not whom
it was with. The uncertainty budget holds when the drift record's rate
is at least RFC 5905's 15/1000000, when every sample's declared holdover
covers its age since its NTP exchange plus its post-exchange adjustment
at that rate, and when the whole interval lies within the profile's
maximum uncertainty around the evaluation origin. A declared pass that
does not hold is refused at its check. The calculation now also refuses
a sample whose NTP exchange completed after the sample. The class's
authority and time still has no rule, so no verdict is accepted yet and
report bytes are unchanged.

A verification with a bound Clock subject now computes a Clock verdict
over the six checks its acceptance declares. The three relational checks
(whole sources, controller identity, acyclic whole target) are
recomputed, and a declared pass that the evidence contradicts is refused
at that check; a declared fail or unavailable is kept, and a repeated
check or evidence reference is an invalid acceptance. The other three
checks have no rule yet and stay unavailable, so no verdict is accepted
and every report keeps the evaluation-time qualification reason; the
report drops it only for an accepted verdict.

An unsigned V2 verification now returns the original fifteen-field
report instead of a configuration refusal at /trust. The report is
composed without any authority state: authenticity is unsigned, the
domain verdict is not evaluated and current eligibility is always
refused. While no accepted Clock verdict exists, it keeps the
evaluation-time qualification reason and its common result is refused;
the command publishes it and exits 2. Software and delegated V2 callers
are still refused at /trust, and legacy reports are byte for byte
unchanged.

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
