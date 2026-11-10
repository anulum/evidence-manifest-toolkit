<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance
-->

# Architecture

This standalone repository owns local governance validation and a common evidence runtime under development. Python modules under `tools/local_scaffold` implement repository checks, while `src/evidence_manifest_toolkit` supplies the six evidence operations and four offline CLI grammars. Governance checks consume finite local source/configuration files and installed development tools. They produce diagnostic reports and an exclusive empty capability inventory; these outputs are not registered scientific evidence.

Dependency alignment admits only the original scaffold declaration or the complete
known development package metadata. Its exact local runtime include is part of
the direct requirement population. Package declarations retain the separate lock,
installed-producer, provenance and audit checks; they supply no release or
qualified runtime capability.

Metadata validation is independent of inventory generation. Generation validates its real metadata dependencies before publishing a complete new file. Final verification checks the actual tree, original metadata digest, initial empty state and required controls. It never rewrites the inventory. Preflight verifies that state and preserves every required role's outcome.

Workflow verification checks the full static graph before admitting an optional
bounded local outcome file. That input adds an all-six-success requirement to
the same existing leaf report. The static-only preflight invocation and the CI
aggregate keep their respective meanings; the local projection carries no host
authentication.

See [the detailed architecture](docs/ARCHITECTURE.md), [Python API](docs/api.md) and [threat model](docs/THREAT_MODEL.md). Operational root, signer, clock and scientific qualification remain separate obligations.
