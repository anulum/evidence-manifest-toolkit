<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance
-->

# Repository boundary decision

## Decision

Maintain Evidence Manifest Toolkit as a standalone owner of common evidence-manifest infrastructure. The initial repository implements local governance validation and declares only planned evidence identifiers. Empty capability, claim and qualified-schema inventories are mandatory until real corresponding implementations and acceptance evidence exist.

## Consequences

Producer-specific scientific data and verdict logic remain with the producer/verifier owner. Future consumers reference canonical manifest/trust contracts rather than copying signing or normalisation logic into local validators. Governance reports do not register schemas or confer evidence authority. Runtime additions require complete owned schemas, vectors, real integrations, licences and independent review.
