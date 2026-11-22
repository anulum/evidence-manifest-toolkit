<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance
-->

# Evidence Manifest Toolkit

This repository provides local validation infrastructure and an evidence runtime under development. Read the [Python API](api.md) for the six source operations and immutable values, and the [Offline CLI](offline-cli.md) for four command grammars and complete output transport. Its maturity remains `architecture_only`, with no qualified runtime inventory or released signing service.

Evidence Manifest Toolkit is part of the **SC Neuromorphic Computing Systems** group (SC-NEUROMORPHIC-COMPUTING-SYSTEMS). The [group and project map](https://github.com/anulum/sc-neurocore/blob/main/docs/ecosystem.md) shows the whole programme and where this repository sits in it.

The [Evidence core contract](contracts/evidence-core-v1.md) specifies the canonical form, byte identity, the evidence-manifest schema and the legacy signed-statement profile as the source implements them. It is a specification, not a capability claim.

Read [Architecture](ARCHITECTURE.md), [Validation tooling](validation-tooling.md), [Threat model](THREAT_MODEL.md) and the [Repository boundary decision](adr/0001-repository-boundary.md). Repository guard reports cover finite local repository checks. Evidence reports preserve separate common, domain and current results; scientific acceptance remains with the corresponding evidence owner.

![ANULUM](assets/anulum_logo_company.jpg)
![Fortis Studio](assets/fortis_studio_logo.jpg)
