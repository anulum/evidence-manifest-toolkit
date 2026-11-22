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

Local repository validation infrastructure and a Python evidence runtime under development. The source module exports canonicalization, byte references, inspection, difference, seal and verification operations, with four offline command grammars. Read the [Python API](docs/api.md) and [Offline CLI](docs/offline-cli.md) for their inputs and result semantics.

The repository records `architecture_only` maturity. Its qualified capability, claim and schema inventories remain empty. Installed packaging and operational root, signer, clock and domain qualification are not supplied by this checkout. Common report eligibility and command completion do not establish scientific acceptance.

The implemented infrastructure checks local metadata, attribution, workflows, dependency alignment, documentation and inventory. The preflight command combines those gates with the complete development-tool checks. A successful report covers only the requested local repository operation.

The workflow guard also accepts an optional local six-role outcome projection.
It requires a valid static graph and six successful results, and refuses skipped,
cancelled or unrun work. Supplied values do not authenticate a hosted run.

```sh
.venv/bin/python tools/check_repository_metadata.py --root . --json
.venv/bin/python tools/check_repository_inventory.py --root . --json
.venv/bin/python tools/preflight.py --root . --profile local-scaffold --json
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the locked development environment, [VALIDATION.md](VALIDATION.md) for result semantics and [ARCHITECTURE.md](ARCHITECTURE.md) for the boundary. Planned evidence formats are described in [ROADMAP.md](ROADMAP.md).

The licence is [AGPL-3.0-or-later](LICENSE). Commercial licensing enquiries use protoscience@anulum.li. Security reports use the private route in [SECURITY.md](SECURITY.md). No donor roster has been supplied; no sponsorship identities are claimed.

<p align="center"><img src="docs/assets/anulum_logo_company.jpg" alt="ANULUM" width="240"> <img src="docs/assets/fortis_studio_logo.jpg" alt="Fortis Studio" width="160"></p>

## Text and data mining reservation

The rightsholder, Miroslav Šotek (ANULUM), expressly reserves the use of the
works in this repository for text and data mining, including the collection of
this content for, and its use in, training, fine-tuning or evaluating machine
learning and artificial intelligence models, in accordance with Article 4(3) of
Directive (EU) 2019/790 and the national provisions transposing it.

No permission for such use has been granted beyond what the licence in
`LICENSE` grants. This reservation does not change that licence: uses the
licence permits remain permitted on its terms, including its attribution and
share-alike conditions.

Reservation made on 2026-11-22. Requests for permission: contact the
rightsholder through the contact listed in this repository.
