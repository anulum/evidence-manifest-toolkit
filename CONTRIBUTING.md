<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance
-->

# Contributing

Use Python 3.13.16 on Linux. Create a project-local environment and install the complete locked development graph:

```sh
python3.13 -m venv --copies .venv
.venv/bin/python -m pip install --require-hashes --build-constraint requirements-dev.txt -r requirements-dev.txt
```

The lock includes the verified source builder required for REUSE. Native Actionlint and Gitleaks artifacts are named with their immutable publisher URLs and SHA-256 in `dependency-provenance.json`; place verified extractions at their recorded `.tool-cache` paths. CodeQL workflow preparation is for the separately authorised hosting lifecycle. Genuine local Python source security analysis uses Bandit. Do not interpret preparation as a hosted CodeQL result.

Run `make quality`, `make test`, `make docs` and the guard commands in [VALIDATION.md](VALIDATION.md). Every maintained Python module, test and helper requires native documentation and strict typing. New guard code requires meaningful 100% statement and branch coverage through public command/file/process behaviour. Missing tools remain failures; do not use skips, mocks or lowered thresholds to clear acceptance.

Keep source changes narrowly owned. Review licences, locked dependencies, safe workflow permissions, real failure handling and the staged diff before committing. Initial local history uses main with zero remotes. Private working records, credentials, generated caches and large evidence artefacts stay outside published source. A source change does not itself authorise push, release or deployment.
