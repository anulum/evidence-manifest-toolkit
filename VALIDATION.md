<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance
-->

# Local validation

Seven public guards accept `--root DIRECTORY --json`. The preflight guard also accepts the implemented `--profile local-scaffold`. Metadata, source provenance, workflow policy, dependency alignment, documentation and inventory are separate complete gates.

| Exit | Meaning |
| --- | --- |
| 0 | Requested local operation completed |
| 2 | Input, policy, output or resource refusal |
| 3 | Required input, tooling or execution unavailable |
| 4 | Invalid invocation or configuration |

Multiple outcomes use precedence 4, 3, 2, 0. Reports have fixed authored codes and safe relative locations. They are diagnostic outputs, not registered evidence or scientific verdicts. Preflight records each of its 17 required roles. `not_run` cannot pass.

Private working documents and assets stay outside built documentation and its
search index. The documentation guard refuses any private output path with
`documentation.private-plan`, including a dangling symbolic link.

The generated search dialog has the accessible name `Search`. Before rendering,
the documentation guard verifies the closed template inventory and exact
configuration and template digests, then uses captured copies. Changed or
additional executable overrides are refused without executing their content.

Maintained HTML templates use native Jinja syntax inspection and decoded HTML
entities for naming checks. Inspection does not render received expressions.

Metadata binds the accepted standard and profile by their exact SHA-256 digests. A previous standard digest is refused even when the metadata remains valid JSON. The schema, validator and metadata must agree before inventory generation; inventory verification then checks the digest of the complete metadata file. Changing only the generated inventory cannot change the accepted identity.

Inventory inspects every maintained filename, Python declaration and incoming import, decoded configuration value and generated catalogue for known private queue identifiers. Metadata, workflow and rendered documentation checks inspect their own corresponding values. Genuine standards such as SHA-256 remain valid. These finite checks identify naming violations; meaning and provenance still require review. An incoming language without an implemented native inspection is refused.

```sh
.venv/bin/python tools/check_repository_metadata.py --root . --json
.venv/bin/python tools/check_source_provenance.py --root . --json
.venv/bin/python tools/check_workflow_policy.py --root . --json
.venv/bin/python tools/check_dependency_alignment.py --root . --json
.venv/bin/python tools/check_documentation.py --root . --json
.venv/bin/python tools/check_repository_inventory.py --root . --mode verify --json
.venv/bin/python tools/preflight.py --root . --profile local-scaffold --json
```

The workflow policy guard first verifies the entire static graph. Its optional
`--outcomes ROOT_RELATIVE_JSON_FILE` additionally validates one caller-supplied
local outcome projection. The JSON object must contain exactly `pre-commit`,
`docs`, `codeql`, `security-audit`, `sbom` and `scorecard`, each with a flat string
value from `success`, `failure`, `cancelled`, `skipped`, `not_run`.
GitHub's nested `result` objects are outside this input format.

```sh
.venv/bin/python tools/check_workflow_policy.py --root . --outcomes received-outcomes.json --json
```

Passing requires a valid static graph and all six values to be `success`.
An admitted adverse outcome produces exit 2 with
`workflow_policy.aggregate-skipped`, once for that input. Invalid shapes,
statuses, unsafe paths and malformed inputs refuse with exit 2; missing or
unreadable files return 3. Empty, missing or repeated flag values return 4.
`--outcomes=received-outcomes.json` is equivalent to the two-token spelling.
Only the workflow leaf accepts this flag; preflight retains its static check.
The guard reads one bounded regular file under the root without following
symlinks and preserves earlier graph findings. Without the flag it checks only
the static graph. Caller-supplied success strings do not authenticate a hosted
run or prove that jobs executed. The CI aggregate retains its own native exits.

Inventory generation requires a new destination: `--mode generate --output NEW_FILE`. It validates metadata independently of a final inventory, writes and fsyncs full temporary bytes, publishes exclusively and fsyncs the parent. Existing files remain untouched. A complete published file survives a later durability fault. Final verification requires the complete source tree and the independently authored JSON ownership sidecar.

All guards operate offline. Dependency security consumes the separately produced, digest-bound real pip-audit snapshot; acquisition is an explicit network operation before validation. Missing or stale accepted inputs remain unavailable. Native quality, test coverage, REUSE, secrets, Actionlint, workflow security, strict rendering and SBOM gates use real installed tools. Hosted checks and unsupported operating systems have no local acceptance claim.

On a clean Linux amd64 checkout, run `make fetch-environment-inputs`, then
`make environment`, then `make prepare-test-inputs` before tests.

The first command acquires every artifact that `dependency-provenance.json`
selects into a new `ENVIRONMENT_INPUTS` directory, and it needs the network.
Registry artifacts come only over verified HTTPS from `files.pythonhosted.org`,
with no credentials, port, query or fragment. Any status other than 200,
including every redirect, is unavailable (exit 3). The declared length and the
received bytes must equal the pins (exit 2), and the read stops one byte after
the pinned length. The maintained RFC wheel is copied from its tracked path.
Every origin and tracked-file check completes before the directory is created
or a connection is made, an existing directory is never written into, and any
failure removes the directory the command created. Its tests also use the
network; without it they fail and are not skipped.

The third command acquires the pinned
fixtures and separately produces the strict audit snapshot. It preserves the
trusted snapshot digest and original production timestamp; acquisition does
not automatically admit changed bytes or refresh an expired seal.

The provenance guard invokes its installed REUSE producer with isolated Python
module discovery. Repository files named `reuse.py` or `reuse/` remain input
data and cannot select the executed licence checker.

For dependency configuration, invalid TOML syntax returns 4. Parsed `tool` and
`mypy` values must be tables; other shapes return 2 with the existing
`dependency_alignment.hook-drift` reason while preserving all input bytes.


REUSE consumes an exact temporary copy of every bounded public input at its
original relative path, including all licence files, sidecars and nested
`REUSE.toml` files. The existing cache and private-document exclusions apply.
Original and copied file sets and bytes must agree after the producer exits.
This keeps cache discovery outside the licence check without weakening native
findings, and received Git ignore rules cannot hide public licensing failures.
Copying, native execution, verification and cleanup share the original
120-second deadline. The preflight licence role uses the same complete input
contract and retains the original native producer result.
Temporary placement follows the caller's environment. The native producer's
Git discovery stops at the temporary parent, preserving complete input checks
when the selected temporary workspace lies inside an ignored repository path.
Its executable search path is closed, so received programs cannot become
licence-discovery tools through the caller's `PATH`. The absolute isolated
Python producer and original licence checks remain unchanged.
