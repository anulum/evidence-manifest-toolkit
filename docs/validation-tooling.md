<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance
-->

# Validation tooling

Public guard commands are documented in `VALIDATION.md` in the source root. Each leaf emits the exact seven-field local diagnostic report. Inventory has separate generation and verification operations; preflight never generates or recursively invokes itself. The process API accepts explicitly trusted argument lists and qualifies only orchestration when tested with finite child programs.

`make quality` and the native documentation role enforce the full Ruff `D`
rules with the NumPy convention. `make test` defaults to serial execution
(`TEST_WORKERS=0`) at niceness 10. A caller with allocated resources may set
`TEST_WORKERS` explicitly; the local preflight test role also defaults to
serial execution. Full-suite runs remain separate from focused local checks.

`run_process` terminates and reaps only descendants that stay in the child's
original process group. Trusted commands must preserve that membership.
Session-escaping descendants require separate caller-owned cleanup. The Linux
subreaper flag remains enabled on the calling process after the operation;
unrelated children are outside the runner's wait and signal scope. See the
threat model for this execution boundary.

The native documentation configuration excludes private working documents and
assets from the generated site and search index. The documentation guard checks
the actual renderer output for private paths before accepting its native success.

The search dialog is named `Search`. The documentation guard accepts only the
exact maintained override and configuration, and renders captured copies.
Additional or changed executable templates are refused before rendering.

The metadata guard checks the accepted standard and profile digests independently of the generated inventory. The repository schema is also digest-bound; replacing it with an older or permissive schema is refused. Inventory generation records the exact metadata bytes only after metadata acceptance.

The dependency guard treats received TOML as data. A malformed document is
invalid configuration (exit 4); a parsed `tool` or `mypy` value that is not a
table is policy drift (exit 2, `dependency_alignment.hook-drift`). These refusals
preserve input bytes and do not echo received values or execute configuration.

The workflow leaf accepts one optional `--outcomes ROOT_RELATIVE_JSON_FILE`.
This bounded local JSON projection has exactly six flat string members:
`pre-commit`, `docs`, `codeql`, `security-audit`, `sbom`, `scorecard`.
Each value must be `success`, `failure`, `cancelled`, `skipped` or `not_run`.
The complete static graph is checked first; the supplied projection then passes
only when all six values are `success`. An admitted adverse input returns the
normal local report with exit 2 and `workflow_policy.aggregate-skipped`.
The no-input operation checks the static graph. Neither operation authenticates
a hosted run, and preflight does not accept the optional flag.

::: local_scaffold.reports

::: local_scaffold.inputs

::: local_scaffold.processes

::: local_scaffold.metadata

::: local_scaffold.inventory

::: local_scaffold.production_names

::: local_scaffold.provenance

::: local_scaffold.dependencies

::: local_scaffold.workflows

::: local_scaffold.documentation

::: local_scaffold.orchestration

::: local_scaffold.cli

::: local_scaffold.actionlint_view

::: local_scaffold.security

::: local_scaffold.yaml_inputs


The prepared workflow references use the dedicated same-repository syntax on github.com. GitHub Enterprise Server is outside this prepared profile. References bind the caller commit and accept neither an explicit ref nor an expression. This is checked locally; no hosted run or service configuration is inferred.

After `make environment`, run `make prepare-test-inputs` before tests on a clean checkout. It acquires the pinned native archives, CodeQL input, strace fixture and unsupported-patch interpreter, then runs the real strict dependency audit. The prepared test workflow uses this order. Acquisition uses the original HTTPS URLs and verifies the retained artifact digests; it does not change the admitted security snapshot digest or its production timestamp. A changed or stale admitted snapshot remains unavailable or refused.

The POSIX publication tests use the pinned Ubuntu strace 6.8 fixture on Linux amd64. `make prepare-test-fixtures` prepares that fixture independently. Preparation verifies the package, executable and original third-party copyright; `dpkg-deb` extracts into the repository cache without installing a host package. The fixture traces only its own child processes and exercises real syscall errors and interruption boundaries. A missing fixture is unavailable, and cannot yield a passing test result.

The dependency refusal fixtures use a complete owned copy of all 103 genuine installed producers. A qualified cache avoids copying that environment on every run. Each use verifies the interpreter, complete installed versions and original METADATA digests. Exclusive locks protect intentional producer changes, and each case restores and rechecks the complete graph. An incomplete or changed cache remains a failure; the tests preserve it for inspection.

Run `make prepare-interpreter-fixture` for the genuine unsupported-patch case. It first acquires the two required original wheel artifacts through `make prepare-test-wheels`. Its independently pinned CPython 3.13.15 archive and copied executable exercise refusal below the reviewed `>=3.13.16,<3.14` range. The isolated environment contains only the two real producers needed for that early boundary: packaging and coverage, both installed from verified wheel bytes. The dependency guard refuses the actual interpreter before treating missing package producers as an availability problem.

`make prepare-major-interpreter-fixture` prepares the independently pinned
CPython 3.14.7 artifact and its genuine coverage wheel. The metadata and
dependency tests exercise this actual unsupported major version as well as
the older patch version. Each isolated interpreter has exactly packaging and
coverage with the original producer metadata. `make prepare-test-inputs`
prepares both interpreters; their presence does not extend the supported range.

The provenance guard uses isolated Python module discovery for its real REUSE
producer. Received modules or packages with the producer's name remain data;
the checker never imports them from the inspected repository.


`analyse_reuse` preserves every public relative path and byte in a temporary
licence-check tree. It runs the installed REUSE CLI, including global and nested
licensing and unused-licence checks, then verifies both the original and copied
inputs. Received Git ignore rules cannot suppress public files. Cached and
private inputs remain outside the existing public ownership scope. All stages
share the unchanged inclusive 120-second limit.

The temporary tree respects the caller's `TMPDIR`, `TMP` and `TEMP` settings.
Git discovery for the native licence producer stops at the temporary parent,
so an ignored workspace inside another repository cannot conceal its inputs.
The absolute isolated Python producer also receives a closed executable search
path. Native licence discovery cannot select received programs through the
caller's `PATH`; the caller's environment remains unchanged. Original producer
code, licence rules, source bytes and native findings remain in force.
