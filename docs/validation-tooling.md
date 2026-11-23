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
rules with the NumPy convention over `src`, `tools` and `tests`. The same three
directories are enrolled in Make, pre-commit and configured preflight lint,
format, strict typing and native documentation commands. `make test` defaults to serial execution
(`TEST_WORKERS=0`) at niceness 10. A caller with allocated resources may set
`TEST_WORKERS` explicitly; the local preflight test role also defaults to
serial execution. Full-suite runs remain separate from focused local checks.
The full test role requires 100% statement and branch coverage for both tooling
and `evidence_manifest_toolkit`; the prepared SAST command includes runtime and
tooling sources. Command configuration alone does not establish a passing run.

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
The complete captured configuration binds the actual `docs`, `tools` and `src`
directories to absolute paths while retaining navigation, plugins, strict mode,
private-page exclusions and disabled runtime inspection. Paths with spaces are
supported. The inventory excludes the exact private document directory after
checking its entry kind; symbolic links and tracked private files remain refused.

The metadata guard checks the accepted standard and profile digests independently of the generated inventory. The repository schema is also digest-bound; replacing it with an older or permissive schema is refused. Inventory generation records the exact metadata bytes only after metadata acceptance.

The dependency guard treats received TOML as data. A malformed document is
invalid configuration (exit 4); a parsed `tool` or `mypy` value that is not a
table is policy drift (exit 2, `dependency_alignment.hook-drift`). These refusals
preserve input bytes and do not echo received values or execute configuration.
Its four local quality hooks have exact commands, source selections, order and
native Boolean controls. Removing `src`, dropping a hook, changing its command
or replacing a Boolean with zero or one retains the hook-drift refusal.

The same guard accepts either the original scaffold declaration or the complete
known development package declaration. Package name, development version, Python
range, build backend, console entrypoint, exact runtime dependencies, licenses and
included resources must agree. A changed or incomplete declaration retains
`dependency_alignment.runtime-dep` (exit 2). Declaration agreement does not clear
the independent lock, installed-producer, provenance or audit checks.

Direct requirements include the exact local `requirements-runtime.in` selection
from `requirements-dev.in`. That runtime file may name the maintained local wheel
directory `vendor/rfc8785`. Unknown includes or options, unpinned requirements,
malformed names or versions and duplicate canonical package names are invalid
configuration (exit 4); no received include path or download URL is followed.

The maintained RFC 8785 wheel has a separate local-artifact declaration. Its exact
wheel, provenance, annotation patch, builder and Apache license bytes are checked
against their source bindings, and its hash remains in the development lock. A
received artifact descriptor cannot choose another path or pretend the local
build is an upstream download. These checks read data only; they do not rebuild,
install, download or qualify an audit result.

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

::: local_scaffold.package_metadata

::: local_scaffold.maintained_dependency

::: local_scaffold.quality_configuration

::: local_scaffold.workflows

::: local_scaffold.documentation

::: local_scaffold.orchestration

::: local_scaffold.cli

::: local_scaffold.ownership_header

::: local_scaffold.source_materials

::: local_scaffold.documentation_projection

::: local_scaffold.actionlint_view

::: local_scaffold.security

::: local_scaffold.yaml_inputs


The prepared workflow references use the dedicated same-repository syntax on github.com. GitHub Enterprise Server is outside this prepared profile. References bind the caller commit and accept neither an explicit ref nor an expression. This is checked locally; no hosted run or service configuration is inferred.

After `make environment`, run `make prepare-test-inputs` before tests on a clean checkout. It acquires the pinned native archives, CodeQL input, strace fixture and unsupported-patch interpreter, then runs the real strict dependency audit. The prepared test workflow uses this order. Fixture acquisition uses the original HTTPS URLs and verifies the retained artifact digests. The separate explicit audit operation queries OSV for the exact 104 registry distributions and publishes its original output with a private, source-bound current admission receipt. The historical audit declaration in dependency provenance remains unchanged; it cannot renew current trust. Current admission binds all 105 installed metadata bodies, the interpreter, registry population and trusted tooling policy, with the same one-day freshness and five-minute future limits. An altered, stale, incomplete or failed current attempt remains unavailable or refused.

The POSIX publication tests use the pinned Ubuntu strace 6.8 fixture on Linux amd64. `make prepare-test-fixtures` prepares that fixture independently. Preparation verifies the package, executable and original third-party copyright; `dpkg-deb` extracts into the repository cache without installing a host package. The fixture traces only its own child processes and exercises real syscall errors and interruption boundaries. A missing fixture is unavailable, and cannot yield a passing test result.

The current development graph has 105 genuine installed producers. Environment refusal fixtures verify their interpreter, complete installed versions and original METADATA digests before use. A cache from an earlier graph remains unavailable until coherently renewed. Exclusive locks protect intentional producer changes, and each case restores and rechecks the complete graph. Package and maintained-wheel declaration cases start from genuine current native admission, alter one actual source or declaration, require refusal, and verify byte-exact recovery. The local RFC fork is not assigned a registry clean result: its separately recorded upstream query and source security review have distinct scope.

Run `make prepare-interpreter-fixture` for the genuine unsupported-patch case. It first acquires the two required original wheel artifacts through `make prepare-test-wheels`. Its independently pinned CPython 3.13.15 archive and copied executable exercise refusal below the reviewed `>=3.13.18,<3.14` range. The isolated environment contains only the two real producers needed for that early boundary: packaging and coverage, both installed from verified wheel bytes. The dependency guard refuses the actual interpreter before treating missing package producers as an availability problem.

`make prepare-major-interpreter-fixture` prepares the independently pinned
CPython 3.14.7 artifact and its genuine coverage wheel. The metadata and
dependency tests exercise this actual unsupported major version as well as
the older patch version. Each isolated interpreter has exactly packaging and
coverage with the original producer metadata. `make prepare-test-inputs`
prepares both interpreters; their presence does not extend the supported range.

The provenance guard uses isolated Python module discovery for its real REUSE
producer. Received modules or packages with the producer's name remain data;
the checker never imports them from the inspected repository.

Native ownership headers retain six fixed owner, license and contact lines,
followed by this project's nonempty file description. Source comments, bare
notices and invisible document headers use their respective native syntax.
Every ordinary source declaration retains its separate SPDX conflict check.

The exact maintained wheel, patch and original Apache notices are checked as
licensed byte artifacts. The typing marker must remain empty. Original raw
fixture objects retain their hash filenames and required notices; they are not
decoded as source code. Whole strict JSON fixture vectors may have array roots.
The recognized original fixture notice stays byte-identical and native REUSE
still checks the complete licensing cohort. Four original BlobRef, empty Signer,
inspection and JSON-reference vector datasets retain exact byte lengths, hashes
and original notices. Their intentional refusal inputs remain opaque test data;
production Unicode, depth and value limits stay unchanged. Other files keep
ordinary checks.


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


## Offline development environment

The primary development interpreter is CPython 3.13.18 on Linux x86-64.
The development lock contains 105 distributions: 104 registry packages and
the separately maintained RFC 8785 fork. The four declared application
dependencies remain exact pins; declaration agreement grants no domain
qualification.

Supply a flat directory containing every selected artifact from
dependency-provenance.json, including the maintained RFC wheel, or let the
first command below create it. It is the one networked step: registry
artifacts come only over verified HTTPS from files.pythonhosted.org, any status
other than 200 is unavailable, the declared length and the bytes must equal
the pins, the maintained wheel is copied from its tracked path, and a failure
leaves no directory. Then run:

~~~sh
make fetch-environment-inputs BASE_PYTHON=/path/to/python3.13 ENVIRONMENT_INPUTS=/path/to/artifacts
make check-environment-inputs BASE_PYTHON=/path/to/python3.13 ENVIRONMENT_INPUTS=/path/to/artifacts
make environment BASE_PYTHON=/path/to/python3.13 ENVIRONMENT_INPUTS=/path/to/artifacts
~~~

The check command reads only data. The same check runs before environment or
installer preparation. It binds the original lock and provenance, every
selected artifact and all maintained RFC derivation inputs under one total
byte budget. Missing, altered, linked or incompatible inputs refuse before
writes. Installation is offline, hash required and followed by the native
compatibility and package hardlink checks. The installer cache and environment
must share a filesystem.

Prepared workflow definitions select the same interpreter and run
`make fetch-environment-inputs` before the environment target, so each hosted
job acquires the pinned artifacts itself. No first-party artifact download
URL or hosted execution result is implied by these definitions.
