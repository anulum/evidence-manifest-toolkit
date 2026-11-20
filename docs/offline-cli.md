<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — offline command transport
-->
# Offline CLI

The source checkout runs the commands through `python -m evidence_manifest_toolkit` from the `src/` directory, using explicit absolute input and output paths. Installed `emt` packaging remains under development. The grammar below uses the executable's design name.

```text
emt seal --content FILE --schema-id ID --registry FILE --objects DIR --limits FILE --output NEW_DIR [--signing-request FILE --signer-config FILE --trust FILE]
emt verify --content FILE --schema-id ID --registry FILE --objects DIR --limits FILE --policy FILE --trust FILE --report NEW_FILE [--signature FILE]...
emt inspect --content FILE --limits FILE --report NEW_FILE
emt diff --left FILE --right FILE --limits FILE --report NEW_FILE [--left-signature FILE]... [--right-signature FILE]...
```

Every configuration is an explicit closed local JSON value. `--limits` supplies all six positive integer bounds described in the [Python API](api.md). Its initial read is bounded by the size measured on the same opened regular-file handle. Once decoded, its bounds control subsequent inputs. A small `max_json_bytes` does not impose that future bound on the limits file itself.

Native parser or canonical writer recursion exhaustion produces `limit_exceeded`
and exit `2` before successful output publication, including when the configured
`max_json_depth` permits the document's container depth.

Registry, policy and trust files encode the complete corresponding public value types. Bytes in configurations use canonical unpadded Base64URL. Decimal lengths, digests and UTC strings retain their original spelling. Repeated detached-signature flags preserve caller order; the command does not discover signatures in the object store.

Registry entry counts follow the complete caller-selected catalogue. There is no universal eight-entry CLI limit. A caller selecting the supported QPU successor catalogue supplies its entire fixed 77-entry cohort.

The trust file can also declare `UnsignedTrustContextV2`, `SoftwareTrustContextV2` or `DelegatedTrustContextV2` through its exact `EMT_CALLER_TRUST_UNSIGNED_V2`, `EMT_CALLER_TRUST_SOFTWARE_V2` or `EMT_CALLER_TRUST_DELEGATED_V2` namespace. The decoder retains every selected field, the complete frozen Clock entry binding, original UTC and floor strings, and ordered canonical control-envelope bytes. Software and delegated historical selections require their own archive; current selections forbid that archive field. Unknown or mixed fields refuse configuration.

Verification pairs the complete V2 declaration with the whole independently selected `authority_policy.v2` before authority acquisition. A legacy policy, mismatched class or fixture policy refuses that selection; a fixture cannot omit the operational Clock requirement. Missing selected policy sources retain the original unavailable reference. These declarations do not supply qualified Clock or authority inputs. After policy/source acquisition, an unsigned selection receives the original fifteen-field report, composed without any authority state: `authenticity` is `unsigned`, `domain_verdict` is `not_evaluated` and `current_eligibility` is always `refused`. While no accepted Clock verdict exists, the report keeps `policy_unavailable` at the policy's Clock qualification pointer, its common result is `refused`, and the command publishes it and exits `2`. A software or delegated selection is still refused at `/trust` with exit `4`, before authentication or output publication. Neither route invents legacy bootstrap fields or chooses a weaker class.

Software trust configuration selects its actual current authorization source, exact current floor and historical archive when required. After policy pairing, these whole tables/histories and their key encoding, scope and time declarations are checked before Clock acquisition. Required source failures preserve their original typed errors and references; a class change is not attempted. These reads require no legacy crypto provider and do not establish signing authority.

Explicit software receipt inputs also check the entire manifest target and selected table/scope references, actual claim membership, one complete key row's scope and declared half-open times, history revocations and the exact full-message signature. A conforming local provider is required for a compatible receipt's mathematical check; empty receipt populations do not initialize one. A valid signature supplies no missing Clock, identity, custody or native authority qualification.

V2 source selection does not initialise the legacy signature provider. Missing that provider cannot replace a V2 policy, native-source or unsupported-state diagnostic with a legacy provider error. Legacy verification still checks its required provider at the original boundary. This distinction supplies no V2 authentication or successful native-state result.

After command configuration decoding, public verification captures actual native entry time before reference acquisition. The fixed Linux/glibc x86-64 method compares its whole installed descriptor and implementing sources, boot source, stable PID/start identity and complete runtime environment with the caller's selected binding. It uses no received executable, callback or clock adjustment. Native source conflicts or an unknown method produce `policy_unavailable` and exit `2` at the policy's Clock qualification pointer; missing original sources remain `reference_unavailable`. No report is published on these thrown failures. With complete Clock sources, verification next checks the entire subject/context/content/receipt/registry/limits/policy joins, declared capture/window consistency and S1 → H → actual E ordering under the native tick calibration. A conflicting whole subject retains the policy Clock diagnostic and exit `2`. These checks supply no physical Clock or authority acceptance; an unsigned selection then receives its refused report with exit `2`, and a software or delegated selection is still refused at `/trust` with exit `4`.

Signed `seal` requires all three signing flags together. `SignerConfig` contains only `adapter_ref`, `signer_key_id`, `public_key` and `profile_id`. The reference names an owner-controlled, locally enrolled signing adapter. The current checkout supplies no qualified CLI adapter; selecting an unavailable adapter refuses signing. No private key or executable is loaded from these configuration fields, and a failed signed request does not become an unsigned result.

Trusted installation code holds the read-only association between an exact descriptor and an already existing signer. Caller configuration must match that descriptor; it cannot enroll or replace the object. A mismatch is a located configuration failure. An empty installation produces `signer_unavailable` with null subject, claim and pointer before signing or publication. Once an eligible signer is invoked, a failed response retains the known content digest in the original signer-response refusal.

A missing local verification provider produces `configuration_error` and exit `4`
before authentication, with null subject, claim and pointer. It creates no requested
report. Restoring the provider permits evaluation of the complete original input;
the command retains every verification gate and requires a fresh report destination.

## Read-only object store

`--objects` selects an existing directory. A digest `sha256:<64 lowercase hex>` maps to the immediate file `<objects>/<64 lowercase hex>`. The store adds no extension, basis suffix or index. Captured bytes must satisfy every applicable declaration, including declarations sharing a digest under different bases.

The resolver anchors the directory descriptor and refuses symlinks and nonregular targets. It reads within the original per-object and remaining cumulative allowance. Input and store files remain unchanged. Artifact URLs and labels are not filesystem paths or network lookup instructions.

## Complete output publication

Unsigned `seal` creates a fresh directory containing exactly `content.json` and `refs.json`. Content is the bare canonical library result. The unregistered reference index contains exactly `content_ref`. Signed transport additionally carries the detached envelope and its reference when an eligible adapter supplies a verified signature.

Seal stdout preserves all three `SealResult` field names. `canonical_content` is represented by `{content_ref, output_file}`, where `output_file` is the selected directory joined with `content.json`. The root `content_ref` is that same complete reference. `envelope_json` is null for unsigned construction, or unpadded Base64URL of the exact detached-envelope file bytes for signed transport.

`verify`, `inspect` and `diff` exclusively create the selected report file. Stdout and that file contain the same complete report bytes. All transport JSON is strict UTF-8 RFC 8785 JCS without a BOM, padding or trailing newline. Serialization adds no accepted flag or registered evidence schema.

Output parents must already exist. The current directory publisher uses Linux `renameat2(RENAME_NOREPLACE)` with an anchored parent, sibling staging, actual absent/occupied capability checks and complete file/directory synchronization. It never substitutes a check followed by an overwriting rename. Existing files, directories and symlinks are preserved. Support on other hosts and filesystems requires equivalent native validation.

Before publication, failures remove only the transaction's unchanged owned staging entries. After publication, a stdout or durability failure leaves the complete immutable output and returns an I/O failure. A retry uses a distinct fresh destination; the command does not delete or overwrite the previous result.

## Exits

| Exit | Meaning |
|---|---|
| `0` | Construction or diagnostic transport completed, or verification's requested common mode is eligible. |
| `2` | Input or verification gate refused without a higher-priority failure. |
| `3` | Required reference or signer unavailable, or actual storage, cleanup, stdout or durability failure. |
| `4` | Invalid invocation/configuration or unsupported implementation capability. |

Observed failures use precedence `4 > 3 > 2 > 0`. A report's successful publication clears no gate. Common or historical exit `0` does not establish scientific or current acceptance; read the complete report.

### Reasons that do not refuse

A report's reasons are refusals, except the three below. A report states them after its common
eligibility is decided from every other reason, so a common mode can be eligible, and `verify` can
exit `0`, while one of them is listed.

| Code | What it states |
|---|---|
| `historical_only` | A historical verification does not establish current eligibility. |
| `domain_verifier_required` | Domain verification is required; the common result says nothing of the domain. |
| `time_consistency_only` | An unsigned caller's evaluation time is qualified only by the consistency of its own NTP records: no authority and no server identity is shown. |

An unsigned caller's exit `0` means exactly what `time_consistency_only` states and no more: its
authenticity stays `unsigned` and its current eligibility stays `refused`.

Thrown failures produce stdout `{"operation": ..., "reasons": [...]}` with the full located reasons and no success field. They create no requested successful report or seal destination. A well-formed returned refusal report can be published in full. Malformed invocations name a recognized command when available and otherwise use `operation="emt"`. Caller diagnostics use fixed authored details rather than interpreter messages or local paths.

V2 verification also reads the complete selected identity and validation rules, and the optional foreign rule, before Clock acquisition. Their private formats, class and source joins share the original reference quota. Missing required rules preserve their exact original references. Consistent rule declarations do not authenticate their referenced procedures or authorize foreign execution, identity, reproduction or Clock use.


Before Clock acquisition, verification also reads the
[four whole native method declarations](api.md#native-method-declaration-sources)
through the existing policy and object store. No new flag, public schema ID,
provider or executable selector is added. All roots and descendants share the
same quota and connected rule/Clock graph, including full parent-to-descendant
depth and cycle checks; missing original sources return `3`, malformed source data returns
`2`, and unavailable or changed installed grammar returns `4`. Thrown failures
publish no requested report. Matching declarations authenticate no identity,
key possession, run, comparison, class or Clock and still require complete V2
state admission.

A complete matching V2 Clock subject also selects the fixed raw
[signature-obligation method](api.md#selected-signature-obligation-method).
The command uses the existing policy reference and object store; there is no new
flag or dynamic provider. Whole rule, base policy, conditions and provenance reads
share the original limits. Invalid closed method configuration returns exit `4`,
an unavailable original source returns `3`, and a whole policy/class/scope conflict
returns `2`, without publishing the requested report. A source-consistent rule
continues through the complete conditional Clock calculation and applicable
ordinary signature coverage. Covered scope then reaches the unsigned report, or
the pending V2 state refusal of a software or delegated selection; rule
consistency alone does not produce a successful report or qualify the Clock.


The same V2 path now reads all three complete
[conditional Clock method records](api.md#complete-conditional-clock-methods)
and calculates all eight N terms, raw sample brackets, M/Q additions and the
whole H-through-actual-E interval. It uses the existing policy/trust/object-store
arguments and the same cumulative limits. Unknown selected methods or inconsistent
full error/windows retain the original Clock diagnostic and exit `2`; invalid
closed local configuration is `4`, and unavailable exact source arguments are `3`.
A numerical calculation does not qualify its physical/model/source premises or
complete V2 state admission, and creates no successful report on a thrown failure.

Verification also checks the original annual acceptance's two complete raw
captures, its own rational calibration, declared acquisition radii and whole
acceptance interval. Understated bounds, inconsistent raw samples and full
five-second budget crossings retain the Clock refusal; malformed raw configuration
and JSON keep their original typed errors. The original source arguments and
limits are reused. Neither these calculations nor stored check labels establish
physical model or class acceptance.

The fixed uncertainty method additionally requires its original annual
`annual_derivation_ref`. The complete raw child keeps both actual annual sample
and packet associations, original synchronization population, exact positive
rational rate and all six bounds per sample. Verification recomputes both original
N+B/M/Q requirements, the selected signed offset and the method's own capture
window. Later invocation terms cannot supply missing annual evidence. Equivalent
rational rates are accepted as equal; the previous uncertainty method is
unsupported. Closed method configuration, unavailable exact references and
inconsistent annual calculations retain exits `4`, `3` and `2` respectively.
These checks neither qualify physical bounds nor publish a successful V2 report.

For actual software receipts, the selected current or explicitly archived source
and one complete equation-verified authorization row must also cover the whole
conditional interval through native entry. Point-time validity and several
overlapping partial rows cannot replace complete coverage. A source issued
after use or claimed signing, or a missing whole covering row, returns exit
2 with invalid_delegation at /statement/authorization_ref; no report is
published. This necessary time check neither authenticates custody nor qualifies
the physical Clock or final class. No new flag or source format is introduced.

After those full source and calculation checks, unsigned/software V2 verification
also enforces complete claim/purpose signature coverage. Missing required
signatures or uncovered scope returns `2` with its full located reason and no
requested report. Only the exact selected ordinary unsigned exception applies;
empty scope or a class label supplies no waiver. A C0 receipt does not fulfil a
separate validation-record signature obligation. Covered scope then reaches the
unsigned report, or the pending V2 state refusal of a software or delegated
selection, and authenticates no physical/model/class source.
Original legacy command results and transport remain unchanged.

With complete Clock calculations and applicable ordinary signature coverage,
verification also reads the [whole reproduction record sources](api.md#whole-reproduction-record-sources)
and checks their actual subject, policy, claim, class and declared identity
relations. Both complete producer and runner identity bindings must retain the
selected identity rule's custody class and exact whole policy reference. A
substitute same-class rule or conflicting custody declaration returns `2` with
`invalid_claim` at that actual identity source field; no report is published.
Matching these source joins does not qualify identity, key possession or a run.
A missing original source returns `3` with its exact unavailable
reference; schema and located relation failures return `2`. These typed source
errors are preserved when first found in the Clock closure. No requested report
is published on a thrown failure. Consistent declarations then reach the
unsigned report, or the pending V2 state refusal of the other classes; they supply no authenticated independent execution,
physical Clock or class admission.

Verification renders the exact report bytes while its original offline store
is still open. Rendering retains the same invocation and cumulative source
budget. The command publishes the report after rendering and successful store
closure; acquisition, rendering or closure failure produces no successful
report file. The original report fields, byte transport and exit precedence
remain unchanged.

For an explicitly delegated V2 caller, verification also acquires the whole
[protected control selection](api.md#protected-control-source-selection) and
matches its independently expected ordered operations against the original
control receipt bytes. Missing original source arguments return `3`; invalid
source formats or located selection conflicts return `2`, without publishing
the requested report. Local configuration failures retain `4`. Matching source
declarations still require the complete protected state and Clock methods;
they do not install authority or produce a qualified V2 report. Unsigned and
software callers select no protected control sources.

The delegated route also reads its complete selected root/grant and current or
historical snapshot histories. Exact rule/stream/floor/window and withdrawal
conservation failures retain located source refusals and publish no report.
Archive selection does not reset the independently selected current floor.
The command reads these immutable inputs; it performs no state installation.

Selected native certificate histories include every whole parent back to the
independently selected grant. Wrong roots, widened scope, leaf control
operations, depth or source-window conflicts refuse with the original source
error status and no report. The full authority and Clock methods remain
required after these necessary source bounds pass.

A selected `revoke_descendants` control retains the complete withdrawal snapshot and its earlier history. The target must name the exact earlier authorising snapshot, preserve every non-withdrawal state field, retain the old revocation rows in their original order and append a nonempty unique population. Withdrawal cannot simultaneously change the issuer, rotation, registry, certificates or identity rules. Finite withdrawal-history timestamps may follow machine expiry; this source check neither authenticates a surviving owner path nor revives positive machine authority. All actual signer, descendant, Clock and installation requirements remain.

Protected source verification follows every full rotation parent to the selected grant. It checks authority/grant identity, strictly ordered rotation counters and effective times, old/new key continuity and grant-window containment. A snapshot names the actual head issuer and cannot discard an established rotation history or name a future rotation. A selected rotation also binds the complete earlier authorising snapshot, predecessor and old signer within that source window. These checks retain all sources under the same quota; they do not authenticate key possession, protected custody, unchanged scope, native signatures, Clock or installation.

After the complete source graph passes identity, schema and metadata checks,
a selected rotation's actual new public key must contain exactly 32 bytes and
match its declared key identifier. Verification compares those actual bytes
with every key withdrawal in the selected earlier authorising snapshot, using
the same cumulative source budget. Other keys, certificate withdrawals and
withdrawals first recorded in a later snapshot do not replace that earlier
source comparison; all original withdrawal and current/historical eligibility
requirements still apply. Malformed new key data or an already withdrawn new
key refuses at the rotation's `/new_public_key_ref`; malformed earlier key
data locates that snapshot's `/revocations/{index}/target_ref`. These checks
supply no key possession, protected custody, signature or Clock qualification.
The command preserves the existing source-error exit and publishes no report
on a thrown failure. No extra option, signing operation or state installation
is introduced.



For an explicitly supplied nonempty protected ordinary receipt population, verification
prepares the complete content once and binds each receipt to that exact content,
the selected current or archived snapshot, and a complete certificate listed in that
snapshot. It checks the certificate subject key, parent issuer continuity, required
principal, role, segment, purpose, claim population and half-open signing/caller
windows. Whole scope sources and inline statements share the invocation quota and
Clock closure. These source checks precede Clock acquisition; matching sources
still require actual native signatures, identity, custody, authority and Clock
qualification. The prepared content and parsed receipts are reused by verification.


The protected ordinary route also retains complete independent-validation packages,
bodies, producer and runner bindings, earlier subjects and policies, and their full
reference closure. Preparation checks known native descendants against the fixed
installed structural lookup while preserving all original static-schema semantics.
The reproduction-record method then follows the original source joins and Clock
calculations under the same quota. Existing class, claim, policy, vendor and key
correspondence checks apply to these records. Their presence supplies no accepted
run, eligible runner authority, identity, non-use or whole-parent reconstruction;
those predicates remain required before reproduction or class admission.


A source-compatible protected ordinary receipt now checks the unchanged native V2
signature equation using the selected certificate's actual bounded raw32 public
key data. Length and the original SHA-256 key identity must match before provider
initialization. The existing canonical-point, small-order, scalar and exact-domain
checks apply to the full original message. The result retains the complete key
reference and bytes under the same quota. It supplies no certificate issuer,
root, custody, identity, possession, Clock or current-use authorization. Encoded
key-source objects require their actual selected decoder and are never guessed
from a generic reference or media label. Empty protected receipt populations
initialize no verifier for this mathematical check.


Independent-validation records now check their entire explicit validation manifest,
actual body citation, native receipt targets and real runner signatures. Protected
record leaf key data and key identity must match the actual runner key. Equal actual
producer/runner key bytes refuse independence even under different reference metadata.
Every ordered receipt is checked, including later failures. All sources use the
original quota; unsigned records need no invented native receipt or key. Mathematical
success supplies no historical authority, key custody, independent run, non-use,
comparison, physical Clock or class admission. Required claim/purpose coverage remains
with the entire selected validation policy, without inventing matching claim names.

Ordinary content signature coverage permits acquisition of the actual record sources
while every unwaived record requirement stays unresolved. A missing ordinary signature
still refuses; a matching content receipt does not sign a validation record. Required
missing or malformed record sources retain their actual source error and command exit.
Source presence, parent correspondence and mathematical signatures clear no pending
record requirement. Definitive whole current content uses the original required paths,
actual selected native/history roots and the same cumulative source budget.

Verification also reconstructs every whole causal parent from its actual earlier
manifest. Only the selected claim's validation, maturity and verdict may change;
all inherited claims and other fields remain exact. An inherited record keeps its
own earlier subject, so successive validations and revalidation do not require
all records to share one base. Whole canonical JSON comparison preserves types.
Missing optional schema metadata cannot bypass native/common manifest checks or
restart graph depth. Every earlier source shares the original invocation quota.
An unrelated mutation or invalid earlier source refuses without a report. Structural
correspondence still requires complete historical authority, independent execution,
comparison, non-use, Clock and class admission before reproduction is accepted.

The delegated source path checks the entire conservative capture-through-entry interval
against the selected grant lifetime and snapshot window, then each matched ordinary
certificate and its complete parent chain. An until-withdrawal grant retains its actual
lower bound and explicitly absent upper bound; withdrawal and authority still require
their original independent checks. Historical control signers retain their own original
claimed-time requirements. These source-window relations supply no accepted root,
protected custody, physical Clock, class result or completed V2 report.

Reproduction verification also checks each whole known native launcher source,
its original integer tokens and Common UTC, and exact declared seat/vendor joins.
The command uses the existing object store and independent selected method; no
flag, executable, current PID/path lookup or public schema is added. Empty vendor
and opaque key declarations remain limited data. Source checks supply no native
identity, possession, run, Clock, custody, class or successful V2 report admission.

For the known raw-launch method, verification compares the entire installed
implementation descriptor and every package Python/JSON source body under the
original limits. Original implementation, environment and qualification inputs
come from the caller's object store before complete reference closure; physical
installation matching follows that closure and cannot fill a missing caller input.
Documentation in implementing Python files is included in those source identities.
Even a documentation-only update needs the corresponding whole descriptor; an old
descriptor is not silently replaced by the new local installation.
No received filename selects an opened resource or executable.
The selected method environment must match the complete actual verifier-entry
environment; historical process observations are not replaced. Source or environment
conflicts return their original typed refusal without publishing a report. Whole
qualification evidence remains data, with native method/class/Clock admission pending.

Reproduction bodies must name the exact full comparison-method reference selected
by the independent validation rule. A different rule or a different digest basis
for the same JSON cannot replace that selection. The declared non-use class must
also be permitted by the selected execution method, alongside the caller policy
and validation rule. These policy relations establish no actual execution,
comparison, non-use or isolation evidence.


After the complete selected protected source closure, verification also checks
that the grant's initial issuer key and every certificate key in the current
and selected archived source forests contain 32 raw bytes matching their own
native key IDs. Every rooted parent is included, even when no ordinary receipts
are supplied. This uses the original resolver and cumulative quota; key-data
consistency authenticates no root, issuer, protected custody, signature, Clock
or positive-use state. Missing and conflicting original sources retain their
typed failures, without an unsigned retry.


After complete key-source validation, every non-grant parent edge in the selected
current and archived certificate forests also checks that the child issuer names
the exact parent certificate subject. This applies even without ordinary receipts.
A conflict locates the child certificate at `/issuer_key_id` with the original
`invalid_delegation` diagnostic. A child may have its own distinct subject key.
Direct grant children retain the independent earlier-state and rotation rules;
the initial grant issuer is not a permanent issuer shortcut. This comparison
supplies no signature, custody, Clock or accepted-state qualification.


Protected verification also compares complete selected control targets with their
matched receipts. A grant's root key and full independent root-selection reference
must match; a certificate's issuer and full parent authorization must match; a new
snapshot's current issuer must match its signer. Conflicts locate the target's
exact field. These checks follow complete original source closure and preserve
earlier source errors. Rotation and owner withdrawal keep their separate rules;
an owner's withdrawal is not constrained to the retained machine issuer. Matching
declarations supply no accepted root, key custody, Clock, signature or transition.


Selected `issue_certificate` control targets and their complete ancestors enter
the same bounded certificate forest as current and archived snapshots. Exact
parent/grant identity, stream, permission, scope, decreasing depth, finite windows,
key data and non-grant parent issuer checks apply even when a target is absent
from the earlier snapshots. Matching source declarations still do not admit a
certificate, signature, identity, custody, native state or Clock qualification.


Every traversed certificate edge must pass strict child-to-parent depth ordering
before advancing, which also refuses a cyclic parent relation. A selected ordinary
policy is not reinterpreted as a native parent certificate: its fixed native-schema
refusal precedes later time or transition predicates. These source checks retain
the original graph/acquisition limits and do not admit a protected certificate.
