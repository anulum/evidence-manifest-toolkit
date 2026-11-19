<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — Python evidence boundary
-->
# Python API

The source module is `evidence_manifest_toolkit`. Its runtime is under development; the repository's qualified capability inventory remains empty. The functions below operate on caller-supplied bytes, configurations and sources. Operational root, signer, clock and scientific qualification are separate obligations.

| Function | Explicit inputs | Result |
|---|---|---|
| `canonicalize_json` | `data: bytes`, keyword `limits: Limits` | Complete RFC 8785 canonical bytes. |
| `reference_bytes` | `data: bytes`, keywords `media_type`, `digest_basis`, `schema_id`, `limits` | `BlobRef` identifying the selected raw or canonical bytes. |
| `inspect` | `content_json: bytes`, keyword `limits` | `Inspection` containing declarations and diagnostics; acceptance is `not_evaluated`. |
| `diff` | `left_json`, `right_json`, keyword `limits`, optional ordered `left_envelopes` and `right_envelopes` | `Difference` with content identities, changed pointers and receipt identities. |
| `seal` | `content_json`, keywords `schema_id`, `registry`, `resolver`, `limits`, optional `signing`, `signer`, `trust` | `SealResult` with canonical content, its reference and an optional detached envelope. |
| `verify` | `content_json`, keywords `schema_id`, `envelopes`, `registry`, `resolver`, `limits`, `policy`, `trust` | Complete fifteen-field `VerificationReport`. |

All six limit fields are explicit positive integers: `max_json_bytes`, `max_blob_bytes`, `max_total_reference_bytes`, `max_reference_count`, `max_graph_depth` and `max_json_depth`. `Limits.validate()` checks the declaration; operations independently check it before acquisition. Construction supplies no defaults or unlimited mode.

Native parser or canonical writer recursion exhaustion raises `InputRefused` with
`Reason.code="limit_exceeded"`, even when `max_json_depth` permits the document's
container depth.

`BlobRef` retains `digest`, decimal-string `byte_length`, `media_type`, `digest_basis` and optional `schema_id`. Its constructor retains the supplied declaration. `BlobRef.from_mapping()` and `to_mapping()` validate the complete wire shape; the returned mapping is detached and read-only. Neither method retrieves bytes or establishes their identity. The wire representation omits an absent `schema_id`; an explicitly received null is invalid.

`reference_bytes` requires `digest_basis="raw_bytes"` or `"jcs_content"`. Raw identity binds the original bytes; canonical identity binds the complete strict canonical document. The helper does not rewrite or store the input. A declared schema ID does not register that schema.

## Sources and authority

The caller selects a complete `SchemaRegistry`, including its snapshot reference and all fourteen fields of every `RegistryEntry`. Static schema bytes, dependencies, reference paths and common semantics are independently checked. An artifact cannot choose a Python implementation or network schema resolver.

Registry size follows the caller-selected catalogue. The supported QPU successor catalogue requires all 77 of its fixed source entries; received content cannot add, remove or substitute those entries.

The caller's `Resolver` implements both methods:

```python
resolve(reference: BlobRef, *, max_bytes: int) -> bytes
resolve_digest(digest: str, *, max_bytes: int) -> bytes
```

Each read returns actual bounded bytes. A missing target raises `ReferenceUnavailable` with the exact original argument in `.reference`. A digest-only lookup retains the original digest string; it does not fabricate a missing length or schema declaration. Operations check returned identities and share cumulative reference budgets across the whole selected graph.

An uncached full-reference read receives the smaller of `max_blob_bytes` and the
remaining cumulative allowance. An exhausted allowance refuses before calling
the resolver. Cached bytes retain their metadata checks and require no new read.

`TrustContext` selects an independently accepted bootstrap policy, current snapshot, accepted sequence floor, evaluation mode and time, explicit control envelopes, and an optional archived snapshot. Historical mode requires the selected archive and retains current floor and revocation checks. Verification does not install a snapshot, advance a floor, issue a certificate or derive trusted time from a producer timestamp.

The exported frozen `UnsignedTrustContextV2`, `SoftwareTrustContextV2` and `DelegatedTrustContextV2` values retain explicit namespace, profile class, evaluation mode/time and the complete Clock entry binding. Software additionally selects its whole authorisation table and sequence floor; delegated selects the independent root, grant, current state, floor, ordered control envelopes and control-selection rule. Their historical archives are class-specific. Verification rechecks the complete caller and pairs it with the whole independently selected `authority_policy.v2` before authority acquisition. A legacy policy, mismatched class or fixture policy cannot select the V2 operational route. Missing selected policy sources preserve their exact original unavailable reference. V2 source selection does not initialise the legacy signature provider; native authentication remains an obligation of the eventual selected state method. Legacy verification retains its original provider checks and failure precedence. These declarations do not qualify their sources; the subsequent operational state path still requires legacy `TrustContext` and refuses a V2 declaration rather than manufacturing equivalent legacy authority.

For these three V2 classes, `verify` captures an actual `CLOCK_MONOTONIC_RAW` entry observation before reference acquisition through its fixed Linux/glibc x86-64 method. It retains the whole read-only kernel `timex` result, acquisition bracket, boot source, process source and runtime environment. The independently selected method reference must match the entire installed `_native_entry_method.json` and its five implementing source files. Boot bytes, stable PID/start identity and the whole runtime environment must match their selected raw sources. Those source reads and implementation resources share the invocation's original quota. An unavailable original source preserves `ReferenceUnavailable.reference`; an unknown method or conflicting native identity refuses with the selected policy's evaluation-time diagnostic. Unsupported native environments also refuse. Matching these sources establishes neither physical uncertainty nor an accepted Clock, controller, witness or authority. When the complete Clock source graph is available, verification also compares its whole caller context, content, ordered receipts, registry, limits, profile and base/final policy reconstruction. It checks the declared capture interval and civil-year acceptance window, the fixed native tick calibration and S1 ≤ H ≤ actual E. Declared source errors still need independent physical proof and complete propagation through E. The subsequent V2 state method remains unavailable as described above.

For a software V2 caller, policy pairing precedes acquisition of the whole current software authorization table and its explicit predecessor history. Verification checks the original decimal floor against current state even in historical mode, keeps the independently selected archive and its whole history, and compares its complete scope-rule reference with the selected authority policy. Stream, sequence, issued-time, raw key encoding/ID, unique complete entry and nonempty key-window checks retain every original source and revocation edge. A historical source need not be an entry in the current chain, but it must match the installation and cannot be later than current state. Both whole table histories also join the Clock context closure with their fixed private bindings, retaining the original depth, byte and count bounds and every distinct edge. Missing tables preserve their original unavailable references. These source checks precede Clock acquisition and supply no curve/signature, possession, custody or authority acceptance. Unsigned callers acquire no software table.

Explicit software receipts additionally undergo whole content, selected table, scope-reference and claim-scope correspondence checks. A single complete key row must match the signer, purpose and ordinary policy principal/role/segment; different rows cannot be combined to widen scope. Claimed signing and caller UTC must fall inside that row's half-open validity window, and a declared revocation in either complete selected history prevents correspondence. An actual compatible signature initializes the maintained provider and checks the exact complete V2 message and key. Target/scope conflicts and invalid signatures retain located typed refusals. Empty software receipt populations initialize no provider. After the whole conditional Clock calculation, the selected software source must already exist at the interval start and claimed signing time. One complete equation-verified row must cover the entire S0-through-native-entry interval, including its uncertainty: the lower endpoint is inclusive and the upper endpoint must precede expiry. Multiple partial rows cannot be joined; an additional narrow row does not invalidate a different complete covering row. Missing complete coverage retains an invalid_delegation refusal at the receipt's /statement/authorization_ref. These necessary checks do not establish the whole scope rule, authenticated identity/possession/custody, qualified Clock or complete native authorization.

`VerificationPolicy` supplies the policy reference, exact required claim and purpose populations, and any declared reference requirements. The referenced policy and caller selections must agree. Selecting a narrower claim population preserves the full content and reference observations; it does not rewrite the inventory or supply a domain verdict.

Unsigned `seal` uses `signing=None`, `signer=None` and `trust=None`. Signed construction requires all three together and current authority. The actual caller-owned `Signer` exposes raw public-key bytes and `sign(message: bytes) -> bytes`. The signature covers the complete context-specific message and is checked before an envelope is returned. A signer failure does not trigger unsigned construction. Initial root issuance and adapter qualification are outside these functions.

## UTC values

`Utc(raw)` validates an original string using the Gregorian calendar, the selected leap-second history and the complete fractional token. It is an immutable string subtype. It preserves the original spelling, including the distinction between `T` and `t`, and uses ordinary string equality for wire identity.

`value.compare(other)` accepts `Utc` or a string, revalidates both operands and returns `-1`, `0` or `1` by exact instant order. It does not round through a floating-point epoch. Malformed scalar input raises `InputRefused` with the original located reason.

The caller's independently qualified `Clock.now()` supplies the time token. `Utc(clock.now())` validates that token; it does not qualify the clock's source, controller, capture, freshness or uncertainty. The existing clock precondition remains with its owner. Required unavailable clock qualification retains the policy refusal in the complete verification report.

## Reports and failures

`VerificationReport` retains all fifteen fields: `content_ref`, `policy_ref`, `registry_ref`, `evaluation_mode`, `evaluation_time`, `evaluated_claim_ids`, `structure`, `integrity`, `authenticity`, `availability`, `common_eligibility`, `domain_verdict`, `current_eligibility`, `reference_observations` and `reasons`.

Common eligibility reports the applicable common gates. `domain_verdict` remains `not_evaluated`; the separately owned domain consumer supplies scientific acceptance. Historical common eligibility does not establish current eligibility. Inspection and difference results do not authenticate receipts or accept evidence.

Thrown `EmtError` subclasses carry one complete `.reason`: `InputRefused`, `ConfigurationError`, `ReferenceUnavailable`, `SignerUnavailable` or `StorageError`. A `Reason` has `code`, `subject_digest`, `claim_id`, `pointer` and fixed `detail`. Unknown identities retain their null values. Returned verification refusals remain complete reports rather than being replaced with a successful Boolean.

An unsigned V2 caller (`UnsignedTrustContextV2`) whose whole sources pass acquisition receives this same fifteen-field report. It is composed without any authority state: no bootstrap, snapshot, floor or receipt is selected, so `authenticity` is `unsigned`, and `current_eligibility` is always `refused`. The signature scope was already decided by the selected signature-obligation rule and its exact unsigned exception, so the legacy receipt rules are not applied again. While no accepted Clock verdict exists, the report keeps `policy_unavailable` at the policy's Clock qualification pointer and its common result is `refused`. Software and delegated V2 callers are still refused at `/trust`.

After an eligible signing adapter is called, response failure uses the fixed
`SignerUnavailable` reason and known content digest. Other typed operation errors
retain their classification. Internal verifier errors are separate from adapter
response failures.

The complete selected V2 identity and validation method rules are acquired after class source initialization and before Clock acquisition, using their known private format bindings and the same operation quota. Verification checks the rule classes, permitted minimum identity, full identity-rule reference, compatible non-use classes and the optional foreign-rule/trust-reference pair. Every whole rule and its declared procedure edges remains in the source closure. Required rule absence preserves the original full unavailable reference; malformed rules and contradictory selections retain located typed errors. These checks establish source consistency, not authenticated identity, reproduction, foreign trust or Clock acceptance. No foreign verifier, root refresh or network operation is launched by this selection.


## Native method declaration sources

Before Clock acquisition, V2 reads the whole selected launcher or observer,
key-possession, execution/seal/release and comparison declarations. The existing
identity/validation rule references select these data; received code, module names
or schema IDs never select an executable. The four declarations and all their
reference edges share the original resolver and cumulative operation limits.
The complete identity, validation, optional foreign and four declaration roots
join one connected rule closure and then the original Clock closure. Their fixed
formats remain available along every parent-to-descendant path, so graph depth
and cycle checks do not restart at a procedure reference. Subsequent Clock,
signature and reproduction checks retain these same acquired declarations.

Each declaration has `method_version="1"`, `implementation_ref`,
`implementation_environment_ref`, `implementation_qualification_ref` and
`semantic_law_ref`, plus its fixed role-specific inputs. The launcher declaration
selects the complete raw launch-record contract and discloses declaration-only
vendor/key limits. The observer declaration retains its complete capture,
authority and endpoint rules. Possession retains the issuer/receiver rules;
execution retains original request, executor, seal, release and non-use selections;
comparison retains the algorithm, complete parameters and outcome mapping.

The entire fixed grammar is read and identity-checked under the same quota,
with no public registry entry or extra `schema_id`. Missing selected sources
preserve their original full references. Invalid whole shapes, reference metadata
or bounds retain typed source failures; absent or changed installed grammar is a
configuration failure. Actual implementation/environment/qualification, observed
identity, possession, custody, execution, comparison and Clock predicates remain
required. A consistent declaration then reaches the unsigned report, or the pending
V2 state boundary of the software and delegated classes; it does not produce an
accepted class or a successful verification report.

## Selected signature-obligation method

After a complete matching V2 Clock subject and any software receipt checks,
verification reads the independently selected `signature_obligation_rule_ref`.
The fixed data method is `emt_signature_obligations_v1`. It defines no public
schema or executable selector. Verification validates and retains the whole
rule. After complete Clock calculations, unsigned/software verification applies
its exact exception and actual receipt coverage. Complete V2 class/state
admission remains pending: a covered scope reaches the unsigned report, or the
state refusal of the software and delegated classes.

The rule is one closed JSON object with every field below. Its reference uses
`application/json`, `raw_bytes` and no `schema_id`.

| Field | Complete value |
|---|---|
| `method_id` | Exactly `emt_signature_obligations_v1`. |
| `profile_class` | The exact independently selected V2 class. |
| `whole_base_policy_ref` | Whole earlier operational policy, with an explicit null Clock slot. |
| `whole_conditions_and_limitations_ref` | Exact whole reference selected by the enclosing authority policy. |
| `required_claim_ids` | Exact ordered caller policy population. |
| `required_purposes` | Exact ordered caller population, using only `evidence`, `deployment`, `human_review`. |
| `required_reference_paths` | Exact complete ordered caller reference requirements, including null instance pointers. |
| `unsigned_exception` | Null, or the exact unsigned scope described below. |
| `valid_from`, `valid_until` | Original valid UTC strings defining a nonempty half-open interval. |
| `renewal_rule` | Exactly `fresh_independent_rule_before_expiry_no_implicit_extension`. |
| `provenance_refs` | Nonempty ordered population of unique whole JSON source references. |

The base reference must exactly match the complete reference selected in the
frozen Clock subject. Equal-valued different raw bytes or a one-sided basis change
refuses that join. The entire base policy must also equal the final ordinary policy
after replacing only its Clock reference with null. Other fields, arrays and limitations remain
unchanged. The base, conditions and every provenance body are actually acquired
and checked under the original cumulative byte and reference limits. Their whole
JSON objects retain the original reference metadata and digest basis, including
`jcs_content`; the raw rule's metadata restriction does not rewrite those sources.
Unknown fields, methods and unsupported rule metadata refuse configuration. Missing sources preserve their
exact original unavailable reference. Contradictory complete policy or scope
joins produce `policy_unavailable` at the affected rule field. The reason names
the actual raw rule digest and a real field pointer inside that rule. Unsupported
metadata on the rule reference identifies the enclosing policy reference slot.

An `unsigned_exception` object has exactly `content_ref`, `claim_ids`, `purposes`
and `validation_record_refs`. The full content reference must match the actual
content. Every unique claim ID must resolve in its whole inventory, every purpose
must belong to the selected policy, and every whole validation reference must
belong to a listed claim. Software and delegated classes cannot carry this
exception. Null and empty scope populations imply no additional waiver; neither
missing receipts nor the class label supplies one.

Parsing the window does not check a caller time centre in place of the complete
Clock-through-entry interval. Parsing provenance does not establish independent
authority, identity, source accuracy or reproduction. No signature requirement,
legacy rule, Clock bound or native acceptance is cleared by these source checks.


Once these complete bindings and the conditional Clock calculation succeed,
unsigned and software verification check the whole content signature scope.
Each required claim/purpose pair needs its own actual receipt coverage or the
exact selected unsigned exception. A null exception, empty claims or empty
purposes waives nothing. An exception applies only to the ordinary complete
native manifest; it cannot waive a control target's signature requirement.
Missing required claim IDs retain `scope_missing`. Missing receipts with an
unwaived obligation retain `signature_required`; actual supplied receipts with
an uncovered claim or purpose retain the corresponding located `scope_missing`.

Software coverage retains the whole actual target/key equation result and its
matching source rows. It supplies no native custody, identity, state, time or
authority acceptance. Intrinsic measured/reproduced claim obligations remain
even outside the caller's required claim list. A signature of the C0 manifest
does not sign its validation records: each unwaived whole record retains its
separate `signature_required` reason. A record exception needs the exact full
record reference, that claim and the evidence purpose. Actual reproduction,
physical acceptance and every other native predicate remain independent.

A covered content scope then reaches the unsigned report, or the pending V2 state
refusal of the other classes. These checks add no report field or successful failure reason and leave legacy
verification and its entire original reports unchanged.

## Whole reproduction record sources

After complete Clock calculations and applicable ordinary signature coverage,
verification reads each independently reproduced claim's entire native record,
earlier body, producer and runner identity bindings, earlier subject and whole
paired policy. An optional foreign identity remains a distinct source. Every
selected graph shares the invocation's original reference budget. The earlier
record policy is retained separately from the later verification policy.

Ordinary content signature failures and outstanding record requirements are kept
separately. Covered ordinary content permits checking the record's actual sources;
the pending record requirement cannot prevent its own source acquisition. Every
unwaived record requirement remains in the aggregate failure result until its full
selected earlier predicate passes. Missing or malformed record sources retain their
actual typed errors. Reading a source, reconstructing a parent or verifying a signature
equation clears no such requirement.

Verification checks the whole record/body subject, claim and policy joins,
selected conditions, custody, permitted record/identity/non-use classes,
declared producer and runner principals, and outcome. Each entire producer and
runner identity binding must declare the selected identity rule's custody class
and name that same complete rule in its whole policy reference. Another rule
with matching class labels cannot replace the independently selected rule.
These joins follow complete original source closure and precede native runner
checks; conflicts retain the actual identity source and field in `invalid_claim`.
They supply no launcher, key-possession, observed identity or run qualification.
Equal declared vendors,
principals or whole key references refuse independence. Different references
establish neither different actual keys nor possession. A declared runner key
must match its identity binding's complete key reference. When both declared key
sources are supplied, their actual whole bytes must also differ; changing reference
metadata does not create an independent key.

An explicit validation C0 is checked as an entire native manifest, including its
common semantics and required graph. It must actually cite the earlier whole body;
no particular invented citation field is required. Ordered native receipts require
that C0 and the runner's explicit raw32 key. Every receipt is parsed in the ordinary
context, binds the complete canonical validation C0, and names only claims present
in it. Its actual V2 equation is checked with the runner key. A protected record also
requires the receipt certificate's actual public bytes and subject key ID to match
that key. These checks retain the full validation content, key source/data and
ordered receipts under the same invocation budget. They do not select historical
authority by the current caller time, infer required validation claim coverage from
the earlier claim's spelling, or replace the complete independent validation policy.

Verification also reads the entire native execution observation and request, output
release, comparison request and observation, raw comparison evidence and access
records through the existing fixed native-method data grammar. Their full graph
shares the original reference budget. Request subjects, claims, policies, selected
methods, runner identity, ordered inputs and outputs, release targets, comparison
implementation/environment/qualification sources and declared outcomes must agree
across the complete records. Access event sequence tokens must increase strictly.
Later release and comparison access records preserve each earlier whole event as
an exact prefix, including every original reference. Their complete method,
qualification, recorder, environment and input-boundary references remain equal.
The recorder is distinct from the observed processes recorded in individual events.
An unchanged or empty prefix supplies no evidence of capture completeness, event
time, loss detection or enforced isolation.
The comparator retains its own identity and launch source; it may be a different
process from the execution runner. Missing declared process identities remain
unavailable rather than being inferred from another record. These checks establish
source correspondence only: they do not prove execution, isolation, seal/release
chronology, the comparison algorithm, source qualification or Clock acceptance.

For a supplied native key-possession source, the preliminary source path also
compares the complete selected identity, method, challenge, issuer declaration and
execution request. It verifies the raw own-key signature over the fixed
`GOTM-NATIVE-KEY-POSSESSION` domain, its NUL/version bytes and the entire canonical
eight-field context. An ordinary statement signature cannot substitute for this
message. Challenge and receiver C0 manifests retain their actual caller schemas,
full source graphs and ordered receipt targets. The declared receiver transaction,
previous and following states, consumed response, head bytes, stable file metadata
and reception interval must agree. Historical head locations remain data and are
never opened by verification. These checks do not establish independently authorised
issuance, an unpredictable nonce, accepted event time, authenticated controller
receipts, durable challenge consumption, observed process capability or key custody.
Omitting a proof supplies no required-possession acceptance; matching sources still
require the complete native identity, method and class qualification.

The challenge C0 also retains its whole issuance observation and both issuance
states. Its challenge, issuer, issuance method and time-source references must
match the independently selected sources; the issuer's selected completion method
must match the actual receiver method. A new issuance preserves the entire prior
ordered challenge population and completion rows, adds exactly the selected raw
challenge and advances the original state sequence once. Its declared file head
must name that successor under the selected storage/owner binding, with stable
regular-file metadata, matching byte size and the complete selected size bound.
The non-bootstrap head retains an entire identity-checked raw journal. Those
opaque journal bytes do not establish a native journal format, atomic transaction,
durability, independent issuer eligibility or unpredictable issuance.

After these source checks, verification follows the complete causal manifest history.
Each later parent must reconstruct from one actual earlier whole manifest by changing
only the selected claim's validation, evidence maturity and verdict. The earlier origin
must be executed, simulated or measured. All other claims, source references, scope,
conditions, measurements and limitations remain exact. Comparison uses whole canonical
JSON bytes, preserving JSON types. An inherited record keeps its own earlier subject;
it is not incorrectly compared directly with every later parent. Revalidating one claim
and successively validating different claims use the same rule.

Every earlier manifest and explicit validation C0 receives its original native schema
and common checks even when optional reference schema metadata is absent. Complete
typed source closure enforces the original depth, count and byte limits from the actual
current root; separate earlier roots cannot restart the depth allowance. Original raw
references and source bytes remain intact. A source-compatible structural history is
retained with the invocation, without qualifying historical policy, identity, signatures,
independent execution, comparison, non-use or Clock evidence.

Successor preparation also retains a definitive whole current content result using
the original caller schemas, independently installed native formats and the actual
selected history roots. It reapplies the original required reference-path population
under the same invocation budget. Earlier static-only unknown-format observations
are not filtered into success or merged with contradictory later observations. The
original content identity and frozen Clock subject remain unchanged, and actual
common/source reasons remain available for the complete successor report method.

Missing sources retain their exact `ReferenceUnavailable.reference`; invalid
sources retain their original typed reason, including failures already found
in the Clock source closure. Located relation conflicts use `invalid_claim`.
Consistent declarations still reach the pending V2 state refusal. They do not
establish a committed independent run, output sealing, comparison order,
authenticated identity, physical Clock, foreign trust or class admission.

## Complete conditional Clock methods

For a whole matching V2 invocation, verification also reads the original three
raw method slots. They are fixed data interpretations, with no executable or
provider dispatch. This source path computes numerical/source consistency;
independent physical model, calibration, source-version/rotation/renewal and
class admission remain required. A consistent calculation still reaches the
pending V2 state refusal described above.

| Existing slot | Fixed `method_id` | `units` |
|---|---|---|
| Profile `holdover_drift_bound_rule_ref` | `emt_monotonic_raw_drift_v1` | `nanoseconds_per_elapsed_nanosecond` |
| Profile `uncertainty_derivation_rule_ref` | `emt_timesyncd_uncertainty_v2` | `integer_nanoseconds` |
| Witness `holdover_and_use_error_derivation_ref` | `emt_clock_use_bounds_v1` | `integer_nanoseconds` |

Each entire record requires `method_id`, `units`, `custody_class`,
`host_identity_ref`, `controller_identity_ref`, `implementation_environment_ref`,
`boot_domain_ref`, `valid_from`, `valid_until`, `renewal_rule`,
`assumptions_and_limitations_ref` and nonempty unique ordered `provenance_refs`.
The renewal literal is
`fresh_source_model_before_expiry_no_implicit_extension`. Class, full sources,
boot and limitations must match the independent whole invocation. Method records
use `application/json`, `raw_bytes` and no public schema. Their provenance keeps
its original complete metadata/basis; a declared schema requires its whole known
structural dependency graph. Every read uses the original cumulative limits.

The drift record additionally requires `maximum_error_rate` with canonical
nonnegative `numerator` and positive `denominator`, plus `rate_source_ref`,
`calibration_source_ref`, `monotonic_mapping_rule_ref` and `adjustment_rule_ref`.
The exact finite fraction is declared nanosecond error per elapsed nanosecond.
Neither its presence nor a Frequency, jitter or synchronized value establishes
an independently supported physical drift bound.

The uncertainty record additionally requires `holdover_rule_ref`,
`daemon_field_mapping_rule_ref`, `accepted_ntp_configuration_ref`,
`acquisition_rule_ref`, `ntp_resolution_and_rotation_rule_ref` and
`sample_mapping_and_quantization_rule_ref` and `annual_derivation_ref`. They retain
the complete earlier models and known source mappings. The selected drift reference must match the
profile's entire original selection. These models precede the profile and do
not refer to future samples, witnesses, final policies or entry observations.

The uncertainty record selects one complete original annual dependency through
`annual_derivation_ref`. Its fixed method is `emt_clock_acceptance_bounds_v1`
with `integer_nanoseconds` units, the same twelve common method fields, and
exactly these additional fields: `monotonic_domain_ref`, `ticks_per_second`,
`before`, `after`, `raw_synchronization_refs`, `measured_offset_source_ref`,
`sample_bounds` and the six rule references listed for the uncertainty record.
This is data under the existing owned uncertainty slot, not a public schema or
an executable selected by the artifact. The previous uncertainty method is
unsupported; a missing original annual dependency is not filled from a later use.

Each annual `before` and `after` association contains exactly
`clock_sample_raw_ref` and `ntp_ref`. The sample reference matches that original
annual sample, and each selected packet belongs to the complete original annual
synchronization population. `measured_offset_source_ref` selects one of those
associated packets; its exact signed calculated offset must equal the annual
`measured_ntp_offset_ns`. The complete original context and six rule selections
must match. Both positive rational tick rates are compared exactly, so equivalent
fractions retain their original encoding without being rejected. Every declared
source and edge uses the same original cumulative budget.

Each annual sample has its own complete six-term `sample_bounds` map. Verification
uses its original packet, raw acquisition bracket, calibration and mapping to
recompute the entire N+B accuracy requirement and M/Q bounds. Later request-bound
sources cannot replace annual inputs. The original capture must fit the annual
method's own half-open applicability window; the later issued acceptance body's
validity is a separate interval. None of these associations or numbers establishes
physical calibration, source support, model qualification or any annual check.
The child precedes the uncertainty record, profile and complete acceptance body
and contains no backward reference to those later sources.

The later use record additionally requires `subject_ref`, `profile_ref`,
`first_sample_source_ref`, `request_id`, `uncertainty_rule_ref`,
`holdover_rule_ref`, `before_ntp_ref`, `after_ntp_ref`, `before_raw_ref`,
`after_raw_ref`, `use_raw_ref`, `use_monotonic_ticks`, `use_error_bound_ns`,
`sample_bounds`, `use_terms` and `entry_terms`. All whole references and request
values match the original frozen subject/profile/samples. Both packet references
belong to the witness's complete raw synchronization population. The record is
created after S1/H and precedes the witness; actual E is acquired separately.

Each of `sample_bounds.before` and `sample_bounds.after` has exactly
`source_encoding`, `elapsed_holdover`, `post_exchange_adjustment`, `acquisition`,
`mapping` and `quantization`. Each of `use_terms` and `entry_terms` has exactly
`acquisition`, `mapping`, `quantization` and `adjustment`. Every term is a closed
object containing canonical nonnegative integer-string `bound_ns` and whole
`source_ref`. Missing terms have no default. Explicit numbers remain declarations
until their actual source/model premises qualify them.

The fixed raw sample mapping retains exactly `clock="CLOCK_REALTIME"`, signed
integer-string `utc_ns`, nonnegative `raw_before`, `raw_after` and a nonempty
`physical_uncertainty` declaration. Verification compares the actual raw UTC,
monotonic endpoint and full acquisition bracket. The uncertainty string supplies
no proof. It recomputes exact packet offset/delay, every eight-term N contribution,
and checks at least N+B in the sample's accuracy radius plus complete M and Q.

Exact calibrated elapsed, the entire declared H error and all entry additions
extend the complete interval through actual E. Actual entry acquisition must fit
its selected whole bound. The recorded H upper endpoint must contain the full H
interval; neither a centre nor a partial addition suffices. The complete union
must fit five seconds around the unchanged S0 and every actual acceptance/model/
signature-rule half-open window. Passing arithmetic clears no physical source,
issuer, custody, reproduction, domain or scientific obligation.

The original annual acceptance capture is also recomputed from its complete
before/after samples and raw sources under the same cumulative limits. Its own
rational tick calibration applies; current entry ticks do not replace that older
domain. Each raw UTC and monotonic endpoint must match, and the declared accuracy
must contain the entire acquisition bracket. All declared accuracy, mapping and
quantisation terms enter the recomputed interval. The recorded acceptance bounds
must contain that whole interval and fit five seconds around its original before
sample. The acceptance validity is checked separately against actual invocation
use through entry; it does not authorise the earlier measurements from which
the acceptance is issued. This checks numerical
and source consistency; it does not approve the six stored check outcomes or
establish physical model, source, calibration, identity or class acceptance.

### Verification execution and rendering

The library returns the original `VerificationReport` with all fifteen fields.
For CLI rendering, verification retains its complete invocation, acquired sources
and original cumulative budget. The offline CLI renders its exact
report bytes before closing the original object store, then publishes the
report after successful closure. Rendering adds no resolver, source budget,
public function or report field, and does not qualify any remaining V2 class
or physical-source obligation.

### Protected control source selection

An explicit `DelegatedTrustContextV2` also selects the entire private
`emt-protected-control-rule-source-r6` and
`emt-protected-control-selection-source-r6` bodies. Their whole rule, independent
root selection, earlier ordinary base and conditions must agree. The earlier
base retains an explicit null Clock slot; after whole Clock binding it must
equal that invocation's complete selected base reference.

The finite ordered selection must correspond exactly to the explicitly supplied
control envelopes. Each expected operation selects its fixed native target
schema. Verification checks the whole separately acquired statement and target,
purpose, signer, authorizing state, authorization and scope. The envelope digest
covers its original supplied bytes, including JSON whitespace; a canonical
digest cannot substitute for those bytes. Repeating the same canonical receipt
with different whitespace is still a duplicate.

The selected grant must bind the complete same r6 rule, independent root and
rotation rule. Verification also reads the actual current snapshot and every
predecessor under the original current floor. Grant and stream references must
match exactly; sequence and issue-time history cannot move backwards, finite
snapshot windows must be nonempty, and whole earlier revocations cannot be
removed or narrowed. Duplicate whole certificate, identity or revocation rows
are refused. Historical evaluation retains the current history and floor while
reading its separately selected archive and complete predecessor history.
These are source checks; they authenticate no bootstrap anchor or state signer.

Every declared certificate in the complete current/archive histories also
resolves its entire parent chain to the exact independently selected grant.
Verification checks all five scope dimensions, strictly decreasing path depth,
the parent's literal certificate-issuance permission, finite child/parent
windows and zero-depth ordinary-only operations. An alternative advertised
grant is refused instead of becoming a replacement root. Complete parent
sources join the same bounded closure and Clock inputs. Matching these bounds
does not authenticate a certificate issuer or replace the full native,
identity, custody, withdrawal and actual signing-time predicates.

All selected source and descendant reads share the original cumulative limits.
Unsigned and software callers acquire no protected control sources. These checks
establish source correspondence only: an empty selection supplies no bootstrap
approval, and matching receipts supply no accepted protected state or eligible
signer. Complete root/grant/custody/current-history/floor/Clock/native-signature
and transition predicates remain required. Verification installs no authority
and introduces no public control operation or additional report field.

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

The delegated source path checks the entire conservative capture-through-entry interval
against the selected grant lifetime and snapshot window, then each matched ordinary
certificate and its complete parent chain. An until-withdrawal grant retains its actual
lower bound and explicitly absent upper bound; withdrawal and authority still require
their original independent checks. Historical control signers retain their own original
claimed-time requirements. These source-window relations supply no accepted root,
protected custody, physical Clock, class result or completed V2 report.

The reproduction source path interprets the entire known launcher record for each
producer and runner after their original whole policy/custody/class relations.
The selected launcher reference must match the independent method declaration.
All14root fields and whole file/process objects are checked, including original
canonical integer tokens and unchanged Common UTC. Seat and a nonempty recorded
vendor must match the declared identity exactly. An empty vendor remains absent
corroboration; the declared key string remains opaque. Recorded paths, PIDs and
file hashes are historical data and select no filesystem/process lookup or code.
Both complete raw records remain with the original reproduction inputs under the
same resolver and quota. These checks authenticate no publisher, process, key,
Clock, custody, execution or identity class; complete V2 admission remains required.

The known raw-launch method also binds its complete selected implementation to
the whole installed descriptor and every maintained package Python/JSON body.
The complete original implementation, environment and qualification sources are
acquired from the caller's resolver before their connected reference graph closes.
Physical installation matching follows that closure; local files cannot replace
an unavailable original caller-selected source.
Documentation inside an implementing Python file is part of its byte identity.
A documentation-only change therefore requires a corresponding whole descriptor.
An earlier descriptor retains its original identity and refuses against a changed
installation; local files do not replace the caller's explicitly selected source.
The descriptor's native filename/length/hash rows select no received path or code.
Actual resources are discovered only inside the fixed installation namespaces;
missing, changed, omitted or extra source bodies refuse. All complete bytes share
the original operation quota. The entire selected method environment is compared
with the actual environment captured at this verification's entry. Historical
producer/runner process facts remain their own sources. The complete original
qualification bytes stay unadmitted: code/environment correspondence alone
establishes no independently qualified method, identity, Clock, custody or class.

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
