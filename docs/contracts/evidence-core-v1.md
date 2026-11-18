<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — evidence core contract
-->
# Evidence core contract, version 1

This page specifies the rules every producer and consumer of an evidence manifest relies on:
- the canonical form;
- byte identity;
- the evidence-manifest schema;
- the legacy signed-statement profile.

It states what this repository's source implements, and the contract test `tests/test_evidence_core_contract.py` binds each
rule to that source.

## What this page is not

- **It is a specification, not a capability claim.** The repository stays at `local_scaffold` with `architecture_only`
  maturity, and its capability, claim and qualified-schema inventories remain empty.
- **Being written here does not freeze the contract.** A freeze also needs the review record and the conformance
  vectors named in [Freeze](#freeze), and it is recorded outside this repository.
- **It does not make the toolkit's runtime accepted.** Acceptance of the runtime is a separate obligation.
- **It does not authenticate a signer.** Signing keys, roots, delegation and clocks are separate obligations.

## 1. Canonical form

**Profile.** The canonical profile identifier is `rfc8785-jcs-v1`. A canonical document is the RFC 8785 (JSON
Canonicalization Scheme) serialisation of a strictly admitted JSON document, as UTF-8 bytes with no byte-order mark
and no trailing newline. The implementation is the `rfc8785` package at the pinned version
`rfc8785==0.1.4+emt.1`, called by `canonicalize_json`.

**Limits.** Every operation that takes `Limits` checks its six fields before it reads any input. Each must be a
positive integer and not a boolean. The first field that fails, in the order `max_json_bytes`, `max_blob_bytes`,
`max_total_reference_bytes`, `max_reference_count`, `max_graph_depth`, `max_json_depth`, is refused as a
configuration error at `/limits/<field>`. No default or unlimited bound exists.

**Admission.** A source document passes five stages in this order. A stage runs only when every stage before it has
passed. Within a stage, the order stated for that stage decides which failure is reported.

| Stage | What is checked | Refusal code | Order within the stage |
|---|---|---|---|
| 1. Size | The byte length does not exceed `Limits.max_json_bytes` | `limit_exceeded` | — |
| 2. Decode | The bytes decode as strict UTF-8. A byte-order mark decodes here; it is refused in stage 4 | `invalid_json` | — |
| 3. Depth scan | A scan of the decoded text, outside strings, counts open `[` and `{`. More than `Limits.max_json_depth` open at once is refused as `limit_exceeded`; a `]` or `}` with nothing open is refused as `invalid_json` | `limit_exceeded` or `invalid_json` | The first violation in the text |
| 4. Parse | The text is one complete JSON value with no leading byte-order mark (`invalid_json`); no object holds the same decoded member name twice (`invalid_json`, detected when that object closes); no `NaN`, `Infinity` or `-Infinity` literal appears (`unsupported_canonical_number`, detected at the literal). Number spellings are kept as text, not converted | as stated | The first detection in the text |
| 5. Validate | Every number spelling converts to a finite IEEE 754 binary64 value (`unsupported_canonical_number`); every string and member name encodes as strict UTF-8, with no lone surrogate (`invalid_json`) | as stated | Document order: array elements by index, object members in their source order, depth first |

A stage-5 failure is reported only when stages 1–4 pass, whatever its position in the text. Exhausting the
interpreter's recursion capacity while parsing, validating or writing canonical bytes is refused as `limit_exceeded`.
`canonicalize_json` then writes the admitted value. A value the canonical writer refuses is
`unsupported_canonical_number`.

**Examples.** Each row is run by the contract test through `canonicalize_json`. All other `Limits` fields are 1. The
bytes are authoritative; the document column describes them.

| # | Document | Bytes (hex) | `max_json_bytes` | `max_json_depth` | Refusal code | Why |
|---|---|---|---|---|---|---|
| E1 | `[1,2]` | `5b312c325d` | 4 | 8 | `limit_exceeded` | Stage 1 |
| E2 | byte `ff` | `ff` | 64 | 8 | `invalid_json` | Stage 2 |
| E3 | BOM, then `[[[[1]]]]` | `efbbbf5b5b5b5b315d5d5d5d` | 64 | 2 | `limit_exceeded` | Stage 3 runs before the BOM is refused in stage 4 |
| E4 | BOM, then `[1]` | `efbbbf5b315d` | 64 | 8 | `invalid_json` | Stage 4 |
| E5 | `[NaN, {"a":1,"a":2}]` | `5b4e614e2c207b2261223a312c2261223a327d5d` | 64 | 8 | `unsupported_canonical_number` | Stage 4: the literal comes first in the text |
| E6 | `[{"a":1,"a":2}, NaN]` | `5b7b2261223a312c2261223a327d2c204e614e5d` | 64 | 8 | `invalid_json` | Stage 4: the duplicate's object closes first |
| E7 | `[1e400, {"a":1,"a":2}]` | `5b31653430302c207b2261223a312c2261223a327d5d` | 64 | 8 | `invalid_json` | Stage 4 before stage 5, although the number comes first |
| E8 | `[1e400, "\ud800"]` | `5b31653430302c20225c7564383030225d` | 64 | 8 | `unsupported_canonical_number` | Stage 5: the number comes first in document order |
| E9 | `["\ud800", 1e400]` | `5b225c7564383030222c2031653430305d` | 64 | 8 | `invalid_json` | Stage 5: the lone surrogate comes first |

**Numbers.** Numbers are canonicalised from their binary64 value, as RFC 8785 requires. Where a source needs an exact
decimal quantity, its consumer reads the original number spelling, which acquisition retains beside the binary64
value. Canonical bytes never carry that spelling.

## 2. Byte identity

A byte reference (`BlobRef`) identifies one byte sequence. Its wire form is a JSON object with exactly these members:

| Member | Rule |
|---|---|
| `digest` | `sha256:` followed by 64 lowercase hexadecimal digits: the SHA-256 of the identified bytes |
| `byte_length` | the length of the identified bytes as a decimal string, `0` or without leading zeros, at most 256 characters |
| `media_type` | a non-empty string that encodes as strict UTF-8 |
| `digest_basis` | `raw_bytes` or `jcs_content` |
| `schema_id` | optional; when present, a non-empty string that encodes as strict UTF-8. It is omitted when absent; `null` is refused |

Any other member, a missing member, or a wrong type refuses the reference.

**The two bases.**
- **`raw_bytes`** identifies the original bytes as given.
- **`jcs_content`** identifies the canonical document of section 1. Its `digest` and `byte_length` are those of the
  canonical bytes, not of the source.

A declared `schema_id` does not register a schema.

**Cache identity.** Two references denote the same stored bytes only when `digest`, `digest_basis` and `byte_length`
are all equal. Equal digests under different bases are different identities.

**Byte encoding inside JSON.** Raw bytes carried in a JSON string, such as a signature, are base64url without padding
(RFC 4648, section 5). A decoder refuses padding, whitespace, characters outside the alphabet, and any spelling that
does not re-encode to itself.

## 3. Evidence-manifest schema, version 1

| Property | Value |
|---|---|
| Schema identifier | `evidence_manifest_toolkit.manifest.v1` |
| `$id` | `urn:gotm:schema:evidence_manifest_toolkit.manifest.v1` |
| Source file | `src/evidence_manifest_toolkit/_schemas/manifest.json` |
| SHA-256 of the file | `06028ae6f76b8be9ef313827ed384bb9412e75b04fb33365d572c7e784282f9d` |
| Dialect | JSON Schema 2020-12 |
| Required members | `schema_id`, `producer`, `created_at`, `canonical_profile`, `payload_ref`, `source_ref`, `environment_ref`, `claims`, `derived_from` |

Within it:
- `canonical_profile` is the constant `rfc8785-jcs-v1`;
- `created_at` is a UTC date-time ending in `Z`;
- the references are byte references of section 2.

## 4. Signed statements, legacy profile

| Property | Value |
|---|---|
| Profile identifier | `evidence_manifest_toolkit.jcs_sha256_ed25519.v1` |
| Statement schema | `evidence_manifest_toolkit.signed_statement.v1`, `$id` `urn:gotm:schema:evidence_manifest_toolkit.signed_statement.v1`, file `src/evidence_manifest_toolkit/_schemas/signed_statement.json` |
| SHA-256 of the statement schema file | `dc9ae930246a4457d6cb8762d289fda485ec391de16a424888b9b076a989c19c` |
| Canonical profile | `rfc8785-jcs-v1` |
| Digest algorithm | `sha256` |
| Signature algorithm | Ed25519 over the message below; the signature is 64 raw bytes |

**Key identity.** A signer key identity is `ed25519:` followed by the lowercase hexadecimal SHA-256 of the 32 raw
public-key bytes. The identity names the key and grants no authority.

**Contexts.** `signature_context` is `group_statement` or `root_control`.

**Scope digest.** `scope_digest` is `sha256:` followed by the SHA-256 of the RFC 8785 serialisation of the scope
object:
- for `group_statement`, the object is `content_digest` and `claim_ids`, the claim identifiers sorted by UTF-16 code
  units and neither normalised nor repaired. Duplicate claim identifiers refuse;
- for `root_control`, the object is `content_digest` and `purpose`.

A statement whose `scope_digest` differs from this value refuses.

**Message.** The signed message is a domain prefix followed by the RFC 8785 serialisation of the whole statement:
- for `group_statement`, the prefix is `GOTM-EMT-SIGNED-STATEMENT-V1` and one line feed;
- for `root_control`, the prefix is `GOTM-EMT-ROOT-CONTROL-V1` and one line feed.

No envelope field, payload digest alone, algorithm fallback or rewritten time enters the message.

**Detached envelope.** A detached envelope is a JSON object with exactly two members:
- `statement`, which is valid against `signed_statement.v1`;
- `signature`, the base64url encoding of section 2 of exactly 64 bytes.

Any other shape refuses.

**Trust classes.**
- **Legacy.** Verification under the legacy `TrustContext` is the route this version specifies.
- **V2 successors.** The successor trust classes `UnsignedTrustContextV2`, `SoftwareTrustContextV2` and
  `DelegatedTrustContextV2` are not part of version 1. Today they end at a configuration refusal for `/trust` when no
  earlier reason applies. A later version of this contract adds them through the change procedure below.

## Change procedure

- **Versioning.** This contract changes only by a new version, never by editing a version in place. A new version
  states what changed, which consumers it affects, and the evidence for it.
- **Compatibility.** A consumer pinned to version 1 keeps the rules above.

## Freeze

Version 1 counts as frozen only when four things exist together:
- this page, at a recorded digest;
- the conformance vector pack for version 1;
- a passing run of that pack against this repository;
- a review record from the group's review seat.

The freeze record that names all four is kept with the group's coordination records, outside this repository.
