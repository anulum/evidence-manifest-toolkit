# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — real public native certificate source graph boundaries

"""Exercise complete parent source bounds without claiming protected certificate admission."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest
from tests.domain.protected_certificate_inputs import (
    CERTIFICATE_SOURCE_CASES,
    CertificateSourceCase,
    protected_certificate_input,
)
from tests.domain.signature_rule_cli import invoke_rule_cli
from tests.domain.test_cli_evidence_sources import _transport
from tests.domain.test_verification_report_sources import (
    _array,
    _bytes,
    _FileResolver,
    _mapping,
    _object,
    _registry,
    _text,
)

from evidence_manifest_toolkit import InputRefused, ReferenceUnavailable, VerificationPolicy, verify


@pytest.mark.parametrize("case", (*CERTIFICATE_SOURCE_CASES, "cli_historical"))
def test_complete_native_parent_source_bounds_through_public_entry(
    case: str,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    chosen: CertificateSourceCase | None = None,
) -> None:
    """Retain entire native parent, scope, depth, window and original source-error semantics.

    Parameters
    ----------
    case : str
        Exact source-consistent chain or independently authored whole input counterfactual.
    tmp_path : Path
        Actual complete source and original offline command store, never an installed root.
    capfd : pytest.CaptureFixture
        Real module CLI output descriptors without replacing resolver or signature provider.

    chosen : CertificateSourceCase or None
        Complete prebuilt original sources, or the original case constructor when absent.

    Notes
    -----
    All sources are explicitly unqualified. A consistent graph reaches the actual
    required Clock refusal; no key, custody, identity, issuer or certificate is admitted.
    """
    cli = case.startswith("cli_")
    chosen = (
        protected_certificate_input(case.removeprefix("cli_"), tmp_path)
        if chosen is None
        else chosen
    )
    inputs, declared = chosen.inputs, chosen.declared
    originals = {path: path.read_bytes() for path in chosen.population.values() if path.exists()}
    resolver = _FileResolver(chosen.population)
    if cli:
        wire = _object(_mapping(chosen.caller))
        if chosen.caller.evaluation_mode == "current":
            del wire["archived_authority_snapshot_ref"]
        status, report = invoke_rule_cli(
            tmp_path,
            population=chosen.population,
            schema_id=_text(inputs["schema_id"]),
            content_raw=_bytes(inputs["content_json"]),
            registry=inputs["registry"],
            limits=dict(_object(_mapping(chosen.limits))),
            policy={
                "policy_ref": dict(chosen.policy_ref.to_mapping()),
                "required_claim_ids": declared["required_claim_ids"],
                "required_purposes": ["evidence"],
            },
            trust=wire,
        )
        captured = capfd.readouterr()
        document = _object(json.loads(captured.out))
        actual = _object(_array(document["reasons"])[0])
        assert captured.out.encode() == _transport({"operation": "verify", "reasons": [actual]})
        assert not captured.err and not report.exists()
        assert status == (3 if chosen.missing is not None else 2)
    else:
        with pytest.raises(
            ReferenceUnavailable if chosen.missing is not None else InputRefused
        ) as caught:
            verify(
                _bytes(inputs["content_json"]),
                schema_id=_text(inputs["schema_id"]),
                envelopes=(),
                registry=_registry(inputs["registry"]),
                resolver=resolver,
                limits=chosen.limits,
                policy=VerificationPolicy(
                    chosen.policy_ref,
                    tuple(_text(x) for x in _array(declared["required_claim_ids"])),
                    ("evidence",),
                ),
                trust=chosen.caller,
            )
        actual = asdict(caught.value.reason)
    if chosen.missing is not None:
        if not cli:
            assert (
                isinstance(caught.value, ReferenceUnavailable)
                and caught.value.reference == chosen.missing
            )
        expected = {
            "code": "reference_unavailable",
            "subject_digest": None,
            "claim_id": None,
            "pointer": None,
            "detail": "Required reference unavailable.",
        }
    elif (
        chosen.expected_subject is not None
        or chosen.expected_pointer
        or chosen.expected_code != "policy_unavailable"
    ):
        expected = {
            "code": chosen.expected_code,
            "subject_digest": chosen.expected_subject,
            "claim_id": None,
            "pointer": chosen.expected_pointer,
            "detail": chosen.expected_detail,
        }
    else:
        expected = {
            "code": "policy_unavailable",
            "subject_digest": chosen.policy_ref.digest,
            "claim_id": None,
            "pointer": "/required_evaluation_time_qualification/clock_qualification_ref",
            "detail": "The required evaluation-time qualification is unavailable.",
        }
        if not cli:
            acquired = tuple(reference for reference, _ in resolver.calls)
            assert all(reference in acquired for reference in chosen.required_sources)
    assert actual == expected
    if not cli and chosen.forbidden_grant is not None:
        assert all(reference != chosen.forbidden_grant for reference, _ in resolver.calls)
    assert all(path.read_bytes() == raw for path, raw in originals.items())
    assert all(path.read_bytes() == raw for path, raw in chosen.original_bytes.items())
