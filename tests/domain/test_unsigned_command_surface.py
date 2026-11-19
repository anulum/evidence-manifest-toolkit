# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the unsigned V2 caller at the four commands

"""Hold the unsigned V2 trust at the command line: the report, each refusal, the other commands.

Each case starts from one complete unsigned V2 verification that the whole-workflow fixture builds
(``cli_sig_exception``) and runs the real ``emt`` command in this process on real files; nothing in
the product is replaced. Each case gets its own fixture, because the first verification of an
entry binding uses it up: a second verification in the same fixture is refused. Exit codes and the
complete output bytes are asserted.
"""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from tests.domain.signature_rule_cli import prepare_rule_cli, run_module_command
from tests.domain.test_cli_evidence_sources import _transport
from tests.domain.test_clock_subject_sources import assert_whole_clock_source_workflow
from tests.domain.unsigned_command_inputs import UnsignedCommandInputs

_SIGNER_SOURCE = Path(__file__).parent / "fixtures/cli-signer-empty-installation-source.json"
_PATH_FLAGS = frozenset(
    {
        "--content",
        "--registry",
        "--objects",
        "--limits",
        "--output",
        "--signing-request",
        "--signer-config",
        "--trust",
    }
)
# The complete inspect and diff outputs for the case's content, measured at toolkit c6e443e, the
# base of this change; this change touches no product source.
_INSPECT_SHA256 = "451f22809f5021733ab78edc1db6a2804655bc33aed6b0aa7abed05425b4b561"
_INSPECT_LENGTH = 3576
_DIFF_SHA256 = "c63aebed2111f5b1c1e5041b5a5a9c63b1fa5acbee9f59a992cdbb141d788522"
_DIFF_LENGTH = 498


def _error(operation: str, pointer: str | None, detail: str, subject: str | None) -> bytes:
    """Return the whole error transport of one configuration refusal."""
    return _transport(
        {
            "operation": operation,
            "reasons": [
                {
                    "claim_id": None,
                    "code": "configuration_error",
                    "detail": detail,
                    "pointer": pointer,
                    "subject_digest": subject,
                }
            ],
        }
    )


def _verify(
    case: UnsignedCommandInputs,
    *,
    trust: dict[str, object] | None = None,
    envelopes: tuple[bytes, ...] = (),
    population: dict[str, Path] | None = None,
    report_parent_mode: int | None = None,
) -> tuple[int, bytes, bytes, Path]:
    """Run ``emt verify`` once on the case's whole inputs with the selected changes.

    Parameters
    ----------
    case : UnsignedCommandInputs
        The complete unsigned verification.
    trust : dict or None
        Replacement caller trust in wire form; the case's own trust when None.
    envelopes : tuple of bytes
        Bytes supplied through ``--signature``, one file each.
    population : dict or None
        Replacement object-store population; the case's own when None.
    report_parent_mode : int or None
        When set, the report is requested inside a fresh directory with this mode.

    Returns
    -------
    tuple
        Exit code, stdout bytes, stderr bytes and the requested report path.
    """
    arguments, report = prepare_rule_cli(
        case.directory,
        population=case.population if population is None else population,
        schema_id=case.schema_id,
        content_raw=case.content_raw,
        registry=case.registry,
        limits=case.limits,
        policy=case.policy,
        trust=case.trust if trust is None else trust,
        envelopes=envelopes,
    )
    if report_parent_mode is not None:
        parent = report.parent / "report-parent"
        parent.mkdir()
        report = parent / "report.json"
        arguments[arguments.index("--report") + 1] = str(report)
        parent.chmod(report_parent_mode)
    case.capfd.readouterr()
    try:
        code = run_module_command(arguments)
    finally:
        if report_parent_mode is not None:
            report.parent.chmod(0o700)
    captured = case.capfd.readouterr()
    return code, captured.out.encode(), captured.err.encode(), report


def _refused_at(case: UnsignedCommandInputs, trust: dict[str, object], pointer: str) -> None:
    """Assert one malformed trust is refused at its pointer with exit 4 and no report."""
    code, out, err, report = _verify(case, trust=trust)
    assert (code, out, err) == (
        4,
        _error("verify", pointer, "Invalid local configuration.", None),
        b"",
    )
    assert not report.exists()


def _report(case: UnsignedCommandInputs) -> None:
    """C1: the composed report is published, equal on stdout and in the file, and exits 2."""
    code, out, err, report = _verify(case)
    published = json.loads(out)
    assert (code, err) == (2, b"")
    assert report.read_bytes() == out
    assert {name: published[name] for name in case.axes} == dict(case.axes)
    assert published["reasons"] == case.reasons
    assert published["content_ref"] == dict(case.content_ref.to_mapping())
    assert published["policy_ref"] == dict(case.policy_ref.to_mapping())


def _historical(case: UnsignedCommandInputs) -> None:
    """C2: historical mode is refused at the evaluation-time qualification, exit 2, no report.

    The entry binding observes this invocation's own time, so it cannot qualify an earlier
    evaluation time; the refusal stands even once a Clock verdict can be accepted.
    """
    code, out, err, report = _verify(case, trust={**case.trust, "evaluation_mode": "historical"})
    assert (code, err) == (2, b"")
    assert out == _transport(
        {
            "operation": "verify",
            "reasons": [
                {
                    "claim_id": None,
                    "code": "policy_unavailable",
                    "detail": "The required evaluation-time qualification is unavailable.",
                    "pointer": "/required_evaluation_time_qualification/clock_qualification_ref",
                    "subject_digest": case.policy_ref.digest,
                }
            ],
        }
    )
    assert not report.exists()


def _signature(case: UnsignedCommandInputs) -> None:
    """C3: one ``--signature`` is refused at ``/envelopes`` with exit 4 and no report."""
    code, out, err, report = _verify(case, envelopes=(b"{}",))
    assert (code, out, err) == (
        4,
        _error(
            "verify",
            "/envelopes",
            "Invalid local trust or policy configuration.",
            case.policy_ref.digest,
        ),
        b"",
    )
    assert not report.exists()


def _policy_only(case: UnsignedCommandInputs) -> dict[str, Path]:
    """Return the case's store reduced to the selected policy object."""
    prefix = case.policy_ref.digest + "|"
    return {key: path for key, path in case.population.items() if key.startswith(prefix)}


def _signature_before_sources(case: UnsignedCommandInputs) -> None:
    """C3, observed early: with only the policy in the store, the signature refusal is unchanged."""
    code, out, err, _ = _verify(case, envelopes=(b"{}",), population=_policy_only(case))
    assert (code, out, err) == (
        4,
        _error(
            "verify",
            "/envelopes",
            "Invalid local trust or policy configuration.",
            case.policy_ref.digest,
        ),
        b"",
    )


def _no_signature_needs_sources(case: UnsignedCommandInputs) -> None:
    """C3's contrast: without a signature, the same reduced store fails acquisition with exit 3."""
    code, out, err, report = _verify(case, population=_policy_only(case))
    assert (code, err) == (3, b"")
    assert out == _transport(
        {
            "operation": "verify",
            "reasons": [
                {
                    "claim_id": None,
                    "code": "reference_unavailable",
                    "detail": "Required reference unavailable.",
                    "pointer": None,
                    "subject_digest": None,
                }
            ],
        }
    )
    assert not report.exists()


def _namespace(case: UnsignedCommandInputs) -> None:
    """C4: an unknown namespace is refused at ``/trust/namespace``."""
    _refused_at(case, {**case.trust, "namespace": "EMT_CALLER_TRUST_OTHER_V2"}, "/trust/namespace")


def _missing_field(case: UnsignedCommandInputs) -> None:
    """C5: a missing field is refused at ``/trust``."""
    trust = dict(case.trust)
    del trust["evaluation_time"]
    _refused_at(case, trust, "/trust")


def _extra_field(case: UnsignedCommandInputs) -> None:
    """C5: an extra field is refused at ``/trust``."""
    _refused_at(case, {**case.trust, "extra": "x"}, "/trust")


def _mode(case: UnsignedCommandInputs) -> None:
    """C6: an unknown evaluation mode is refused at ``/trust/evaluation_mode``."""
    _refused_at(case, {**case.trust, "evaluation_mode": "future"}, "/trust/evaluation_mode")


def _time(case: UnsignedCommandInputs) -> None:
    """C7: an evaluation time with a UTC offset is refused at ``/trust/evaluation_time``."""
    trust = {**case.trust, "evaluation_time": "2026-11-19T12:00:00+01:00"}
    _refused_at(case, trust, "/trust/evaluation_time")


def _binding(case: UnsignedCommandInputs) -> None:
    """C8: a malformed entry-binding member is refused at its own pointer."""
    binding = case.trust["clock_entry_binding"]
    assert isinstance(binding, dict) and "boot_domain_ref" in binding
    trust = {**case.trust, "clock_entry_binding": {**binding, "boot_domain_ref": 5}}
    _refused_at(case, trust, "/trust/clock_entry_binding/boot_domain_ref")


def _profile_class(case: UnsignedCommandInputs) -> None:
    """C9: another profile class under the unsigned namespace is refused at its pointer."""
    trust = {**case.trust, "profile_class": "software_local_unprotected"}
    _refused_at(case, trust, "/trust/profile_class")


def _seal(case: UnsignedCommandInputs, *, triple: bool) -> tuple[int, bytes, bytes, Path]:
    """Run ``emt seal`` with the signer fixture's files and the case's unsigned trust.

    Parameters
    ----------
    case : UnsignedCommandInputs
        Supplies the unsigned V2 trust that replaces the fixture's trust file.
    triple : bool
        True for the whole signing triple; False for ``--trust`` alone.

    Returns
    -------
    tuple
        Exit code, stdout bytes, stderr bytes and the output parent directory.
    """
    source = json.loads(_SIGNER_SOURCE.read_bytes())
    directory = case.directory / "seal-inputs"
    for relative, token in source["exact_original_files_hex"].items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes.fromhex(token))
    (directory / "configs/trust.json").write_bytes(_transport(case.trust))
    (directory / "out").mkdir()
    arguments = ["emt", *source["argv"]]
    for index, token in enumerate(arguments[:-1]):
        if token in _PATH_FLAGS:
            arguments[index + 1] = str(directory / arguments[index + 1])
    if not triple:
        for flag in ("--signing-request", "--signer-config"):
            at = arguments.index(flag)
            del arguments[at : at + 2]
    case.capfd.readouterr()
    code = run_module_command(arguments)
    captured = case.capfd.readouterr()
    return code, captured.out.encode(), captured.err.encode(), directory / "out"


def _seal_with_triple(case: UnsignedCommandInputs) -> None:
    """C11: an unsigned trust cannot sign; ``/trust`` is refused and no output is created."""
    code, out, err, parent = _seal(case, triple=True)
    assert (code, out, err) == (
        4,
        _error("seal", "/trust", "Invalid local configuration.", None),
        b"",
    )
    assert not list(parent.iterdir())


def _seal_with_trust_alone(case: UnsignedCommandInputs) -> None:
    """C12: ``--trust`` without the rest of the triple is an invalid invocation."""
    code, out, err, parent = _seal(case, triple=False)
    assert (code, out, err) == (4, _error("seal", None, "Invalid command invocation.", None), b"")
    assert not list(parent.iterdir())


def _diagnostic(case: UnsignedCommandInputs, command: list[str]) -> bytes:
    """Run ``inspect`` or ``diff`` on the case's content; assert exit 0 and the report file."""
    directory = case.directory / "diagnostic-inputs"
    directory.mkdir()
    content = directory / "content.json"
    content.write_bytes(case.content_raw)
    limits = directory / "limits.json"
    limits.write_bytes(_transport(case.limits))
    report = directory / "report.json"
    arguments = [
        "emt",
        *(str(content) if token == "CONTENT" else token for token in command),
        "--limits",
        str(limits),
        "--report",
        str(report),
    ]
    case.capfd.readouterr()
    code = run_module_command(arguments)
    captured = case.capfd.readouterr()
    assert (code, captured.err) == (0, "")
    assert report.read_bytes() == captured.out.encode()
    return captured.out.encode()


def _inspect(case: UnsignedCommandInputs) -> None:
    """C13: ``inspect`` on the unsigned case's content gives the base's output."""
    out = _diagnostic(case, ["inspect", "--content", "CONTENT"])
    assert (hashlib.sha256(out).hexdigest(), len(out)) == (_INSPECT_SHA256, _INSPECT_LENGTH)


def _diff(case: UnsignedCommandInputs) -> None:
    """C14: ``diff`` of the content with itself gives the base's output."""
    out = _diagnostic(case, ["diff", "--left", "CONTENT", "--right", "CONTENT"])
    assert (hashlib.sha256(out).hexdigest(), len(out)) == (_DIFF_SHA256, _DIFF_LENGTH)


def _unwritable_report(case: UnsignedCommandInputs) -> None:
    """C15: a report directory that cannot be written gives a storage error and no file."""
    code, out, err, report = _verify(case, report_parent_mode=0o500)
    assert (code, err) == (3, b"")
    assert out == _transport(
        {
            "operation": "verify",
            "reasons": [
                {
                    "claim_id": None,
                    "code": "storage_error",
                    "detail": "Output could not be stored.",
                    "pointer": None,
                    "subject_digest": None,
                }
            ],
        }
    )
    assert not list(report.parent.iterdir())


_CASES: dict[str, Callable[[UnsignedCommandInputs], None]] = {
    "c01_report": _report,
    "c02_historical": _historical,
    "c03_signature": _signature,
    "c03_signature_before_sources": _signature_before_sources,
    "c03_no_signature_needs_sources": _no_signature_needs_sources,
    "c04_namespace": _namespace,
    "c05_missing_field": _missing_field,
    "c05_extra_field": _extra_field,
    "c06_mode": _mode,
    "c07_time": _time,
    "c08_binding": _binding,
    "c09_profile_class": _profile_class,
    "c11_seal_with_triple": _seal_with_triple,
    "c12_seal_with_trust_alone": _seal_with_trust_alone,
    "c13_inspect": _inspect,
    "c14_diff": _diff,
    "c15_unwritable_report": _unwritable_report,
}


@pytest.mark.parametrize("case", sorted(_CASES))
def test_unsigned_v2_caller_at_the_command_line(
    case: str, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """Run one command case on a fresh complete unsigned V2 verification.

    Parameters
    ----------
    case : str
        The case of the unsigned command surface, numbered as in the item's card.
    tmp_path : Path
        Owned fixture directory for this case alone.
    capfd : pytest.CaptureFixture
        Actual stdout/stderr capture of the same process.
    """
    assert_whole_clock_source_workflow(
        "cli_sig_exception", tmp_path, capfd, command_check=_CASES[case]
    )
