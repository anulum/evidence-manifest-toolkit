# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — explicit offline command transport

"""Run actual offline diagnostics and preserve complete result/error byte transport."""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Never

from ._cli_operations import seal_command, self_bound_command, verify_command
from ._difference import diff
from ._errors import ConfigurationError, EmtError, InputRefused
from ._file_io import read_file, read_limits
from ._inspection import inspect
from ._publication import publish_report
from ._serialization import error_bytes, report_bytes
from ._values import Reason


class _Arguments(argparse.Namespace):
    """Keep typed original diagnostic command options after invocation parsing.

    Attributes
    ----------
    command : str or None
        Actual selected original command; unknown invocations never become an operation.
    limits, report, content, left, right : Path or None
        Original explicit caller paths, absent only for inapplicable command options.
    left_signature, right_signature : list of Path
        Original ordered detached-envelope inputs, without discovery in an object store.
    schema_id : str
        Explicit independently selected schema for seal and verify.
    registry, objects, output, policy, trust, signing_request, signer_config : Path or None
        Complete applicable caller configurations, read-only store and fresh destination.
    declaration, request : Path or None
        The self-bound launch's declaration and its fresh request directory.
    signature : list of Path
        All original verify receipts, retaining explicit caller order.
    """

    def __init__(self) -> None:
        """Initialize only inapplicable optional paths and the documented empty receipt lists."""
        self.command: str | None = None
        self.limits: Path | None = None
        self.report: Path | None = None
        self.content: Path | None = None
        self.left: Path | None = None
        self.right: Path | None = None
        self.left_signature: list[Path] = []
        self.right_signature: list[Path] = []
        self.schema_id: str = ""
        self.registry: Path | None = None
        self.objects: Path | None = None
        self.output: Path | None = None
        self.policy: Path | None = None
        self.trust: Path | None = None
        self.signing_request: Path | None = None
        self.signer_config: Path | None = None
        self.signature: list[Path] = []
        self.declaration: Path | None = None
        self.request: Path | None = None


class _Parser(argparse.ArgumentParser):
    """Refuse invalid invocations using fixed authored JSON instead of argparse input echoes."""

    def error(self, message: str) -> Never:
        """Refuse invocation failures without exposing the parser's argument or path text.

        Parameters
        ----------
        message : str
            Parser diagnostic deliberately excluded from caller output.

        Raises
        ------
        ConfigurationError
            Invocation failed before any file acquisition or report publication.
        """
        raise ConfigurationError(
            Reason("configuration_error", None, None, None, "Invalid command invocation.")
        )


def _parser() -> _Parser:
    """Construct the five-command grammar with explicit complete caller selections.

    Returns
    -------
    _Parser
        Required explicit paths, exact repeated receipt flags and no argument abbreviation.
    """
    parser = _Parser(prog="emt", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    sealing = commands.add_parser("seal", allow_abbrev=False)
    sealing.add_argument("--output", type=Path, required=True, metavar="NEW_DIR")
    sealing.add_argument("--signing-request", type=Path, metavar="FILE")
    sealing.add_argument("--signer-config", type=Path, metavar="FILE")
    sealing.add_argument("--trust", type=Path, metavar="FILE")
    verification = commands.add_parser("verify", allow_abbrev=False)
    verification.add_argument("--policy", type=Path, required=True, metavar="FILE")
    verification.add_argument("--trust", type=Path, required=True, metavar="FILE")
    verification.add_argument("--signature", type=Path, action="append", default=[], metavar="FILE")
    self_bound = commands.add_parser("verify-self-bound", allow_abbrev=False)
    self_bound.add_argument("--declaration", type=Path, required=True, metavar="FILE")
    self_bound.add_argument("--request", type=Path, required=True, metavar="NEW_DIR")
    for command in (sealing, verification, self_bound):
        command.add_argument("--content", type=Path, required=True, metavar="FILE")
        command.add_argument("--schema-id", required=True, metavar="ID")
        command.add_argument("--registry", type=Path, required=True, metavar="FILE")
        command.add_argument("--objects", type=Path, required=True, metavar="DIR")
    inspection = commands.add_parser("inspect", allow_abbrev=False)
    inspection.add_argument("--content", type=Path, required=True, metavar="FILE")
    difference = commands.add_parser("diff", allow_abbrev=False)
    difference.add_argument("--left", type=Path, required=True, metavar="FILE")
    difference.add_argument("--right", type=Path, required=True, metavar="FILE")
    difference.add_argument(
        "--left-signature", type=Path, action="append", default=[], metavar="FILE"
    )
    difference.add_argument(
        "--right-signature", type=Path, action="append", default=[], metavar="FILE"
    )
    for command in (inspection, difference, sealing, verification, self_bound):
        command.add_argument("--limits", type=Path, required=True, metavar="FILE")
    for command in (inspection, difference, verification, self_bound):
        command.add_argument("--report", type=Path, required=True, metavar="NEW_FILE")
    return parser


def _path(value: Path | None) -> Path:
    """Require a parser-selected applicable original file path.

    Parameters
    ----------
    value : Path or None
        Actual parsed option, without a fabricated fallback path.

    Returns
    -------
    Path
        Original explicit applicable caller path.

    Raises
    ------
    ConfigurationError
        A required invocation option is absent.
    """
    if value is None:
        raise ConfigurationError(
            Reason("configuration_error", None, None, None, "Invalid command invocation.")
        )
    return value


def _execute(arguments: _Arguments) -> tuple[bytes, int]:
    """Call the genuine operation and exclusively publish its entire canonical result.

    Parameters
    ----------
    arguments : _Arguments
        Complete successfully parsed explicit command options.

    Returns
    -------
    tuple of bytes and int
        Entire canonical stdout and original common-mode exit status after exclusive publication.

    Raises
    ------
    EmtError
        Configuration, source acquisition, parsing or exclusive publication fails.
    """
    signing_options = (arguments.signing_request, arguments.signer_config, arguments.trust)
    if (
        arguments.command == "seal"
        and any(path is not None for path in signing_options)
        and not all(path is not None for path in signing_options)
    ):
        raise ConfigurationError(
            Reason("configuration_error", None, None, None, "Invalid command invocation.")
        )
    if arguments.command == "verify-self-bound":
        return self_bound_command(
            declaration=_path(arguments.declaration),
            content=_path(arguments.content),
            schema_id=arguments.schema_id,
            registry=_path(arguments.registry),
            objects=_path(arguments.objects),
            limits=_path(arguments.limits),
            request=_path(arguments.request),
            report=_path(arguments.report),
        )
    limits = read_limits(_path(arguments.limits))
    if arguments.command == "seal":
        return seal_command(
            content=_path(arguments.content),
            schema_id=arguments.schema_id,
            registry=_path(arguments.registry),
            objects=_path(arguments.objects),
            limits=limits,
            output=_path(arguments.output),
            signing_request=arguments.signing_request,
            signer_config=arguments.signer_config,
            trust=arguments.trust,
        ), 0
    if arguments.command == "verify":
        return verify_command(
            content=_path(arguments.content),
            schema_id=arguments.schema_id,
            registry=_path(arguments.registry),
            objects=_path(arguments.objects),
            limits=limits,
            policy=_path(arguments.policy),
            trust=_path(arguments.trust),
            signatures=arguments.signature,
            report=_path(arguments.report),
        )
    if arguments.command == "inspect":
        result = inspect(
            read_file(_path(arguments.content), max_bytes=limits.max_json_bytes), limits=limits
        )
        output = report_bytes(result)
    else:
        left = read_file(_path(arguments.left), max_bytes=limits.max_json_bytes)
        right = read_file(_path(arguments.right), max_bytes=limits.max_json_bytes)
        left_envelopes = tuple(
            read_file(path, max_bytes=limits.max_json_bytes) for path in arguments.left_signature
        )
        right_envelopes = tuple(
            read_file(path, max_bytes=limits.max_json_bytes) for path in arguments.right_signature
        )
        difference = diff(
            left,
            right,
            limits=limits,
            left_envelopes=left_envelopes,
            right_envelopes=right_envelopes,
        )
        output = report_bytes(difference)
    publish_report(_path(arguments.report), output)
    return output, 0


def _stdout(data: bytes) -> None:
    """Write exact caller bytes without a buffered newline or interpreter diagnostic.

    Parameters
    ----------
    data : bytes
        Complete selected diagnostic or deliberately authored error transport.

    Raises
    ------
    OSError
        The caller's actual stdout descriptor cannot accept the full result.
    """
    remaining = memoryview(data)
    while remaining:
        remaining = remaining[os.write(sys.stdout.fileno(), remaining) :]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the current offline command implementation through real process entrypoints.

    Parameters
    ----------
    argv : Sequence of str or None
        Explicit command arguments, or the actual process arguments when absent.

    Returns
    -------
    int
        Zero for completed diagnostics, two for input refusal, three for required I/O,
        and four for invocation/configuration/implementation failure. Exceptions never
        manufacture successful output or an eligible result.
    """
    supplied = list(sys.argv[1:] if argv is None else argv)
    operation = (
        supplied[0]
        if supplied and supplied[0] in {"seal", "verify", "verify-self-bound", "inspect", "diff"}
        else "emt"
    )
    try:
        arguments = _Arguments()
        _parser().parse_args(supplied, namespace=arguments)
        output, status = _execute(arguments)
    except SystemExit as exit_request:
        return int(exit_request.code or 0)
    except EmtError as error:
        output = error_bytes(operation, (error.reason,))
        status = (
            4
            if isinstance(error, ConfigurationError)
            else 2
            if isinstance(error, InputRefused)
            else 3
        )
    except Exception:
        output = error_bytes(
            operation,
            (
                Reason(
                    "configuration_error",
                    None,
                    None,
                    None,
                    "Local operation implementation is unavailable.",
                ),
            ),
        )
        status = 4
    try:
        _stdout(output)
    except OSError:
        return 3
    return status
