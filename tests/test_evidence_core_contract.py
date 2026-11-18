# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — evidence core contract

"""Bind every value the evidence core contract page states to the source that implements it.

The page `docs/contracts/evidence-core-v1.md` states identifiers, digests, prefixes and patterns. Each test reads
the implementing source (a schema file, a module constant read from its syntax tree, or the repository's pinned
dependencies) and requires the page to state exactly that value. A change on either side without the other fails.
"""

import ast
import hashlib
import json
import re
from pathlib import Path

import pytest

from evidence_manifest_toolkit import InputRefused, Limits, canonicalize_json
from tests.conftest import SOURCE

PAGE = SOURCE / "docs" / "contracts" / "evidence-core-v1.md"
PACKAGE = SOURCE / "src" / "evidence_manifest_toolkit"
SCHEMAS = PACKAGE / "_schemas"


def page_text() -> str:
    """Return the contract page's text.

    Returns
    -------
    str
        The complete page as UTF-8 text.
    """
    return PAGE.read_text(encoding="utf-8")


def module_constant(module: Path, name: str) -> object:
    """Return the literal value assigned to a module-level name, read from the module's syntax tree.

    Parameters
    ----------
    module : Path
        The Python source file.
    name : str
        The module-level name assigned once to a literal.

    Returns
    -------
    object
        The literal value, or for a ``re.compile`` call the pattern string it compiles.

    Raises
    ------
    AssertionError
        The name is not assigned exactly once at module level.
    """
    tree = ast.parse(module.read_text(encoding="utf-8"))
    values = [
        statement.value
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in statement.targets)
    ]
    assert len(values) == 1, f"{name} is not assigned exactly once in {module.name}"
    value = values[0]
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "compile"
    ):
        return ast.literal_eval(value.args[0])
    return ast.literal_eval(value)


def schema(name: str) -> dict[str, object]:
    """Return one packaged schema decoded from JSON.

    Parameters
    ----------
    name : str
        The schema file's stem under ``_schemas``.

    Returns
    -------
    dict[str, object]
        The decoded schema document.
    """
    decoded: dict[str, object] = json.loads((SCHEMAS / f"{name}.json").read_bytes())
    return decoded


@pytest.mark.parametrize("name", ["manifest", "signed_statement"])
def test_the_page_states_each_schema_file_digest_and_identifier(name: str) -> None:
    """The stated SHA-256 and ``$id`` of each schema equal the packaged file's."""
    text = page_text()
    digest = hashlib.sha256((SCHEMAS / f"{name}.json").read_bytes()).hexdigest()
    assert f"`{digest}`" in text
    assert f"`{schema(name)['$id']}`" in text
    assert f"`src/evidence_manifest_toolkit/_schemas/{name}.json`" in text


def test_the_canonical_profile_and_digest_algorithm_match_both_schemas() -> None:
    """Both schemas fix the profile and algorithm the page states."""
    text = page_text()
    manifest = schema("manifest")["properties"]
    statement = schema("signed_statement")["properties"]
    assert isinstance(manifest, dict) and isinstance(statement, dict)
    assert manifest["canonical_profile"] == {"const": "rfc8785-jcs-v1"}
    assert statement["canonical_profile"] == {"const": "rfc8785-jcs-v1"}
    assert statement["digest_algorithm"] == {"const": "sha256"}
    assert "`rfc8785-jcs-v1`" in text and "| Digest algorithm | `sha256` |" in text


def test_the_page_lists_the_manifest_required_members_in_order() -> None:
    """The page's required-member row equals the manifest schema's ``required`` list."""
    required = schema("manifest")["required"]
    assert isinstance(required, list)
    assert (
        "| Required members | " + ", ".join(f"`{member}`" for member in required) + " |"
        in page_text()
    )


def test_the_signature_profile_and_domain_prefixes_match_the_statement_module() -> None:
    """The profile identifier and both message prefixes equal the module's constants."""
    text = page_text()
    module = PACKAGE / "_statements.py"
    profile = module_constant(module, "PROFILE_ID")
    group = module_constant(module, "_GROUP_PREFIX")
    root = module_constant(module, "_ROOT_PREFIX")
    properties = schema("signed_statement")["properties"]
    assert isinstance(properties, dict)
    profile_rule = properties["profile_id"]
    assert isinstance(profile_rule, dict) and profile == profile_rule["const"]
    assert f"`{profile}`" in text
    for prefix in (group, root):
        assert isinstance(prefix, bytes) and prefix.endswith(b"\n")
        assert f"`{prefix[:-1].decode('ascii')}` and one line feed" in text


def test_the_digest_pattern_matches_the_codec() -> None:
    """The codec's digest pattern is ``sha256:`` and 64 lowercase hexadecimal digits, as the page states."""
    assert module_constant(PACKAGE / "_codecs.py", "DIGEST_PATTERN") == "sha256:[0-9a-f]{64}"
    assert "`sha256:` followed by 64 lowercase hexadecimal digits" in page_text()


def test_the_canonicaliser_pin_matches_the_repository_dependencies() -> None:
    """The page names the exact canonicaliser version the repository pins."""
    domain = json.loads((SOURCE / "repository-domain.json").read_bytes())
    pins = [pin for pin in domain["domain_runtime_dependencies"] if pin.startswith("rfc8785==")]
    assert pins == ["rfc8785==0.1.4+emt.1"]
    assert f"`{pins[0]}`" in page_text()


EXAMPLE_ROW = re.compile(
    r"^\| (E\d+) \| (.+?) \| `([0-9a-f]+)` \| (\d+) \| (\d+) \| `([a-z_]+)` \| [^|]+ \|$"
)


def admission_examples() -> list[tuple[str, str, bytes, int, int, str]]:
    """Return every row of the page's admission example table.

    Returns
    -------
    list of tuple
        The row label, document description, input bytes, size bound, depth bound and stated refusal code.
    """
    rows = []
    for line in page_text().splitlines():
        match = EXAMPLE_ROW.match(line)
        if match is not None:
            label, document, raw, size, depth, code = match.groups()
            rows.append((label, document, bytes.fromhex(raw), int(size), int(depth), code))
    return rows


def test_the_example_table_is_complete_and_describes_its_bytes() -> None:
    """The page lists nine examples, E1 to E9, and each document column matches its bytes."""
    rows = admission_examples()
    assert [row[0] for row in rows] == [f"E{index}" for index in range(1, 10)]
    for _, document, raw, _, _, _ in rows:
        shown = re.findall(r"`([^`]*)`", document)
        assert len(shown) == 1
        if document.startswith("byte "):
            assert raw.hex() == shown[0]
        elif document.startswith("BOM, then "):
            assert raw[:3] == b"\xef\xbb\xbf" and raw[3:].decode("utf-8") == shown[0]
        else:
            assert document == f"`{shown[0]}`" and raw.decode("utf-8") == shown[0]


@pytest.mark.parametrize("label", [f"E{index}" for index in range(1, 10)])
def test_each_admission_example_is_refused_with_the_stated_code(label: str) -> None:
    """``canonicalize_json`` refuses each example with the code the page states, so the stated order holds."""
    row = next(row for row in admission_examples() if row[0] == label)
    _, _, raw, size, depth, code = row
    limits = Limits(
        max_json_bytes=size,
        max_blob_bytes=1,
        max_total_reference_bytes=1,
        max_reference_count=1,
        max_graph_depth=1,
        max_json_depth=depth,
    )
    with pytest.raises(InputRefused) as refused:
        canonicalize_json(raw, limits=limits)
    assert refused.value.reason.code == code


def test_the_page_states_the_limit_field_order_of_the_source() -> None:
    """The order in which the page says the limits are checked is the source's own order."""
    fields = module_constant(PACKAGE / "_json.py", "_LIMIT_FIELDS")
    assert isinstance(fields, tuple)
    prose = " ".join(page_text().split())
    assert ", ".join(f"`{name}`" for name in fields) in prose


def test_the_page_states_its_non_claims() -> None:
    """The page says it is no capability claim, no freeze by itself and no runtime acceptance."""
    text = page_text()
    assert "is a specification, not a capability claim" in text
    assert "does not freeze the contract" in text
    assert "does not make the toolkit's runtime accepted" in text
