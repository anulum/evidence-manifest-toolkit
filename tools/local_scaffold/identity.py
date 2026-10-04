# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance


"""Reviewed identity constants for local repository validation."""

from typing import Final

REPOSITORY: Final = "EVIDENCE-MANIFEST-TOOLKIT"


GROUP: Final = "SC-NEUROMORPHIC-COMPUTING-SYSTEMS"


PROFILE: Final = {
    "id": "gotm.enterprise-repository-tier0.local-scaffold",
    "revision": "2026-10-04",
    "standard_sha256": "8421674a61444474447fad2f4d2bfc54dc5a1ea12ae988785e57dbcab385938c",
    "profile_sha256": "f453a70eae008c41f8d26a1f495ec3636f64739bcedb9caac0bdf8774300905c",
}


SPDX_PREFIX: Final = "SPDX-License-Identifier" + ":"


HEADER: Final = [
    SPDX_PREFIX + " AGPL-3.0-or-later",
    "Commercial license available",
    "© Concepts 1996–2026 Miroslav Šotek. All rights reserved.",
    "© Code 2020–2026 Miroslav Šotek. All rights reserved.",
    "ORCID: 0009-0009-3560-0851",
    "Contact: www.anulum.li | protoscience@anulum.li",
    "EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance",
]


REQUIRED: Final = [
    (".editorconfig", "file"),
    (".gitattributes", "file"),
    (".github/CODEOWNERS", "file"),
    (".github/FUNDING.yml", "file"),
    (".github/ISSUE_TEMPLATE/bug_report.yml", "file"),
    (".github/ISSUE_TEMPLATE/config.yml", "file"),
    (".github/ISSUE_TEMPLATE/feature_request.yml", "file"),
    (".github/dependabot.yml", "file"),
    (".github/pull_request_template.md", "file"),
    (".github/workflows/ci.yml", "file"),
    (".github/workflows/codeql.yml", "file"),
    (".github/workflows/docs.yml", "file"),
    (".github/workflows/pre-commit.yml", "file"),
    (".github/workflows/sbom.yml", "file"),
    (".github/workflows/scorecard.yml", "file"),
    (".github/workflows/security-audit.yml", "file"),
    (".gitignore", "file"),
    (".pre-commit-config.yaml", "file"),
    (".zenodo.json", "file"),
    ("ARCHITECTURE.md", "file"),
    ("CHANGELOG.md", "file"),
    ("CITATION.cff", "file"),
    ("CODE_OF_CONDUCT.md", "file"),
    ("CONTRIBUTING.md", "file"),
    ("CONTRIBUTORS.md", "file"),
    ("GOVERNANCE.md", "file"),
    ("LICENSE", "file"),
    ("LICENSES", "directory"),
    ("Makefile", "file"),
    ("NOTICE.md", "file"),
    ("README.md", "file"),
    ("REUSE.toml", "file"),
    ("ROADMAP.md", "file"),
    ("SECURITY.md", "file"),
    ("SUPPORT.md", "file"),
    ("VALIDATION.md", "file"),
    ("docs/ARCHITECTURE.md", "file"),
    ("docs/THREAT_MODEL.md", "file"),
    ("docs/adr/0001-repository-boundary.md", "file"),
    ("pyproject.toml", "file"),
    ("requirements-dev.txt", "file"),
    ("tests", "directory"),
    ("tools/preflight.py", "file"),
    ("repository-domain.json", "file"),
    ("schemas/repository-domain.schema.json", "file"),
    ("capability-inventory.json", "file"),
    ("mkdocs.yml", "file"),
    ("tools/check_repository_metadata.py", "file"),
    ("tools/check_source_provenance.py", "file"),
    ("tools/check_workflow_policy.py", "file"),
    ("tools/check_dependency_alignment.py", "file"),
    ("tools/check_documentation.py", "file"),
    ("tools/check_repository_inventory.py", "file"),
    ("docs/assets/anulum_logo_company.jpg", "file"),
    ("docs/assets/anulum_logo.png", "file"),
    ("docs/assets/fortis_studio_logo.jpg", "file"),
    ("repository-domain.json.license", "file"),
    ("schemas/repository-domain.schema.json.license", "file"),
    ("capability-inventory.json.license", "file"),
    (".zenodo.json.license", "file"),
    ("requirements-dev.in", "file"),
    ("dependency-provenance.json", "file"),
    ("dependency-provenance.json.license", "file"),
    ("docs/index.md", "file"),
    ("docs/validation-tooling.md", "file"),
    ("tests/test_repository_metadata.py", "file"),
    ("tests/test_source_provenance.py", "file"),
    ("tests/test_workflow_policy.py", "file"),
    ("tests/test_dependency_alignment.py", "file"),
    ("tests/test_documentation.py", "file"),
    ("tests/test_repository_inventory.py", "file"),
    ("tests/test_preflight.py", "file"),
    ("workflow-policy.json", "file"),
    ("workflow-policy.json.license", "file"),
]


FORBIDDEN: Final = [
    ".coordination",
    ".env",
    "04_ARCANE_SAPIENCE",
    "AGENTS.md",
    "BACKUP",
    "CLAUDE.md",
    "CODEX.md",
    "GEMINI.md",
    "GROK.md",
    "KIMI.md",
]


PLANNED: Final = [
    "evidence_manifest_toolkit.adapter_conformance.v1",
    "evidence_manifest_toolkit.group_certificate.v1",
    "evidence_manifest_toolkit.manifest.v1",
    "evidence_manifest_toolkit.registry_snapshot.v1",
    "evidence_manifest_toolkit.signed_statement.v1",
    "evidence_manifest_toolkit.studio_mapping.v1",
    "evidence_manifest_toolkit.target_descriptor.v1",
    "evidence_manifest_toolkit.trust_snapshot.v1",
]


FUNDING: Final = {
    "github": "anulum",
    "buy_me_a_coffee": "anulum",
    "custom": [
        "https://buy.stripe.com/4gM00kbiMdjAberaYz5J601",
        "https://www.paypal.com/donate?hosted_button_id=4X5F6DNT934HY",
        "https://go.twint.ch/1/e/tw?tw=acq.lJTAypb8SL2s8vPg7fL0ubi2C220ajOH0BEQn1aKfEJIiIakLpt8jlEv8XdQ9tCp.",
        "https://anulum.li/contact.html",
    ],
}
