# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance


"""Reviewed workflow inventory constants for local repository validation."""

from typing import Final, TypedDict


class WorkflowSpec(TypedDict):
    """The exact trigger and job inventory for one reviewed analysis workflow."""

    triggers: list[str]
    jobs: list[str]


class JobSpec(TypedDict, total=False):
    """One owned job and its fixed command or same-revision reusable call."""

    owner: str
    category: int
    needs: list[str]
    command: str
    uses: str


class StepSource(TypedDict):
    """Explicit algorithm and digest for one complete parsed step sequence."""

    sha256: str


class WorkflowPolicy(TypedDict):
    """Closed build-time workflow parameters; input cannot weaken safety policy."""

    schema_revision: str
    workflows: dict[str, WorkflowSpec]
    jobs: dict[str, JobSpec]
    actions: dict[str, str]
    python_version: str
    job_timeout_minutes: int
    workflow_max_bytes: int
    workflow_max_lines: int
    permissions: dict[str, str]
    concurrency_group: str
    cancel_in_progress: bool
    platform: str
    step_inputs_sha256: dict[str, StepSource]
    workflow_inputs_sha256: dict[str, StepSource]


WORKFLOW_POLICY: Final[WorkflowPolicy] = {
    "workflow_inputs_sha256": {
        "ci.yml": {"sha256": "64445a0ef5fe296928ae6f30370aaf2626703dfe06bc2d8c8f8f17500b45baaa"},
        "codeql.yml": {
            "sha256": "b2362efac2b35c8fc8257108b60970237e12b9a7c827433e94e3268ecfd4cb89"
        },
        "docs.yml": {"sha256": "303bb0e5fd0fbc7e4d4774c4d12a37b2ad8f367b74ec4e29d2dbec56a8fe235b"},
        "pre-commit.yml": {
            "sha256": "8365069582d289a9be22d8cdf3fea0b5821a64aabeb394fc93e2e78dbf9fd5ac"
        },
        "sbom.yml": {"sha256": "9b701faa7bf00c526ab1a8c153af5d986acd3afb81308610f31b2d790a2fbb3f"},
        "scorecard.yml": {
            "sha256": "53e4ae8f558338d32437287edbf6a9ee20c49b6554e1c6bf870f10d41a2501b8"
        },
        "security-audit.yml": {
            "sha256": "96067e119d27255c33241574d3df40958a39cf25c69c2c70f380b48ba566eb70"
        },
    },
    "platform": "github.com",
    "step_inputs_sha256": {
        "ci.yml/complete": {
            "sha256": "27a8d67d28e7c37496270963292e378b2f9afa3bafdf3f98948e101a0851c1aa"
        },
        "codeql.yml/analysis": {
            "sha256": "5a952105403e67e8098cad4af05a99517e5eacab9a5c5784d60656dacba84fad"
        },
        "docs.yml/render": {
            "sha256": "c8682675b183eae2b0bf26949ee6bbcacfcbaadcf56487f59853db0fb7fdbe34"
        },
        "pre-commit.yml/quality": {
            "sha256": "e176f493f00dd17432220c750d94920b24f4e99e2862e6b0b1c2d52682e36d8d"
        },
        "pre-commit.yml/tests": {
            "sha256": "82084c228041aa8854a7c97ce3699fabdd50b3072bd49f1410c3ccf09c5fef2e"
        },
        "sbom.yml/inventory": {
            "sha256": "ae638eab92e33a12f46b694029c6e3aa6d4d4e6bb8b7c8b0b95965e88c67a9d3"
        },
        "scorecard.yml/configuration": {
            "sha256": "374b74e8689289a2272f469f0b0a4852e54b9db4618efbb199351b9619a3ff4a"
        },
        "security-audit.yml/dependency": {
            "sha256": "c06a5231cbd6a38cb4d0868cdaefd23963c9b20e7aa25e40ddd962299dc3bb47"
        },
        "security-audit.yml/secrets": {
            "sha256": "8fb0a9025c09a506a1b3ccedf86bb1076b5fea0711b09518978e1edcff80fac1"
        },
        "security-audit.yml/static": {
            "sha256": "94c6097477fe89193eafc04538cbd27964435b275841fa370a61d453c843258e"
        },
        "security-audit.yml/workflow": {
            "sha256": "4c0e7312e3880afe37fd0bd30559bfb0a8bc54d573584275283edabfc9a07b21"
        },
    },
    "schema_revision": "emt.local-workflow-policy.v1",
    "workflows": {
        "pre-commit.yml": {
            "triggers": ["workflow_call", "workflow_dispatch"],
            "jobs": ["quality", "tests"],
        },
        "docs.yml": {"triggers": ["workflow_call", "workflow_dispatch"], "jobs": ["render"]},
        "codeql.yml": {"triggers": ["workflow_call", "workflow_dispatch"], "jobs": ["analysis"]},
        "security-audit.yml": {
            "triggers": ["workflow_call", "workflow_dispatch"],
            "jobs": ["dependency", "static", "secrets", "workflow"],
        },
        "sbom.yml": {"triggers": ["workflow_call", "workflow_dispatch"], "jobs": ["inventory"]},
        "scorecard.yml": {
            "triggers": ["workflow_call", "workflow_dispatch"],
            "jobs": ["configuration"],
        },
        "ci.yml": {
            "triggers": ["push", "pull_request", "workflow_dispatch"],
            "jobs": [
                "pre-commit",
                "docs",
                "codeql",
                "security-audit",
                "sbom",
                "scorecard",
                "complete",
            ],
        },
    },
    "jobs": {
        "pre-commit.yml/quality": {
            "owner": "local-validation-maintainer",
            "category": 2,
            "needs": [],
            "command": "make quality",
        },
        "pre-commit.yml/tests": {
            "owner": "local-validation-maintainer",
            "category": 4,
            "needs": [],
            "command": "make test",
        },
        "docs.yml/render": {
            "owner": "local-validation-maintainer",
            "category": 9,
            "needs": [],
            "command": "make docs",
        },
        "codeql.yml/analysis": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make source-analysis",
        },
        "security-audit.yml/dependency": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make dependency-security",
        },
        "security-audit.yml/static": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make static-security",
        },
        "security-audit.yml/secrets": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make secret-scan",
        },
        "security-audit.yml/workflow": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make workflow-security",
        },
        "sbom.yml/inventory": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make sbom",
        },
        "scorecard.yml/configuration": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make supply-chain",
        },
        "ci.yml/pre-commit": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/pre-commit.yml",
        },
        "ci.yml/docs": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/docs.yml",
        },
        "ci.yml/codeql": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/codeql.yml",
        },
        "ci.yml/security-audit": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/security-audit.yml",
        },
        "ci.yml/sbom": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/sbom.yml",
        },
        "ci.yml/scorecard": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/scorecard.yml",
        },
        "ci.yml/complete": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": ["pre-commit", "docs", "codeql", "security-audit", "sbom", "scorecard"],
            "command": "aggregate_all_six",
        },
    },
    "actions": {
        "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "github/codeql-action/init": "2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
        "github/codeql-action/analyze": "2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
    },
    "python_version": "3.13.18",
    "job_timeout_minutes": 20,
    "workflow_max_bytes": 102400,
    "workflow_max_lines": 1000,
    "permissions": {},
    "concurrency_group": "${{ github.workflow }}-${{ github.ref }}",
    "cancel_in_progress": True,
}
