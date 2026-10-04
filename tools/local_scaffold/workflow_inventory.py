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
            "sha256": "34838cef9e09e55609e28660ceeaa90ba303fc128d90eefab0d9d745c9211187"
        },
        "docs.yml": {"sha256": "d10a00c9044e621b7e0afc611dcd3278aeed88d3eeb4622c37fe66a5abf6d8eb"},
        "pre-commit.yml": {
            "sha256": "d715a2f516df1392d197a1dc189d3373893e13b448e1774ec950c276c98eb8d7"
        },
        "sbom.yml": {"sha256": "4467b50b83b585ea4b05f5e4fb08a027adc08b5b6f4a4f4f8eb420274d848052"},
        "scorecard.yml": {
            "sha256": "75710dff695080cacaaa583b00302799ac365e3e7db094b4466a4ad4e998d86e"
        },
        "security-audit.yml": {
            "sha256": "dbaa82ead24e056a455734a75552d7f1ba4b82efad45f308ed53d367a83e9e72"
        },
    },
    "platform": "github.com",
    "step_inputs_sha256": {
        "ci.yml/complete": {
            "sha256": "27a8d67d28e7c37496270963292e378b2f9afa3bafdf3f98948e101a0851c1aa"
        },
        "codeql.yml/analysis": {
            "sha256": "93f42aeb65fe5168dcd68dfa34bd82fcf7f672bf50f9405bdbf3287429bc8ef4"
        },
        "docs.yml/render": {
            "sha256": "60ca514b4891b3c4df79375b79c3669f9ac86ca90870fdda1b6e439a98afc05c"
        },
        "pre-commit.yml/quality": {
            "sha256": "acca9bee5a2516cbfb969fbe99f2f44247bf4a3fd880b676d4b9197cce848756"
        },
        "pre-commit.yml/tests": {
            "sha256": "5887f449e2bca6242ffc495daf0f9181be6035d4429a0b7e2f882cb9757c31be"
        },
        "sbom.yml/inventory": {
            "sha256": "038b225e451ccdbbc8f84086cd53ffba43a94d52a2dfa2faf289d2d73af99ed0"
        },
        "scorecard.yml/configuration": {
            "sha256": "dc59deb2ce3169dcacab11219f4028721b83c11106a8138a738120f3ce88a147"
        },
        "security-audit.yml/dependency": {
            "sha256": "9a6a3e53ffbed3833a9a00a85a469779a29d569d1450630ff687ae1c8a71b31d"
        },
        "security-audit.yml/secrets": {
            "sha256": "235d84069958c8a2cdb1f8f1bbff5bf73cff2a59aaf514923abc00fbaea3bb14"
        },
        "security-audit.yml/static": {
            "sha256": "7a52ac3d6d07529d193a7ef638e70169b2976dde4c801664e0d58d15de020bb4"
        },
        "security-audit.yml/workflow": {
            "sha256": "9a714c90a46f731b4f7852c241852a3749c6e40f66e660edb987b79cb908c6f7"
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
    "python_version": "3.13.16",
    "job_timeout_minutes": 20,
    "workflow_max_bytes": 102400,
    "workflow_max_lines": 1000,
    "permissions": {},
    "concurrency_group": "${{ github.workflow }}-${{ github.ref }}",
    "cancel_in_progress": True,
}
