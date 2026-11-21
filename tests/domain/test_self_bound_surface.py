# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the public self-bound submodule's pinned surface

"""Pin the self-bound submodule's names and keep them out of the package root."""

import evidence_manifest_toolkit as toolkit
from evidence_manifest_toolkit import self_bound
from evidence_manifest_toolkit._self_bound_launch import SelfBoundRequest, verify_self_bound


def test_the_submodule_exports_exactly_the_launch_and_its_request() -> None:
    """Its two names are the launch function and its result, and nothing else is public."""
    assert tuple(self_bound.__all__) == ("SelfBoundRequest", "verify_self_bound")
    assert self_bound.verify_self_bound is verify_self_bound
    assert self_bound.SelfBoundRequest is SelfBoundRequest
    public = {name for name in vars(self_bound) if not name.startswith("_")}
    assert public == set(self_bound.__all__)


def test_the_package_root_does_not_export_the_launch() -> None:
    """The root keeps its pure operations; the host-reading launch stays in its submodule."""
    for name in self_bound.__all__:
        assert name not in toolkit.__all__
        assert not hasattr(toolkit, name)
