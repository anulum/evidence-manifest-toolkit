# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — the public self-bound launch, a host-reading and file-writing route

"""Build an unsigned V2 request in the process that verifies it, and verify it there.

This is not one of the package's pure operations over bytes and a resolver. It reads the
host — the boot identifier, this process's ``/proc/self/stat``, the native entry method and
timesyncd's NTP reply through ``/usr/bin/busctl`` — and, after verification returns, writes the
request's records into the caller's object store and publishes a fresh request directory.
The command ``emt verify-self-bound`` is the same route for a launcher that starts a child.
"""

from ._self_bound_launch import SelfBoundRequest, verify_self_bound

__all__ = ["SelfBoundRequest", "verify_self_bound"]
