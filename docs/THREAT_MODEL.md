<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance
-->

# Threat model

Assets are original source/configuration bytes, attribution, exact development producers, complete validation outcomes and caller-selected inventory outputs. Inputs may contain malformed text, duplicate keys, hostile YAML, path escapes, symlinks, special files, oversized trees, false claims or weakened policy. Caller diagnostics must not expose confidential input values or arbitrary exception/tool text.

Trust comes from reviewed guard source and verified tool producers. Caller repository input is untrusted. No received file chooses an executable or plugin. JSON/YAML parsing is bounded and offline. Native tool output is privately captured under explicit byte and time limits. Linux groups are created by the caller and only those owned groups are terminated and reaped; unrelated processes remain outside that authority.

A supplied workflow outcome file is an untrusted local projection. It cannot
bypass graph validation, introduce roles or callbacks, or authenticate a hosted
run. An owner using genuine host receipts must independently establish their
origin and the construction of the supplied six-role projection.

Exclusive output publication denies overwrite and symbolic ancestors. Failure before publication removes only the positively owned temporary file. Failure after full publication preserves complete bytes and returns nonzero. Filesystem faults establish recovery behaviour, not physical storage reliability.

Residual risks include a compromised host/interpreter, malicious trusted dependency producer, concurrent filesystem mutation and inaccurate upstream vulnerability information. Guards and local snapshots do not prove authenticity of scientific evidence or establish security certification. Signing, operational trust, hosted service settings and Windows process handling require their own genuine implementation and review.
