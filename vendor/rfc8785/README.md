<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
EVIDENCE-MANIFEST-TOOLKIT — maintained JCS dependency
-->
# Maintained rfc8785 wheel

This local `0.1.4+emt.1` build parameterizes `re.Match` as `re.Match[str]` in the upstream string-escaping callback. The canonicalization algorithms and full upstream Apache-2.0 license are preserved. Version metadata, NOTICE and RECORD distinguish this build from the upstream release.

[Source provenance](source-provenance.json) records the official download URL, original and local wheel hashes, complete license and build-tool hash. The local wheel SHA-256 is `e04761706fcbbb5f0afd5fa74a7e6ea7484ce97f073adb5372ab8ee93230c48e`.

Rebuild from the exact official `rfc8785-0.1.4-py3-none-any.whl` using a fresh destination:

```sh
python tools/vendor_rfc8785.py /path/to/rfc8785-0.1.4-py3-none-any.whl /path/to/new/rfc8785-0.1.4+emt.1-py3-none-any.whl
```

The tool checks the complete upstream wheel and implementation hashes, applies the exact annotation patch, recalculates every RECORD hash/length and uses fixed ZIP metadata. It refuses a different source or an existing destination. It downloads and installs nothing.
