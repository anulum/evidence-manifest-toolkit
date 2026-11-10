# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — frozen environment input identities

"""Bind complete Common environment inputs before any bootstrap mutation."""

from typing import Final

PYTHON_VERSION: Final = "3.13.18"
MAX_ARTIFACT_BYTES: Final = 20_000_000

SOURCE_PINS: Final = {
    "requirements-dev.in": "4befc8e16f07989488cad8cfd56c2a34122563c45bfb5a72d69a5eec2880c692",
    "requirements-dev.txt": "87b4805b45eeb78dd61745f7dabd39759c5e3f474c10a7acfd109051f42f05f5",
    "requirements-runtime.txt": "77447e22a0ed70905472e26ee12dd3eb0af4e7f447deff5faa7e550353c66845",
    "dependency-provenance.json": "9ab2cc6dab04fa6f3627bbdc1f6711eeb507e973da5445dab424e7e53fb8ab45",
}
