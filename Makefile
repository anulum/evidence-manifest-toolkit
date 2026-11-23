# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# EVIDENCE-MANIFEST-TOOLKIT — source and configuration provenance

PYTHON := .venv/bin/python
BASE_PYTHON ?= python
ENVIRONMENT_DIR ?= .venv
ENVIRONMENT_INPUTS ?= .tool-cache/environment-inputs
ENVIRONMENT_INPUT_BYTES ?= 134217728
UV := .tool-cache/bootstrap-uv/uv
UV_CACHE ?= .tool-cache/uv-cache
TEST_WORKERS ?= 0

.PHONY: quality test docs preflight inventory-generate inventory source-analysis static-security dependency-security secret-scan workflow-security sbom supply-chain

quality:
	$(PYTHON) -m ruff check src tools tests
	$(PYTHON) -m ruff format --check src tools tests
	$(PYTHON) -m mypy src tools tests
	$(PYTHON) -m ruff check --select D src tools tests

test:
	nice -n 10 $(PYTHON) -m pytest -n $(TEST_WORKERS) --dist=worksteal --basetemp=.tool-cache/tests --cov=tools --cov=evidence_manifest_toolkit --cov-branch --cov-fail-under=100 --cov-report=term-missing tests

docs:
	$(PYTHON) tools/check_documentation.py --root . --json

inventory-generate:
	$(PYTHON) tools/check_repository_inventory.py --root . --mode generate --output capability-inventory.json --json

inventory:
	$(PYTHON) tools/check_repository_inventory.py --root . --mode verify --json

preflight:
	$(PYTHON) tools/preflight.py --root . --profile local-scaffold --json

source-analysis:
	$(PYTHON) tools/check_static_security.py --root . --json

static-security: source-analysis

dependency-security:
	$(PYTHON) tools/check_dependency_alignment.py --root . --json

secret-scan:
	.tool-cache/native/gitleaks/gitleaks dir --redact --no-banner --log-level error --ignore-gitleaks-allow --gitleaks-ignore-path /dev/null --config gitleaks.toml .

workflow-security:
	$(PYTHON) -I -c 'import sys;sys.path.insert(0,"tools");from local_scaffold.actionlint_view import main;sys.exit(main())'
	.venv/bin/zizmor --no-config --no-ignores --strict-collection --persona auditor --offline .github/workflows/*.yml

sbom:
	.venv/bin/cyclonedx-py environment --output-format JSON --output-file .tool-cache/sbom.json $(PYTHON)

supply-chain:
	$(PYTHON) tools/check_source_provenance.py --root . --json
	$(PYTHON) tools/check_workflow_policy.py --root . --json
	$(PYTHON) tools/check_dependency_alignment.py --root . --json


.PHONY: environment prepare-native prepare-codeql prepare-test-fixtures prepare-test-wheels prepare-interpreter-fixture prepare-major-interpreter-fixture prepare-test-inputs produce-audit prepare-uv check-environment-inputs fetch-environment-inputs

environment:
	test ! -L "$(ENVIRONMENT_DIR)"
	test ! -L .tool-cache
	test ! -L .tool-cache/bootstrap-builders.lock
	$(BASE_PYTHON) -B -I -c 'import platform; assert platform.python_version() == "3.13.18"'
	$(MAKE) --no-print-directory prepare-uv
	$(BASE_PYTHON) -B -I -c 'import pathlib; pathlib.Path("$(ENVIRONMENT_DIR)").parent.mkdir(parents=True,exist_ok=True)'
	mkdir -p "$(UV_CACHE)"
	$(BASE_PYTHON) -B -I -c 'import os,sys; assert os.stat(sys.argv[1]).st_dev == os.stat(sys.argv[2]).st_dev, "uv cache and environment must share a filesystem"' "$(UV_CACHE)" "$(dir $(ENVIRONMENT_DIR))"
	if test ! -e "$(ENVIRONMENT_DIR)/pyvenv.cfg"; then $(UV) --no-config venv --python "$(BASE_PYTHON)" --no-python-downloads --link-mode hardlink "$(ENVIRONMENT_DIR)"; fi
	"$(ENVIRONMENT_DIR)/bin/python" -B -I -c 'import platform; assert platform.python_version() == "3.13.18"'
	$(BASE_PYTHON) -B -I -c 'import pathlib,re; text=pathlib.Path("requirements-dev.txt").read_text(); blocks=re.findall(r"(?m)^((?:pip|poetry-core)==[^\n]+\n(?:    [^\n]*\n)*)",text); assert len(blocks)==2; pathlib.Path(".tool-cache/bootstrap-builders.lock").write_text("".join(blocks))'
	$(UV) --no-config pip install --python "$(ENVIRONMENT_DIR)/bin/python" --cache-dir "$(UV_CACHE)" --link-mode hardlink --require-hashes --no-deps --no-index --find-links "$(ENVIRONMENT_INPUTS)" -r .tool-cache/bootstrap-builders.lock
	$(UV) --no-config pip install --python "$(ENVIRONMENT_DIR)/bin/python" --cache-dir "$(UV_CACHE)" --link-mode hardlink --require-hashes --no-deps --no-build-isolation --no-index --find-links "$(ENVIRONMENT_INPUTS)" -r requirements-dev.txt
	$(UV) --no-config pip check --python "$(ENVIRONMENT_DIR)/bin/python"
	"$(ENVIRONMENT_DIR)/bin/python" -B -I -c 'import pathlib,sys; files=list(pathlib.Path(sys.prefix).glob("lib/python3.13/site-packages/*.dist-info/METADATA")); assert files and all(p.stat().st_nlink>1 for p in files), "Package hardlink verification failed"'

fetch-environment-inputs:
	test ! -L .tool-cache
	test ! -L "$(ENVIRONMENT_INPUTS)"
	$(BASE_PYTHON) -B -I -c 'import platform; assert platform.python_version() == "3.13.18"'
	mkdir -p .tool-cache
	$(BASE_PYTHON) -B -I tools/fetch_environment_inputs.py --root . --artifacts "$(ENVIRONMENT_INPUTS)" --json

check-environment-inputs:
	$(BASE_PYTHON) -B -I -c 'import platform; assert platform.python_version() == "3.13.18"'
	$(BASE_PYTHON) -B -I tools/check_environment_inputs.py --root . --artifacts "$(ENVIRONMENT_INPUTS)" --environment "$(ENVIRONMENT_DIR)" --max-input-bytes "$(ENVIRONMENT_INPUT_BYTES)" --json

prepare-uv:
	test ! -L .tool-cache
	test ! -L .tool-cache/bootstrap-uv
	test ! -L "$(UV)"
	$(MAKE) --no-print-directory check-environment-inputs
	mkdir -p .tool-cache/bootstrap-uv
	if test ! -e "$(UV)"; then $(BASE_PYTHON) -B -I -c 'import pathlib,shutil,sys,zipfile; destination=pathlib.Path(sys.argv[2]); archive=zipfile.ZipFile(sys.argv[1]); names=[n for n in archive.namelist() if n.endswith("/scripts/uv")]; assert len(names)==1; source=archive.open(names[0]); target=destination.open("xb"); shutil.copyfileobj(source,target); target.close(); source.close(); archive.close(); destination.chmod(0o755)' "$(ENVIRONMENT_INPUTS)/uv-0.13.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl" "$(UV)"; fi
	printf '%s  %s\n' 4b5e59bc557ff2cd70934beb59d0eaa92820702853d49f0066b50aa11a8f0c52 "$(UV)" | sha256sum --check --status


prepare-native:
	test ! -L .tool-cache
	test ! -L .tool-cache/native
	test ! -L .tool-cache/native-artifacts
	test ! -L .tool-cache/native/actionlint
	test ! -L .tool-cache/native/gitleaks
	test ! -L .tool-cache/native/actionlint/actionlint
	test ! -L .tool-cache/native/gitleaks/gitleaks
	test ! -L .tool-cache/native-artifacts/actionlint.tar.gz
	test ! -L .tool-cache/native-artifacts/gitleaks.tar.gz
	mkdir -p .tool-cache/native-artifacts .tool-cache/native/actionlint .tool-cache/native/gitleaks
	test ! -L .tool-cache/native-artifacts
	curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 2353908 --output .tool-cache/native-artifacts/actionlint.tar.gz https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz
	printf '%s  %s\n' 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 .tool-cache/native-artifacts/actionlint.tar.gz | sha256sum --check --status
	tar --no-same-owner --no-same-permissions -xzf .tool-cache/native-artifacts/actionlint.tar.gz -C .tool-cache/native/actionlint actionlint
	curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 8230402 --output .tool-cache/native-artifacts/gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
	printf '%s  %s\n' 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb .tool-cache/native-artifacts/gitleaks.tar.gz | sha256sum --check --status
	tar --no-same-owner --no-same-permissions -xzf .tool-cache/native-artifacts/gitleaks.tar.gz -C .tool-cache/native/gitleaks gitleaks

prepare-codeql:
	test ! -L .tool-cache
	test ! -L .tool-cache/native-artifacts
	test ! -L .tool-cache/native-artifacts/codeql-bundle-python-linux64.tar.zst
	mkdir -p .tool-cache/native-artifacts
	test ! -L .tool-cache/native-artifacts
	curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 111165259 --output .tool-cache/native-artifacts/codeql-bundle-python-linux64.tar.zst https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-python-linux64.tar.zst
	printf '%s  %s\n' ea86393c6c812542ae5a3a7122bcc760873707a50b25cc47d2fd7cfd514b0cb0 .tool-cache/native-artifacts/codeql-bundle-python-linux64.tar.zst | sha256sum --check --status

prepare-test-fixtures:
	test ! -L .tool-cache
	test ! -L .tool-cache/native-fixtures
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/bin
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/bin/strace
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc/strace
	test ! -L .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc/strace/copyright
	mkdir -p .tool-cache/native-fixtures/strace-6.8-0ubuntu2
	if test ! -e .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 584172 --output .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb https://archive.ubuntu.com/ubuntu/pool/main/s/strace/strace_6.8-0ubuntu2_amd64.deb; fi
	printf '%s  %s\n' d588810ae26b06fee6678dc81e5b54f6efcde8e718e4589adb4d11d254b9820b .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted; then dpkg-deb --extract .tool-cache/native-fixtures/strace-6.8-0ubuntu2/strace_6.8-0ubuntu2_amd64.deb .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted; fi
	printf '%s  %s\n' 28f957c227012de0b18d1bd7fff2d396cb693ea60ed8013be68de071e84b5001 .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/bin/strace | sha256sum --check --status
	printf '%s  %s\n' 40e4ca01654c733c06fabee65168da4c177117b1bd084f3a752bc8a989736e04 .tool-cache/native-fixtures/strace-6.8-0ubuntu2/extracted/usr/share/doc/strace/copyright | sha256sum --check --status

prepare-test-wheels:
	test ! -L .tool-cache
	test ! -L .tool-cache/wheelhouse
	test ! -L .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl
	test ! -L .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl
	mkdir -p .tool-cache/wheelhouse
	if test ! -e .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 129956 --output .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl; fi
	printf '%s  %s\n' d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl | sha256sum --check --status
	if test ! -e .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 257955 --output .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl https://files.pythonhosted.org/packages/1d/56/6785397d07c29c8e70fbb9a07e97d062b43c21ffc5f12385917847f09f63/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; fi
	printf '%s  %s\n' 4358b9c8c0125b460407f3017c6cce8156e904b32772c5630d27112f52bdbfe5 .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl | sha256sum --check --status

prepare-interpreter-fixture:
	test ! -L .tool-cache
	test ! -L .tool-cache/native-fixtures
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/extracted
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/extracted/python
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/guard-environment
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/guard-environment/bin
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/guard-environment/bin/python
	test ! -L .tool-cache/native-fixtures/cpython-3.13.15/installer-cache
	$(MAKE) prepare-test-wheels
	mkdir -p .tool-cache/native-fixtures/cpython-3.13.15
	if test ! -e .tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 35004265 --output .tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz https://github.com/astral-sh/python-build-standalone/releases/download/20260929/cpython-3.13.15%2B20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz; fi
	printf '%s  %s\n' c552deaf9ed0e678dee4ccc760d6dcd7cab33f1bd43e8037123b4a4db8508e14 .tool-cache/native-fixtures/cpython-3.13.15/cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/cpython-3.13.15/extracted; then $(PYTHON) -I -c 'import pathlib,tarfile; root=pathlib.Path(".tool-cache/native-fixtures/cpython-3.13.15"); target=root/"extracted"; target.mkdir(); archive=tarfile.open(root/"cpython-3.13.15+20260929-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"); archive.extractall(target,filter="data"); archive.close()'; fi
	printf '%s  %s\n' bb4d05c1f88e8568985e8704afe1822e82700a54bad9317c05c8eb96d3186701 .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13 | sha256sum --check --status
	printf '%s  %s\n' d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl | sha256sum --check --status
	printf '%s  %s\n' 4358b9c8c0125b460407f3017c6cce8156e904b32772c5630d27112f52bdbfe5 .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/cpython-3.13.15/guard-environment; then .tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13 -I -m venv --without-pip --copies .tool-cache/native-fixtures/cpython-3.13.15/guard-environment && .venv/bin/uv --no-config pip install --python .tool-cache/native-fixtures/cpython-3.13.15/guard-environment/bin/python --no-index --no-deps --link-mode copy --cache-dir .tool-cache/native-fixtures/cpython-3.13.15/installer-cache .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl .tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; fi
	printf '%s  %s\n' bb4d05c1f88e8568985e8704afe1822e82700a54bad9317c05c8eb96d3186701 .tool-cache/native-fixtures/cpython-3.13.15/guard-environment/bin/python | sha256sum --check --status
	.tool-cache/native-fixtures/cpython-3.13.15/guard-environment/bin/python -I -c 'import hashlib,importlib.metadata,json,platform; expected={"packaging":("26.3","70fdb89fc4d4a9a043bf7372b8972bcc883fddff34ab55e9cf80d73875384763"),"coverage":("7.16.2","a5447449aa5b0b5a8b7c6a800434623a70c316750fcdde7ebd5b0b41fe756f99")}; observed=list(importlib.metadata.distributions()); actual={d.metadata["Name"]:(d.version,hashlib.sha256(d.read_text("METADATA").encode()).hexdigest()) for d in observed}; assert platform.python_version()=="3.13.15" and actual==expected and len(observed)==2; print(json.dumps({"actual_python":platform.python_version(),"qualified_fixture_producers":actual},sort_keys=True))'

prepare-major-interpreter-fixture:
	test ! -L .tool-cache
	test ! -L .tool-cache/native-fixtures
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/extracted
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/extracted/python
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin/python3.14
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/guard-environment
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/guard-environment/bin
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/guard-environment/bin/python
	test ! -L .tool-cache/native-fixtures/cpython-3.14.7/installer-cache
	test ! -L .tool-cache/wheelhouse
	test ! -L .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl
	$(MAKE) prepare-test-wheels
	if test ! -e .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 258727 --output .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl https://files.pythonhosted.org/packages/a8/d4/a306940c81c6ae759e82fff27d20b7fdc6896e422b821f51313cce212b6c/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; fi
	mkdir -p .tool-cache/native-fixtures/cpython-3.14.7
	if test ! -e .tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz; then curl --fail --silent --show-error --location --proto '=https' --max-time 90 --max-filesize 35945651 --output .tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz https://github.com/astral-sh/python-build-standalone/releases/download/20260901/cpython-3.14.7%2B20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz; fi
	printf '%s  %s\n' 3959f92825141e04adf44982d3a83ee57af0877e893b0796e04c1468749d9b04 .tool-cache/native-fixtures/cpython-3.14.7/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/cpython-3.14.7/extracted; then $(PYTHON) -I -c 'import pathlib,tarfile; root=pathlib.Path(".tool-cache/native-fixtures/cpython-3.14.7"); target=root/"extracted"; target.mkdir(); archive=tarfile.open(root/"cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"); archive.extractall(target,filter="data"); archive.close()'; fi
	printf '%s  %s\n' 241bf774a81580bb760adf960b48df7e6b23b1de026c9c912d4ca6be1a08241e .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin/python3.14 | sha256sum --check --status
	printf '%s  %s\n' d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl | sha256sum --check --status
	printf '%s  %s\n' 35f37886699cb9abd29958247d718628d5bc6f39e623dff66a09e546c42a7e03 .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl | sha256sum --check --status
	if test ! -e .tool-cache/native-fixtures/cpython-3.14.7/guard-environment; then .tool-cache/native-fixtures/cpython-3.14.7/extracted/python/bin/python3.14 -I -m venv --without-pip --copies .tool-cache/native-fixtures/cpython-3.14.7/guard-environment && .venv/bin/uv --no-config pip install --python .tool-cache/native-fixtures/cpython-3.14.7/guard-environment/bin/python --no-index --no-deps --link-mode copy --cache-dir .tool-cache/native-fixtures/cpython-3.14.7/installer-cache .tool-cache/wheelhouse/packaging-26.3-py3-none-any.whl .tool-cache/wheelhouse/coverage-7.16.2-cp314-cp314-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl; fi
	printf '%s  %s\n' 241bf774a81580bb760adf960b48df7e6b23b1de026c9c912d4ca6be1a08241e .tool-cache/native-fixtures/cpython-3.14.7/guard-environment/bin/python | sha256sum --check --status
	.tool-cache/native-fixtures/cpython-3.14.7/guard-environment/bin/python -I -c 'import hashlib,importlib.metadata,json,platform; expected={"packaging":("26.3","70fdb89fc4d4a9a043bf7372b8972bcc883fddff34ab55e9cf80d73875384763"),"coverage":("7.16.2","a5447449aa5b0b5a8b7c6a800434623a70c316750fcdde7ebd5b0b41fe756f99")}; observed=list(importlib.metadata.distributions()); actual={d.metadata["Name"]:(d.version,hashlib.sha256(d.read_text("METADATA").encode()).hexdigest()) for d in observed}; assert platform.python_version()=="3.14.7" and actual==expected and len(observed)==2; print(json.dumps({"actual_python":platform.python_version(),"qualified_fixture_producers":actual},sort_keys=True))'

prepare-test-inputs:
	$(MAKE) prepare-native
	$(MAKE) prepare-codeql
	$(MAKE) prepare-test-fixtures
	$(MAKE) prepare-interpreter-fixture
	$(MAKE) prepare-major-interpreter-fixture
	$(MAKE) produce-audit

produce-audit:
	$(PYTHON) tools/check_dependency_alignment.py --root . --produce-audit --json
