#!/bin/bash -eu
# Copyright 2026 FENGARDE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Build all 19 atheris fuzz harnesses from tools/fuzz/ into $OUT.
# This list MUST match .github/workflows/fuzz.yml and tools/fuzz/ exactly.
FUZZ_TARGETS=(
  fuzz_active_directory
  fuzz_cef
  fuzz_cisco_asa
  fuzz_cloudtrail
  fuzz_db_audit
  fuzz_dns_query
  fuzz_generic_syslog
  fuzz_inventory_diff
  fuzz_k8s_audit
  fuzz_linux_ssh
  fuzz_m365_audit
  fuzz_mail_gateway
  fuzz_mcp_agent
  fuzz_modbus_anomaly
  fuzz_n8n_audit
  fuzz_opcua_audit
  fuzz_sysmon
  fuzz_vmware_vsphere
  fuzz_windows_eventlog
)

# The harnesses add services/ to sys.path at RUN time, which PyInstaller cannot see, so (1) the Dockerfile puts the
# service directories on PYTHONPATH for the analysis, (2) every package is collected explicitly, and (3) shared/ocsf.py
# finds tools/validate_contract.py and contracts/ relative to its own bundled location (_MEIPASS), so ship both.
PYI_ARGS=(
  --paths "$SRC/fengarde/services"
  --paths "$SRC/fengarde/services/ws2-normalization"
  --paths "$SRC/fengarde/tools/fuzz"
  --collect-submodules shared
  --collect-submodules parsers
  --collect-submodules enrichment
  --hidden-import yaml
  --add-data "$SRC/fengarde/tools/validate_contract.py:tools"
  --add-data "$SRC/fengarde/contracts:contracts"
)

for fuzzer in "${FUZZ_TARGETS[@]}"; do
  compile_python_fuzzer "$SRC/fengarde/tools/fuzz/${fuzzer}.py" "${PYI_ARGS[@]}"
done