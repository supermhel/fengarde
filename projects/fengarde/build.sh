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

# Build all 17 atheris fuzz harnesses from tools/fuzz/ into $OUT.
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
  fuzz_mcp_agent
  fuzz_modbus_anomaly
  fuzz_n8n_audit
  fuzz_opcua_audit
  fuzz_sysmon
  fuzz_vmware_vsphere
  fuzz_windows_eventlog
)

for fuzzer in "${FUZZ_TARGETS[@]}"; do
  compile_python_fuzzer "$SRC/fengarde/tools/fuzz/${fuzzer}.py"
done