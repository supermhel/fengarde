# Stage 1 row diff: `causal_order_retained` recorded, not gating (2026-10-02)

Record of the before/after comparison required by the causal-order plan (Stage 1). `eval/adversarial/out/` is generated and gitignored, so the comparison is committed here instead of the raw JSON.

- **Before:** `eval/adversarial/layer_a.py --seed 7` and `eval/adversarial/scenario_matrix.py --seed 7` at the code of commit `c8705c6`.
- **After:** the same commands with `layer_a._cmp` additionally recording `causal_order_fidelity` and `causal_order_retained` (= not (baseline is not None and (mutated is None or mutated < baseline))). Neither is in `pass`.
- **Result:** 84 applicable rows compared (37 Layer A + 47 scenario-matrix). **0 `pass` flips. 0 rows with any changed pre-existing key.** Layer A is 34/37 (0.9189) before and after; the scenario-matrix per-scenario overall blocks and the pooled number (37/47) are identical.
- **What the new flag says, today:** every row with `causal_order_retained = False` is either already failing (`pass = False`) or on the `loss` axis, where dropping a step's own source legitimately changes the fraction (the loss-axis verdict keeps using the boolean `order_retained`). So promoting it into `pass` (Stage 2, owner-gated) would flip **no** non-loss row on the current catalogue; it would matter for future mutations that keep detection and the legacy join but disturb order or edge timing.
- `None` in the `causal_order_fidelity` column means no edge was available to grade (not a measured 0).

| lane | storyline | axis | variant | pass before | pass after | causal_order_fidelity | causal_order_retained |
|---|---|---|---|---|---|---|---|
| layer_a | ai_to_ot | composition | identity+network | False | False | 0.4 | False |
| layer_a | ai_to_ot | composition | identity+network+protocol | True | True | 1.0 | True |
| layer_a | ai_to_ot | composition | identity+network+tool+timing+telemetry+prompt+protocol | True | True | 1.0 | True |
| layer_a | ai_to_ot | credential | borrowed_credential | True | True | 1.0 | True |
| layer_a | ai_to_ot | credential | different_path | True | True | 1.0 | True |
| layer_a | ai_to_ot | identity | actor_split | True | True | 1.0 | True |
| layer_a | ai_to_ot | identity | different_actor | True | True | 1.0 | True |
| layer_a | ai_to_ot | identity | service_account | True | True | 1.0 | True |
| layer_a | ai_to_ot | identity | unusual_operator | True | True | 1.0 | True |
| layer_a | ai_to_ot | network | actor_multiple_ips | True | True | 1.0 | True |
| layer_a | ai_to_ot | network | ip_pivot | True | True | 1.0 | True |
| layer_a | ai_to_ot | network | segment_ips | False | False | 0.4 | False |
| layer_a | ai_to_ot | network | source_rotation | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | base64_wrap | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | benign_camouflage | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | case_flip | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | delimiter_changes | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | equivalent_phrasing | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | language_switch | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | structured_wrap | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | unicode_confusables | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | url_encode | True | True | 1.0 | True |
| layer_a | ai_to_ot | prompt | whitespace | True | True | 1.0 | True |
| layer_a | ai_to_ot | protocol | changed_register | True | True | 1.0 | True |
| layer_a | ai_to_ot | protocol | modbus_func_code | True | True | 1.0 | True |
| layer_a | ai_to_ot | protocol | opcua_path | True | True | 1.0 | True |
| layer_a | ai_to_ot | protocol | opcua_path_in_hours | True | True | 1.0 | True |
| layer_a | ai_to_ot | telemetry | delay | True | True | 1.0 | True |
| layer_a | ai_to_ot | telemetry | duplicate | True | True | 1.0 | True |
| layer_a | ai_to_ot | telemetry | loss | False | False | 1.0 | True |
| layer_a | ai_to_ot | telemetry | reorder | True | True | 1.0 | True |
| layer_a | ai_to_ot | timing | delayed | True | True | 1.0 | True |
| layer_a | ai_to_ot | timing | split_window | True | True | 1.0 | True |
| layer_a | ai_to_ot | timing | straddle_maintenance | True | True | 1.0 | True |
| layer_a | ai_to_ot | tool | alternate_tool | True | True | 1.0 | True |
| layer_a | ai_to_ot | tool | argument_shape | True | True | 1.0 | True |
| layer_a | ai_to_ot | tool | chained_intermediary | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | delivery | duplicate_all | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | delivery | reverse_arrival | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | delivery | shuffle_arrival | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | loss | drop_agent_mcp_tool_call | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | loss | drop_credential_use | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | loss | drop_external_content | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | loss | drop_modbus_write | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | loss | drop_n8n_execution | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | loss | drop_plc_state_change | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | loss | drop_process_anomaly | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | timing | jitter_900ms | True | True | 1.0 | True |
| scenario_matrix | ai_to_ot | timing | shift_1h | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | delivery | duplicate_all | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | delivery | reverse_arrival | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | delivery | shuffle_arrival | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | distribution | ip_rotate_2 | False | False | 0.5 | False |
| scenario_matrix | infra_takeover | distribution | ip_rotate_all | False | False | 0.5 | False |
| scenario_matrix | infra_takeover | identity | account_split_2 | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | loss | drop_cloud_root_login | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | loss | drop_mass_vm_delete | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | loss | drop_privileged_container | True | True | None | False |
| scenario_matrix | infra_takeover | noise | benign_decoys | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | pacing | stretch_2x | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | pacing | stretch_6x | False | False | 1.0 | True |
| scenario_matrix | infra_takeover | timing | jitter_900ms | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | timing | shift_1h | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | volume | thin_25pct | True | True | 1.0 | True |
| scenario_matrix | infra_takeover | volume | thin_60pct | False | False | 1.0 | True |
| scenario_matrix | it_intrusion | delivery | duplicate_all | True | True | 0.8333 | True |
| scenario_matrix | it_intrusion | delivery | reverse_arrival | True | True | 0.8333 | True |
| scenario_matrix | it_intrusion | delivery | shuffle_arrival | True | True | 0.8333 | True |
| scenario_matrix | it_intrusion | distribution | ip_rotate_2 | False | False | 0.3333 | False |
| scenario_matrix | it_intrusion | distribution | ip_rotate_all | False | False | 0.3333 | False |
| scenario_matrix | it_intrusion | identity | account_split_2 | True | True | 0.8333 | True |
| scenario_matrix | it_intrusion | loss | drop_dns_exfil | True | True | 0.75 | False |
| scenario_matrix | it_intrusion | loss | drop_initial_access | True | True | 0.75 | False |
| scenario_matrix | it_intrusion | loss | drop_lateral_movement | True | True | 0.6667 | False |
| scenario_matrix | it_intrusion | loss | drop_priv_grant | True | True | 0.75 | False |
| scenario_matrix | it_intrusion | loss | drop_recon_port_scan | True | True | 1.0 | True |
| scenario_matrix | it_intrusion | loss | drop_ssh_bruteforce | True | True | 1.0 | True |
| scenario_matrix | it_intrusion | noise | benign_decoys | True | True | 0.8333 | True |
| scenario_matrix | it_intrusion | pacing | stretch_2x | False | False | 0.8333 | True |
| scenario_matrix | it_intrusion | pacing | stretch_6x | False | False | None | False |
| scenario_matrix | it_intrusion | timing | jitter_900ms | True | True | 0.8333 | True |
| scenario_matrix | it_intrusion | timing | shift_1h | True | True | 0.8333 | True |
| scenario_matrix | it_intrusion | volume | thin_25pct | False | False | 0.6667 | False |
| scenario_matrix | it_intrusion | volume | thin_60pct | False | False | None | False |
