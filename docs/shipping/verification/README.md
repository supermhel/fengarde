# Manual verification driver

`e2e.py` is the script the 2026-11-05 live runs in the [Verification log](../README.md#verification-log) were driven with, cleaned of
machine-specific paths. It is a **manual** tool:

- It needs Docker (Linux containers) and pulls vendor images (`fluent/fluent-bit:5.1.5`, `timberio/vector:0.61.0-alpine`, `rsyslog/rsyslog:2026-10`,
  `balabit/syslog-ng:4.12.0`, `alpine:3.20`, `debian:trixie-slim`). It starts throwaway containers and volumes named `fengarde-e2e-*` and removes them afterwards.
  It never touches a running FENGARDE stack: it starts its own ws1 HTTP and TCP-syslog listeners on a memory bus on `127.0.0.1` and ports it picks.
- It copies `docs/shipping/configs/` into a scratch directory, substitutes the placeholder address `192.0.2.10` and the ports, starts the shipper
  container against that copy, writes test input (a Docker json-file, an n8n audit file, dnsmasq lines, `systemd-cat` journal entries, `logger` lines) and prints each
  message that reached the bus together with the parser WS-2 chose and the OCSF class. Container-side bytes are captured by a proxy in front of the TCP listener.
- It covers `fb-docker fb-n8n vec-n8n fb-dns vec-dns vec-docker fb-journald vec-journald rs-fwd rs-relay ng-fwd ng-relay`. It does **not** cover Windows
  (the Windows run was done by hand on a Windows 11 host), Pi-hole, the `include_units` journal test, the relay bind-address tests or any real appliance.
- It is **not part of CI** and is not a test (the file name does not start with `test_`, and nothing imports it). `tools/test_shipping_recipes.py`
  is the zero-infra gate; this driver is how the "run live" statements were produced. Output depends on the host and image tags; some recipes need
  environment such as `VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true`, which the driver sets itself for `vec-n8n`.

Run: `python docs/shipping/verification/e2e.py rs-fwd 8` (recipe, seconds to wait). Checked again on 2026-11-07 for `rs-fwd` (the `sshd` line resolved to `linux_ssh`, 3002) and
`fb-journald` (the committed config, with the three `Systemd_Filter` lines, delivered journal entries through ws1 HTTP); the other recipes were not re-run for this commit.
The ingest token is generated per run and passed to the container by variable name; it is not printed.

**2026-11-11 additions (PR #153 verification, not in this folder's driver):** the socket-activated sshd journal and the 60 s outage runs were driven by scratch scripts, not committed. Limits: connection refused only, at most 40 records per run, shippers fed by `logger` on `/dev/log` or an appended file, the listener on the same host, Debian 13 only. See the Delivery guarantees table in `../README.md`.
