# Docker

> **Status of this recipe.** The configs were linted with the official container images (Vector 0.61.0, Fluent Bit 5.1.5, rsyslog 8.2610.0,
> syslog-ng 4.12.0) and, where Linux-capable, run live on Docker Desktop against a real ws1 listener and the real WS-2 path
> (see the [Verification log](README.md#verification-log)). What was not run is stated below. The committed samples are still adapter
> fixtures / templates, not captures; `tools/test_shipping_recipes.py` runs them through WS-2.

Parser: `generic_syslog` for ordinary container output; `linux_ssh` when the container line is an sshd line (via the text sniff).
A container's application logs are **not** parsed by an app-specific parser, only as generic syslog text.

## Fluent Bit -> HTTP (adapter `docker-json`)

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

Ingest path: `POST http://<ws1>:8554/v1/ingest?source_type=<type>&format=ndjson` with
`Authorization: Bearer $FENGARDE_INGEST_TOKEN`, optional `X-Fengarde-Shipper` (adapter label, one per sender) and
`X-Fengarde-Source` (device name). See [../ingest-http.md](../ingest-http.md). TLS is not terminated by ws1; put it behind the proxy in
[../deployment.md](../deployment.md) before leaving a loopback/LAN segment.

The adapter needs `docker_id` and/or `docker_name` **and** `time` on each record; a bare json-file line is left untouched and
dead-letters (documented no-op). This recipe keeps `time` with a custom parser and derives the ids from the file path with a
Lua filter. The adapter docs suggest Fluent Bit can add these ids itself. It cannot: Fluent Bit has **no `docker` filter** (checked against the
fluent/fluent-bit-docs `pipeline/filters` listing on GitHub, 2026-11-05), so the ids are derived from the file path. Consequence: with this
recipe `docker_name` is the first 12 hex of the container id, not the human container name.

```ini fluent-bit-docker.conf
# Fluent Bit (Docker host) json-file logs -> FENGARDE HTTP ingest. Linted and run live on Linux containers 2026-11-05 (README Verification log).
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
[SERVICE]
    Flush         5
    Parsers_File  fluent-bit-docker-parsers.conf

[INPUT]
    Name        tail
    Path        /var/lib/docker/containers/*/*-json.log
    Path_Key    path
    Parser      docker_keep_time
    Tag         docker.*

# The adapter needs docker_id / docker_name. This derives them from the file path
# (name = first 12 hex of the id). Container NAMES are not in the path.
[FILTER]
    Name      lua
    Match     docker.*
    script    docker_ids.lua
    call      add_ids

[OUTPUT]
    Name             http
    Match            docker.*
    Host             192.0.2.10
    Port             8554
    URI              /v1/ingest?source_type=generic_syslog&format=ndjson
    Format           json_lines
    Json_Date_Key    false
    Header           Authorization Bearer ${FENGARDE_INGEST_TOKEN}
    Header           X-Fengarde-Shipper docker-json
    Header           X-Fengarde-Source docker-host-01
```

```ini fluent-bit-docker-parsers.conf
[PARSER]
    Name         docker_keep_time
    Format       json
    Time_Key     time
    Time_Format  %Y-%m-%dT%H:%M:%S.%L
    Time_Keep    On
```

```lua docker_ids.lua
function add_ids(tag, ts, record)
  local id = record["path"] and string.match(record["path"], "/containers/(%x+)/")
  if id == nil then return 0, ts, record end
  record["docker_id"] = id
  record["docker_name"] = string.sub(id, 1, 12)
  return 1, ts, record
end
```

Samples (the adapter fixtures, i.e. the shape the adapter accepts; **NOT this config's literal output**: they carry a human
`docker_name` such as `n8n_bankcorp`, whereas this config's Lua sets `docker_name` to the 12-hex id):
[n8n container line](samples/docker-n8n.fluentbit.json) -> `generic_syslog`; [sshd in a container](samples/docker-sshd.fluentbit.json) -> `linux_ssh`.

**Verified (Fluent Bit 5.1.5, Linux container):** `%L` consumed the 9-digit Docker fraction and the trailing `Z`: `2026-11-05T08:30:00.123456789Z` parsed to
08:30:00.123457 UTC (double precision), `...01.5Z` to 01.5; non-time text logs `invalid time format ... for 'garbage'`. With `Time_Keep On` the original `time`
string reaches ws1 unchanged. Run live: the Lua `add_ids` script added `docker_id` (64 hex from the path) and `docker_name` (first 12); two
json-file lines reached ws1 as `docker-json` / `generic_syslog` and normalized to class 1002. **Limit found:** the program slot is the 12-hex id, so a container's
line becomes `linux_ssh` only when the container's own text carries a syslog-style `sshd[pid]:` prefix (as the sshd sample does); a bare
`Failed password ...` line resolves to `generic_syslog`. The glob in `Path` is re-scanned every 60 s by default, so containers created later appear after up to a minute.

## Vector -> TCP syslog 5515

Vendor docs: <https://vector.dev/docs/reference/configuration/sources/docker_logs/>. **Verified live** (Vector 0.61.0, Docker socket mounted, one test container): `.container_name`,
.stream, .timestamp, .message exist; stderr produced `<11>`, stdout `<14>`; frames reached the FENGARDE TCP listener LF-terminated; both lines normalized to class 1002 / `generic_syslog`
(the same `sshd[pid]:` prefix caveat applies). VRL warned `can't abort infallible function` for `join!`, so the config uses `join(...)`. The test copy added `include_containers` to avoid shipping other containers' logs.

```toml vector-docker.toml
# Vector docker_logs -> FENGARDE TCP syslog 5515. Linted and run live on Linux containers 2026-11-05 (README Verification log).
# Verified on Vector 0.61.0: .container_name, .stream, .timestamp and .message exist on docker_logs events. Needs the Docker socket mounted.
[sources.docker]
type = "docker_logs"

[transforms.to_line]
type = "remap"
inputs = ["docker"]
source = '''
msg = string!(.message)
name = string!(.container_name)
pri = if .stream == "stderr" { "<11>" } else { "<14>" }
.message = join([pri, format_timestamp!(.timestamp, format: "%b %e %H:%M:%S"), " ", name, " ", name, ": ", msg], separator: "")
'''

[sinks.fengarde]
type = "socket"
inputs = ["to_line"]
mode = "tcp"
address = "192.0.2.10:5515"
encoding.codec = "text"
```

Sample: [line shape this remap targets](samples/docker-n8n.vector.syslog.txt) -> `generic_syslog`. The remap puts the container
**name** in both the host and the program slot; the `docker-json` adapter would put the 12-char id in the host slot, so this sample is the
adapter's output for the docker fixture with the host slot replaced by the name (the test asserts exactly that). Not a Vector capture.

## Not covered

- Containers using a non-`json-file` logging driver; Docker events; Kubernetes (different ids and shape).
- Multi-line records (stack traces) are separate lines.
- App-level parsing of the container's own output.
