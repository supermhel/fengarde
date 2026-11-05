# Docker

> **Status of this recipe.** The configs below were written from vendor documentation and were **not
> executed**: Vector, Fluent Bit, rsyslog and syslog-ng are not installed on the machine that produced them, so they are
> **not machine-linted** (`tools/lint_shipping_recipes.sh` does that when you have the tool). What *is* proven is the
> FENGARDE half: each sample listed here goes through the real WS-2 path (`adapt_record` -> `resolve` -> parse -> OCSF
> validation) in `tools/test_shipping_recipes.py`. Whether your shipper emits exactly that sample shape is not proven by that test.

Parser: `generic_syslog` for ordinary container output; `linux_ssh` when the container line is an sshd line (via the text sniff).
A container's application logs are **not** parsed by an app-specific parser, only as generic syslog text.

## Fluent Bit -> HTTP (adapter `docker-json`)

Ingest path: `POST http://<ws1>:8554/v1/ingest?source_type=<type>&format=ndjson` with
`Authorization: Bearer $FENGARDE_INGEST_TOKEN`, optional `X-Fengarde-Shipper` (adapter label, one per sender) and
`X-Fengarde-Source` (device name). See [../ingest-http.md](../ingest-http.md). TLS is not terminated by ws1; put it behind the proxy in
[../deployment.md](../deployment.md) before leaving a loopback/LAN segment.

The adapter needs `docker_id` and/or `docker_name` **and** `time` on each record; a bare json-file line is left untouched and
dead-letters (documented no-op). This recipe keeps `time` with a custom parser and derives the ids from the file path with a
Lua filter. The adapter docs mention Fluent Bit's `docker` filter for ids; **I could not confirm such a filter exists
under that name** (<https://docs.fluentbit.io/manual/pipeline/filters> does not list it), so it is not used. Consequence: with this
recipe `docker_name` is the first 12 hex of the container id, not the human container name.

```ini fluent-bit-docker.conf
# Fluent Bit (Docker host) json-file logs -> FENGARDE HTTP ingest. Written from vendor docs, NOT executed.
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

Samples (documented example, the adapter fixtures; the ids/names in them come from the docs example, not from this Lua):
[n8n container line](samples/docker-n8n.fluentbit.json) -> `generic_syslog`; [sshd in a container](samples/docker-sshd.fluentbit.json) -> `linux_ssh`.

## Vector -> TCP syslog 5515

Vendor docs: <https://vector.dev/docs/reference/configuration/sources/docker_logs/>. Field names **unverified**.

```toml vector-docker.toml
# Vector docker_logs -> FENGARDE TCP syslog 5515. Written from vendor docs, NOT executed.
# The docker_logs field names (.container_name, .stream, .timestamp) are UNVERIFIED.
[sources.docker]
type = "docker_logs"

[transforms.to_line]
type = "remap"
inputs = ["docker"]
source = '''
msg = string!(.message)
name = string!(.container_name)
pri = if .stream == "stderr" { "<11>" } else { "<14>" }
.message = join!([pri, format_timestamp!(.timestamp, format: "%b %e %H:%M:%S"), " ", name, " ", name, ": ", msg], separator: "")
'''

[sinks.fengarde]
type = "socket"
inputs = ["to_line"]
mode = "tcp"
address = "192.0.2.10:5515"
encoding.codec = "text"
```

Sample: [line shape this remap targets](samples/docker-n8n.vector.syslog.txt) (adapter output for the docker fixture; Vector
puts the container name in the host slot, the adapter the id) -> `generic_syslog`.

## Not covered

- Containers using a non-`json-file` logging driver; Docker events; Kubernetes (different ids and shape).
- Multi-line records (stack traces) are separate lines.
- App-level parsing of the container's own output.
