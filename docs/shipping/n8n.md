# n8n

> **Status of this recipe.** The configs were linted with the official container images (Vector 0.61.0, Fluent Bit 5.1.5, rsyslog 8.2610.0,
> syslog-ng 4.12.0) and, where Linux-capable, run live on Docker Desktop against a real ws1 listener and the real WS-2 path
> (see the [Verification log](README.md#verification-log)). What was not run is stated below. The committed samples are still adapter
> fixtures / templates, not captures; `tools/test_shipping_recipes.py` runs them through WS-2.

Parser: `n8n_audit` (class 6003 API Activity; login/logout 3002). Path: HTTP, `source_type=n8n_audit`.

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

Ingest path: `POST http://<ws1>:8554/v1/ingest?source_type=<type>&format=ndjson` with
`Authorization: Bearer $FENGARDE_INGEST_TOKEN`, optional `X-Fengarde-Shipper` (adapter label, one per sender) and
`X-Fengarde-Source` (device name). See [../ingest-http.md](../ingest-http.md). TLS is not terminated by ws1; put it behind the proxy in
[../deployment.md](../deployment.md) before leaving a loopback/LAN segment.

**The shape gap (read this).** `n8n_audit` expects JSON with `eventType` (or `event_type`/`type`), optional `user`/`userEmail`,
`ip`, `workflowId`, `path`, `ts`. That is the parser's own documented convention. This recipe tails a JSON-lines file that
already holds records in that shape and forwards it. **n8n's native event-log / log-streaming payload has not been compared
against this parser**, so no config here turns n8n's native output into that shape, and none is claimed to. Producing the file
(for example with a small n8n workflow or a transform step) is on you.

```toml vector-n8n.toml
# Vector: JSON-lines file of n8n audit events -> FENGARDE HTTP ingest. Linted and run live on Linux containers 2026-11-05 (README Verification log).
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
# Vector 0.61 does NOT expand env-var references (dollar-brace) unless started with VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true (otherwise the literal text is sent as the token and ws1 answers 401).
# Records MUST already be in the n8n_audit parser's shape (eventType, user, ...). See n8n.md.
[sources.n8n]
type = "file"
include = ["/home/node/.n8n/fengarde-audit.log"]

# The file source emits each line as .message; decode it so the record is the bare audit object.
[transforms.parse]
type = "remap"
inputs = ["n8n"]
source = '''
. = object!(parse_json!(string!(.message)))
'''

[sinks.fengarde]
type = "http"
inputs = ["parse"]
uri = "http://192.0.2.10:8554/v1/ingest?source_type=n8n_audit&format=ndjson"
method = "post"
encoding.codec = "json"
framing.method = "newline_delimited"
auth.strategy = "bearer"
auth.token = "${FENGARDE_INGEST_TOKEN}"
request.headers = { "X-Fengarde-Shipper" = "vector", "X-Fengarde-Source" = "n8n-01" }
```

```ini fluent-bit-n8n.conf
# Fluent Bit: JSON-lines file of n8n audit events -> FENGARDE HTTP ingest. Linted and run live on Linux containers 2026-11-05 (README Verification log).
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
# Records MUST already be in the n8n_audit parser's shape (eventType, user, ...). See n8n.md.
[SERVICE]
    Parsers_File  fluent-bit-n8n-parsers.conf

[INPUT]
    Name    tail
    Path    /home/node/.n8n/fengarde-audit.log
    Parser  json
    Tag     n8n

[OUTPUT]
    Name             http
    Match            n8n
    Host             192.0.2.10
    Port             8554
    URI              /v1/ingest?source_type=n8n_audit&format=ndjson
    Format           json_lines
    Json_Date_Key    false
    Header           Authorization Bearer ${FENGARDE_INGEST_TOKEN}
    Header           X-Fengarde-Shipper fluent-bit
    Header           X-Fengarde-Source n8n-01
```

```ini fluent-bit-n8n-parsers.conf
[PARSER]
    Name    json
    Format  json
```

Sample: [parser-shaped record](samples/n8n-audit.json), taken from the `n8n_audit` parser docstring (documented shape, not an n8n
capture) -> `n8n_audit`.

**Verified live (Linux containers):** Fluent Bit 5.1.5 and Vector 0.61.0 each tailed a JSON-lines file and delivered two records; WS-2 resolved both to `n8n_audit` (6003 and 3002 login) with
`X-Fengarde-Shipper`/`Source` preserved. **Fixed by this test:** (1) Fluent Bit failed with `parser 'json' is not registered` (`--dry-run` does not catch it) and, ignoring that, shipped
`{"log": "<line>"}`, which `n8n_audit` rejects; the config now loads `fluent-bit-n8n-parsers.conf`. (2) Vector's file source has no `decoding` option (rejected by `vector validate`) and delivers lines as `.message`; a `remap` now
parses them. (3) Vector 0.61 does NOT expand environment variables in config unless `VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true` is set; otherwise the literal text was sent as the bearer token and ws1
answered 401 (every line dropped). The variable-expansion pass also reads comments, so a config comment must not contain a dollar-brace reference. A non-JSON line is forwarded by Vector as its raw event
(`parse_json` fails, the event passes through) and dead-lettered by WS-2.

## Not covered

- n8n's native event names/payload (unverified mapping); n8n execution logs on stdout (those reach FENGARDE only as generic
  container text, see [docker.md](docker.md)).
- The file path `/home/node/.n8n/fengarde-audit.log` is a placeholder.
