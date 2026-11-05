# n8n

> **Status of this recipe.** The configs below were written from vendor documentation and were **not
> executed**: Vector, Fluent Bit, rsyslog and syslog-ng are not installed on the machine that produced them, so they are
> **not machine-linted** (`tools/lint_shipping_recipes.sh` does that when you have the tool). What a green test (per author run) covers is the
> FENGARDE half: each sample listed here goes through the real WS-2 path (`adapt_record` -> `resolve` -> parse -> OCSF
> validation) in `tools/test_shipping_recipes.py`. Whether your shipper emits exactly that sample shape is not proven by that test.

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
# Vector: JSON-lines file of n8n audit events -> FENGARDE HTTP ingest. Written from vendor docs, NOT executed.
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
# Records MUST already be in the n8n_audit parser's shape (eventType, user, ...). See n8n.md.
[sources.n8n]
type = "file"
include = ["/home/node/.n8n/fengarde-audit.log"]
decoding.codec = "json"

[sinks.fengarde]
type = "http"
inputs = ["n8n"]
uri = "http://192.0.2.10:8554/v1/ingest?source_type=n8n_audit&format=ndjson"
method = "post"
encoding.codec = "json"
framing.method = "newline_delimited"
auth.strategy = "bearer"
auth.token = "${FENGARDE_INGEST_TOKEN}"
request.headers = { "X-Fengarde-Shipper" = "vector", "X-Fengarde-Source" = "n8n-01" }
```

```ini fluent-bit-n8n.conf
# Fluent Bit: JSON-lines file of n8n audit events -> FENGARDE HTTP ingest. Written from vendor docs, NOT executed.
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
# Records MUST already be in the n8n_audit parser's shape (eventType, user, ...). See n8n.md.
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

Sample: [parser-shaped record](samples/n8n-audit.json), taken from the `n8n_audit` parser docstring (documented shape, not an n8n
capture) -> `n8n_audit`.

## Not covered

- n8n's native event names/payload (unverified mapping); n8n execution logs on stdout (those reach FENGARDE only as generic
  container text, see [docker.md](docker.md)).
- The file path `/home/node/.n8n/fengarde-audit.log` is a placeholder.
