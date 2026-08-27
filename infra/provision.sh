#!/bin/sh
# Idempotent provisioning: install ISM retention policies and index templates from contracts/.
#
# M4.6: for a SCRIPTED upgrade (not first-boot compose provisioning), prefer
# `python3 tools/migrate_opensearch.py` instead of this file for the TEMPLATE
# half -- it diffs each template's mapping_version against what's installed
# and only PUTs what actually changed (auditable plan-then-apply), rather
# than this script's unconditional re-PUT-everything loop. Kept here because
# the `provision` compose service intentionally stays a minimal curl-only
# image (curlimages/curl) with no Python, so it can't invoke that tool
# directly; this script is still what `docker compose up` runs automatically.
set -eu
OS="${OPENSEARCH_URL:-http://opensearch:9200}"

echo "Waiting for OpenSearch at $OS ..."
until curl -sf "$OS/_cluster/health" >/dev/null; do sleep 2; done

echo "Installing ISM retention policies ..."
# Real ISM (Index State Management) policies in OpenSearch's own schema
# (states/transitions at _plugins/_ism/policies/<name>). Each policy body
# carries an ism_template block, so it auto-attaches to matching indices at
# index-creation time -- no template setting involved (the old
# index.lifecycle.name references were Elasticsearch-only and are removed).
# Idempotent: create-PUT first; if the policy already exists, re-PUT with
# the stored _seq_no/_primary_term (ISM's required update handshake). The
# seq/primary parse uses sed because the provision container is curl-only.
for pol in events-common-90d events-90d events-400d-pci alerts-365d reports-365d incidents-365d; do
  if curl -sf -X PUT "$OS/_plugins/_ism/policies/$pol" \
       -H 'Content-Type: application/json' \
       --data-binary "@/mappings/ism-$pol.json" >/dev/null 2>&1; then
    echo " - policy $pol installed"
  else
    meta=$(curl -sf "$OS/_plugins/_ism/policies/$pol" || true)
    seq=$(printf '%s' "$meta" | sed -n 's/.*"_seq_no":\([0-9][0-9]*\).*/\1/p')
    prim=$(printf '%s' "$meta" | sed -n 's/.*"_primary_term":\([0-9][0-9]*\).*/\1/p')
    if [ -n "$seq" ] && [ -n "$prim" ] && \
       curl -sf -X PUT "$OS/_plugins/_ism/policies/$pol?if_seq_no=$seq&if_primary_term=$prim" \
         -H 'Content-Type: application/json' \
         --data-binary "@/mappings/ism-$pol.json" >/dev/null 2>&1; then
      echo " - policy $pol updated (already existed)"
    else
      echo " - policy $pol FAILED to install/update" >&2
      exit 1
    fi
  fi
done

echo "Installing index templates ..."
# Gap-hunt (2026-08-26): this loop used `curl ... && echo ok || echo "(skipped)"`,
# which DEFEATS the script's `set -eu`: any rejected template (HTTP 4xx/5xx,
# body error, unreachable cluster) printed "(skipped: X)" and exited 0, so a
# broken template or a partially-down cluster "provisioned" successfully and
# left the indexer writing with no contract mappings and no error anywhere.
# Fail loudly instead: curl's exit status catches transport + HTTP >=400
# (-f), and the response BODY is additionally grepped for OpenSearch's
# "acknowledged":true so a 200-with-error-body can't slip through as success.
for tmpl in events-common events-bank events-dc assets alerts reports incidents; do
  echo " - template $tmpl"
  body=$(curl -fsS -X PUT "$OS/_index_template/$tmpl" \
    -H 'Content-Type: application/json' \
    --data-binary "@/mappings/$tmpl.json") || {
      echo "   FAILED: template $tmpl rejected by OpenSearch at $OS (curl exit $?)" >&2
      exit 1
  }
  if ! printf '%s' "$body" | grep -q '"acknowledged"[[:space:]]*:[[:space:]]*true'; then
    echo "   FAILED: OpenSearch did not acknowledge template $tmpl: $(printf '%s' "$body" | head -c 500)" >&2
    exit 1
  fi
  echo "   ok"
done

echo "Provisioning complete."
