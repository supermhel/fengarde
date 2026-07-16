#!/bin/sh
# Idempotent provisioning: install ILM policies and index templates from contracts/.
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

echo "Installing ILM policies ..."
# NOT actually implemented -- honest placeholder, not a silent no-op passed
# off as success. contracts/opensearch-mappings/ilm-policies.json is written
# in Elasticsearch ILM syntax (phases/actions/min_age), but this stack runs
# OpenSearch, whose Index State Management (ISM) plugin uses a DIFFERENT
# policy schema (states/transitions) at a different endpoint
# (_plugins/_ism/policies/<name>, not _ilm/policy/<name>). PUTting the
# current file's bodies as-is would be rejected as malformed. Every index
# template below already references these policy names via
# index.lifecycle.name, so until this is fixed, ILM/retention on a live
# OpenSearch cluster is NOT actually enforced -- tracked as an open gap
# (SSOT.md), not silently worked around here. Fixing it needs a live
# cluster to verify the real ISM policy bodies against, which this repo's
# zero-infra test path can't do.
for pol in events-30d events-90d events-400d-pci alerts-365d; do
  echo " - policy $pol (NOT installed -- schema mismatch, see comment above)"
done

echo "Installing index templates ..."
for tmpl in events-common events-bank events-dc assets alerts; do
  echo " - template $tmpl"
  curl -sf -X PUT "$OS/_index_template/$tmpl" \
    -H 'Content-Type: application/json' \
    --data-binary "@/mappings/$tmpl.json" >/dev/null \
    && echo "   ok" || echo "   (skipped: $tmpl)"
done

echo "Provisioning complete."
