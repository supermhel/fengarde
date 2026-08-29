FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
# shared lib + this service
COPY services/shared /app/shared
COPY services/ws1-collectors /app/ws1-collectors
RUN pip install --no-cache-dir --require-hashes -r /app/ws1-collectors/requirements.txt
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
# Security-adversarial #2 (2026-07-29 audit): no service ran as a non-root
# container user. This service parses attacker-controlled network input
# directly (syslog UDP), so it's the highest-value one to drop privileges on.
# The UDP listener already binds 5514, not 514, specifically so root was never
# required (see syslog_udp_server.py's docstring). SYSLOG_SPOOL_PATH (opt-in,
# off by default) must point at a path writable by this uid if enabled.
# uid/gid are PINNED explicitly (not left to groupadd/useradd auto-assignment)
# because infra/docker-compose.yml's ws1-spool-init container chowns the
# named spool volume to these exact numeric ids before this service starts --
# an unpinned gid works by coincidence on whatever this image's build
# happened to auto-assign (cavecrew-reviewer caught this: it had silently
# landed on 999, not because anything guaranteed it) and would silently
# desync from the compose file's hardcoded chown on any base-image or
# package-layering change.
RUN groupadd --system --gid 999 app && useradd --system --gid app --uid 10001 --no-create-home app \
    && chown -R app:app /app
USER app
WORKDIR /app/ws1-collectors
CMD ["python", "main.py"]
