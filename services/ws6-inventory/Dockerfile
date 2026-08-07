FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
# M7 Track Y follow-up: shared lib was originally needed only for
# bus_consumer.py's `shared.bus`/`shared.log` imports, reached only when
# BUS_BACKEND is set (see app.py's __main__). As of Task K (2026-08-07),
# store.py/keystore.py/authz.py also import `shared.log` (structured
# logging replaced their hand-rolled print(json.dumps(...)) warnings) -- so
# the HTTP surface now depends on `shared` unconditionally too. Each of
# those three sets its own `_SERVICES_DIR` sys.path bootstrap (see e.g.
# store.py's header comment) so this remains correct however the module is
# imported, not only under this image's PYTHONPATH=/app.
COPY services/shared /app/shared
COPY services/ws6-inventory /app/ws6-inventory
RUN pip install --no-cache-dir -r /app/ws6-inventory/requirements.txt
ENV PYTHONPATH=/app
ENV INVENTORY_DB=/data/inventory.db
ENV PORT=8000
# Security-adversarial #2 (2026-07-29 audit): drop root before running. /data
# (the SQLite volume) must exist and be owned by the app uid BEFORE the
# VOLUME instruction -- Docker copies an image path's existing content/
# ownership into the volume on first use, so creating it root-owned here
# would leave inventory.db unwritable under USER app.
RUN groupadd --system app && useradd --system --gid app --uid 10001 --no-create-home app \
    && mkdir -p /data && chown -R app:app /app /data
VOLUME ["/data"]
EXPOSE 8000
USER app
WORKDIR /app/ws6-inventory
CMD ["python", "app.py"]
