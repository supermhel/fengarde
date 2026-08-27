# Security-adversarial #2 (2026-07-29 audit): the other 7 service Dockerfiles
# were given a non-root USER; this one is deliberately left as-is. nginx:alpine
# already drops every worker process (the one actually parsing client
# requests) to its own unprivileged built-in "nginx" user -- only the short-
# lived master process stays root, solely to bind port 80 and read config, and
# never touches request data. Forcing the master non-root too would mean
# either binding a port >1024 (a docker-compose.yml port-mapping change) or
# adding a capability, and this environment has no running Docker engine to
# build/verify that change against, so it's deferred rather than shipped
# unverified.
FROM nginx:alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752
# Static single-file dashboard. COPY only what belongs at the web root --
# a COPY-everything-then-denylist drifted twice (the denylist referenced a
# long-gone nginx.conf and left INTERFACE.md/test files live at the web
# root); an allowlist of the exact two needed paths cannot drift. The nginx
# template, tests, and docs live outside the html root by construction.
COPY services/ws7-dashboard/index.html /usr/share/nginx/html/index.html
COPY services/ws7-dashboard/mocks /usr/share/nginx/html/mocks
# Reverse-proxy config: serves the static files AND proxies /api/alerts to
# OpenSearch (same-origin -> no CORS). Lives outside the html root so it is not
# also served as a static file. Shipped as a TEMPLATE under
# /etc/nginx/templates/ -- nginx:alpine's official entrypoint hook renders it
# to conf.d/default.conf at container start via envsubst, substituting only
# vars present in the environment (v0.4 Track S1: ${FENGARDE_API_KEY}).
COPY services/ws7-dashboard/templates/default.conf.template /etc/nginx/templates/default.conf.template
# Placeholder htpasswd so auth_basic_user_file always resolves to a real file
# even when auth is off (S2 override mounts a real one over this path).
RUN touch /etc/nginx/dashboard.htpasswd
# Image-level defaults so envsubst never substitutes an EMPTY value into
# `auth_basic ${DASHBOARD_AUTH_REALM};` (empty -> nginx syntax error, refuses
# to start). docker-compose.yml also sets these explicitly, but the image
# must be self-defaulting for anyone running it outside that compose file.
ENV DASHBOARD_AUTH_REALM=off
ENV FENGARDE_API_KEY=""
# ws3-indexer's triage API port (templates/default.conf.template resolves the
# upstream from this var; a compose override that moves ws3's triage port must
# set the same var here so the dashboard proxy follows it -- gap-hunt #68).
ENV WS3_TRIAGE_PORT=8013
# OpenSearch upstream for /api/alerts (templates/default.conf.template resolves
# it from this var -- R3-#17). Base = the singleton "opensearch" service; the HA
# profile overrides this to a reachable node and puts the dashboard on the ha
# network, so the 502-to-empty-fallback it previously masked is gone.
ENV OPENSEARCH_HOST=opensearch:9200
EXPOSE 80
# DX4: alerts come LIVE from /api/alerts (proxied to OpenSearch). Inventory is
# fetched from WS-6 via window.INVENTORY_API. Both fall back to mocks/mock_data.js.
