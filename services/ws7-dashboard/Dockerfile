FROM nginx:alpine
# Static single-file dashboard.
COPY services/ws7-dashboard /usr/share/nginx/html
# Reverse-proxy config: serves the static files AND proxies /api/alerts to
# OpenSearch (same-origin -> no CORS). Lives outside the html root so it is not
# also served as a static file. Shipped as a TEMPLATE under
# /etc/nginx/templates/ -- nginx:alpine's official entrypoint hook renders it
# to conf.d/default.conf at container start via envsubst, substituting only
# vars present in the environment (v0.4 Track S1: ${ARGIEM_API_KEY}).
RUN rm -f /usr/share/nginx/html/nginx.conf /usr/share/nginx/html/Dockerfile \
    /usr/share/nginx/html/templates/default.conf.template
COPY services/ws7-dashboard/templates/default.conf.template /etc/nginx/templates/default.conf.template
# Placeholder htpasswd so auth_basic_user_file always resolves to a real file
# even when auth is off (S2 override mounts a real one over this path).
RUN touch /etc/nginx/dashboard.htpasswd
# Image-level defaults so envsubst never substitutes an EMPTY value into
# `auth_basic ${DASHBOARD_AUTH_REALM};` (empty -> nginx syntax error, refuses
# to start). docker-compose.yml also sets these explicitly, but the image
# must be self-defaulting for anyone running it outside that compose file.
ENV DASHBOARD_AUTH_REALM=off
ENV ARGIEM_API_KEY=""
EXPOSE 80
# DX4: alerts come LIVE from /api/alerts (proxied to OpenSearch). Inventory is
# fetched from WS-6 via window.INVENTORY_API. Both fall back to mocks/mock_data.js.
