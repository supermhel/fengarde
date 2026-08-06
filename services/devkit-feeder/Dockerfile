# DX2-live one-shot feeder: injects an SSH brute-force burst into raw.events so a
# fresh `docker compose up` yields a REAL alert with no manual step.
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91
# H9 supply-chain: install redis via requirements.txt (pinned redis==8.1.0) so
# pip-audit / SBOM can see it -- the old inline `pip install redis==5.0.8` escaped
# both (and was version-skewed vs the 8.1.0 used elsewhere).
COPY services/devkit-feeder/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
WORKDIR /app
COPY services/devkit-feeder/feed.py /app/feed.py
# Security-adversarial #2 (2026-07-29 audit): drop root before running.
RUN groupadd --system app && useradd --system --gid app --uid 10001 --no-create-home app \
    && chown -R app:app /app
USER app
CMD ["python", "feed.py"]
