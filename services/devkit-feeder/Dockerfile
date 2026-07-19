# DX2-live one-shot feeder: injects an SSH brute-force burst into raw.events so a
# fresh `docker compose up` yields a REAL alert with no manual step.
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91
RUN pip install --no-cache-dir redis==5.0.8
WORKDIR /app
COPY services/devkit-feeder/feed.py /app/feed.py
CMD ["python", "feed.py"]
