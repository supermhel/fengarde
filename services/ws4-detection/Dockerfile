FROM python:3.12-slim
WORKDIR /app
COPY services/shared /app/shared
COPY contracts /app/contracts
COPY services/ws4-detection /app/ws4-detection
RUN pip install --no-cache-dir -r /app/ws4-detection/requirements.txt || true
ENV PYTHONPATH=/app
ENV BUS_BACKEND=redis
WORKDIR /app/ws4-detection
CMD ["python", "main.py"]
