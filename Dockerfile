FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    groupadd --gid 10001 app && \
    useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home app && \
    mkdir -p /data && chown 10001:10001 /data && chmod 0700 /data

COPY rxp_decrypt.py ./rxp_decrypt.py
COPY webapp ./webapp
COPY portal ./portal
USER 10001:10001
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health', timeout=2).read()"
CMD ["uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8787", "--no-access-log", "--workers", "1"]
