FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py mikrotik.py storage.py wireguard.py bot.py ./

RUN groupadd -r appuser && useradd -r -g appuser appuser \
    && mkdir -p /data && chown appuser:appuser /data

ENV DB_PATH=/data/bot.db \
    LOG_LEVEL=INFO

VOLUME ["/data"]

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:80/health')" || exit 0

CMD ["python", "bot.py"]
