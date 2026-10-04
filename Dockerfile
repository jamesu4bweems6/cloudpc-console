FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    CLOUDPC_DATA_DIR=/data
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN groupadd --gid 10001 cloudpc \
    && useradd --uid 10001 --gid cloudpc --no-create-home cloudpc \
    && mkdir -p /data/live \
    && chown -R cloudpc:cloudpc /data
COPY cloudpc_protocol.py connect_once.py zte_connection.py zte_gateway_probe.py live_validate.py keepalive_loop.py sample-profile.json zte-sample-profile.json ./
COPY web/server.py web/index.html web/app.js web/style.css ./web/
USER 10001:10001
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=3).read()"
CMD ["python", "-X", "utf8", "web/server.py", "--bind", "0.0.0.0", "--port", "8765"]
