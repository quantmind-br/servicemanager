FROM python:3.12-slim AS build

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
RUN pip install --no-cache-dir uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY service_manager ./service_manager
COPY templates ./templates
COPY static ./static
COPY scripts ./scripts
COPY app.py wsgi.py ./
RUN uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    DATABASE_PATH=/data/service-manager.db \
    TRUSTED_PROXY_HOPS=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y nginx \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 servicemanager \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin servicemanager \
    && mkdir -p /app /data /backups /tmp/nginx/client_temp /tmp/nginx/proxy_temp /tmp/nginx/fastcgi_temp /tmp/nginx/uwsgi_temp /tmp/nginx/scgi_temp /var/cache/nginx \
    && chown -R 10001:10001 /app /data /backups /tmp/nginx /var/cache/nginx \
    && chmod 0700 /data /backups /tmp/nginx /var/cache/nginx

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY --chown=10001:10001 service_manager ./service_manager
COPY --chown=10001:10001 docker/gunicorn.conf.py /app/gunicorn.conf.py
COPY --chown=10001:10001 templates ./templates
COPY --chown=10001:10001 static ./static
COPY --chown=10001:10001 scripts ./scripts
COPY --chown=10001:10001 app.py wsgi.py ./
COPY --chown=10001:10001 docker/nginx.conf /etc/nginx/nginx.conf
COPY --chown=10001:10001 docker/entrypoint.sh /app/docker-entrypoint.sh
COPY --chown=10001:10001 docker/supervisor.py /app/docker-supervisor.py
RUN chmod 0755 /app/docker-entrypoint.sh /app/docker-supervisor.py

VOLUME ["/data", "/backups"]
EXPOSE 8000
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD python -c "from urllib.request import urlopen; response = urlopen('http://127.0.0.1:8000/healthz', timeout=3); raise SystemExit(response.status != 200)"
ENTRYPOINT ["/app/docker-entrypoint.sh"]
