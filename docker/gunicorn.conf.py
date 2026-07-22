accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '{"event": "request", "method": "%(m)s", "path": "%(U)s", "status": %(s)s, "duration_us": %(D)s, "remote_addr": "%(h)s"}'
import os

workers = int(os.environ.get("WEB_CONCURRENCY", "4"))
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", "2"))
