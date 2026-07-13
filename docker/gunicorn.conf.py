accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '{"event": "request", "method": "%(m)s", "path": "%(U)s", "status": %(s)s, "duration_us": %(D)s, "remote_addr": "%(h)s"}'
