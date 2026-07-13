from __future__ import annotations

import os
import shlex
import signal
import subprocess
import threading
import sys
import time
from urllib.request import urlopen


def _test_hooks_enabled() -> bool:
    return os.environ.get("SERVICE_MANAGER_TEST_HOOKS") == "1"


def _command(name: str, default: list[str]) -> list[str]:
    configured = os.environ.get(name) if _test_hooks_enabled() else None
    return shlex.split(configured) if configured else default


def _terminate(processes: list[subprocess.Popen[object]]) -> None:
    def _signal(process: subprocess.Popen[object], send: object) -> None:
        try:
            send()
        except (OSError, ValueError):
            pass

    for process in processes:
        if process.poll() is None:
            _signal(process, process.terminate)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and any(process.poll() is None for process in processes):
        time.sleep(0.1)
    for process in processes:
        if process.poll() is None:
            _signal(process, process.kill)
    for process in processes:
        try:
            process.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass


def _wait_for_gunicorn(gunicorn: subprocess.Popen[object], should_stop: threading.Event) -> bool:
    health_url = os.environ.get("SERVICE_MANAGER_HEALTH_URL", "http://127.0.0.1:8001/healthz") if _test_hooks_enabled() else "http://127.0.0.1:8001/healthz"
    for _ in range(30):
        if should_stop.is_set():
            return False
        if gunicorn.poll() is not None:
            raise RuntimeError("gunicorn exited before health check")
        try:
            with urlopen(health_url, timeout=1) as response:
                if response.status == 200:
                    return True
        except OSError:
            pass
        if should_stop.wait(1):
            return False
    raise RuntimeError("gunicorn health check timed out")


def main() -> int:
    should_stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: should_stop.set())
    signal.signal(signal.SIGINT, lambda *_: should_stop.set())

    processes: list[subprocess.Popen[object]] = []
    try:
        gunicorn = subprocess.Popen(
            _command(
                "SERVICE_MANAGER_GUNICORN_CMD",
                ["gunicorn", "--config", "/app/gunicorn.conf.py", "--bind", "127.0.0.1:8001", "--workers", "2", "wsgi:app"],
            )
        )
        processes.append(gunicorn)
        if not _wait_for_gunicorn(gunicorn, should_stop):
            return 0
        config_test = _command("SERVICE_MANAGER_NGINX_TEST_CMD", ["nginx", "-t"])
        if subprocess.run(config_test, capture_output=True).returncode != 0:
            raise RuntimeError("nginx configuration test failed")
        nginx = subprocess.Popen(_command("SERVICE_MANAGER_NGINX_CMD", ["nginx", "-g", "daemon off;"]))
        processes.append(nginx)
        while not should_stop.is_set():
            for process in processes:
                code = process.poll()
                if code is not None:
                    return code if code != 0 else 1
            should_stop.wait(0.2)
        return 0
    except (RuntimeError, OSError):
        print("ERROR: service supervisor failed to run the process group", file=sys.stderr)
        return 1
    finally:
        _terminate(processes)


if __name__ == "__main__":
    raise SystemExit(main())
