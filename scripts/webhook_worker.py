"""Standalone supervised webhook delivery worker.

Loads configuration from the environment, installs SIGTERM/SIGINT handlers
that request a graceful shutdown, and runs the delivery loop with production
defaults (no resolver or connection-factory overrides).
"""

from __future__ import annotations

import os
import signal
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service_manager.webhooks import run_worker


def main() -> int:
    database_path = os.environ.get("DATABASE_PATH")
    data_key_b64 = os.environ.get("DATA_KEY_V1")
    public_origin = os.environ.get("PUBLIC_ORIGIN", "")

    if not database_path:
        print("DATABASE_PATH is required", file=sys.stderr)
        return 2
    if not data_key_b64:
        print("DATA_KEY_V1 is required", file=sys.stderr)
        return 2

    stop_event = threading.Event()

    def _handle_signal(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    run_worker(database_path, data_key_b64, public_origin, stop_event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
