"""
src/services/persistence.py

AlertRepository — Single Responsibility: owns alert storage / retrieval.

Extracted from app.py's global `alert_buffer` list and free-floating
save_alerts / load_alerts functions.  A class-based repository makes
the persistence contract explicit and mockable in tests.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from src import config

logger = logging.getLogger(__name__)

_MAX_ALERTS = 50


class AlertRepository:
    """Thread-safe, file-backed ring buffer for recent alerts."""

    def __init__(self, persistence_file: Path | None = None) -> None:
        self._file = persistence_file or (config.LOGS_DIR / "alerts_persistence.json")
        self._alerts: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def push(self, alert: dict[str, Any]) -> None:
        """Prepend a new alert and cap the buffer at _MAX_ALERTS."""
        with self._lock:
            self._alerts.insert(0, alert)
            if len(self._alerts) > _MAX_ALERTS:
                self._alerts.pop()
        self._save()

    def get_all(self) -> list[dict[str, Any]]:
        """Return a shallow copy of the current alert buffer."""
        with self._lock:
            return list(self._alerts)

    def load(self) -> None:
        """Restore buffer from disk on startup."""
        if not self._file.exists():
            return
        try:
            with open(self._file, "r") as fh:
                data = json.load(fh)
            with self._lock:
                self._alerts = data if isinstance(data, list) else []
            logger.info(f"✓ Loaded {len(self._alerts)} alerts from persistence layer")
        except Exception as exc:
            logger.warning(f"Could not load alerts from {self._file}: {exc}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _save(self) -> None:
        try:
            with self._lock:
                snapshot = list(self._alerts)
            with open(self._file, "w") as fh:
                json.dump(snapshot, fh, indent=2)
        except Exception as exc:
            logger.warning(f"Could not persist alerts: {exc}")


# Module-level singleton
alert_repo = AlertRepository()
