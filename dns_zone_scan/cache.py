"""Tiny JSON file cache (gitignored .cache/ folder) to keep reruns fast and polite."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

CACHE_DIR = Path(".cache")
DEFAULT_TTL = 24 * 3600


def _path(key: str) -> Path:
    h = hashlib.sha1(key.encode()).hexdigest()[:16]
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)[:60]
    return CACHE_DIR / f"{safe}.{h}.json"


def get(key: str, ttl: int = DEFAULT_TTL):
    p = _path(key)
    try:
        if time.time() - p.stat().st_mtime > ttl:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def put(key: str, value) -> None:
    try:
        CACHE_DIR.mkdir(exist_ok=True)
        _path(key).write_text(json.dumps(value), encoding="utf-8")
    except OSError:
        pass
