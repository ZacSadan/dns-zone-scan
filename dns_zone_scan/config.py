"""Optional scan settings from input/config.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml

CONFIG_NAMES = ("config.yaml", "config.yml")
DEFAULTS = {"tcp_ports": []}


def is_config_file(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES


def find_config(input_dir: Path) -> Path | None:
    for name in CONFIG_NAMES:
        if (input_dir / name).is_file():
            return input_dir / name
    return None


def load_config(path: Path | None) -> dict:
    cfg = dict(DEFAULTS)
    if path is None:
        return cfg
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    cfg.update(data)
    cfg["tcp_ports"] = parse_ports(cfg.get("tcp_ports"), path)
    return cfg


def parse_ports(value, path: Path | None = None) -> list[int]:
    """Extra TCP ports to probe on every IP, besides the always-probed 80 and 443."""
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    ports = []
    for p in value:
        try:
            port = int(p)
        except (TypeError, ValueError):
            raise ValueError(f"{path or 'config'}: tcp_ports: {p!r} is not a port number") from None
        if not 1 <= port <= 65535:
            raise ValueError(f"{path or 'config'}: tcp_ports: {port} is out of range 1-65535")
        if port not in (80, 443) and port not in ports:
            ports.append(port)
    return ports
