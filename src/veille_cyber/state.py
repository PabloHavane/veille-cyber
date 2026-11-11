"""Lecture/écriture de l'état : dernière exécution réussie et CVE retenues."""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

from .items import Item

STATE_VERSION = 1


def load(path: Path) -> tuple[str | None, dict[str, Item]]:
    if not path.exists():
        return None, {}
    data = json.loads(path.read_text(encoding="utf-8"))
    version = data.get("version")
    if version != STATE_VERSION:
        # On refuse plutôt que d'écraser un état qu'on ne sait pas lire.
        raise ValueError(f"{path} : version d'état {version!r} non prise en charge "
                         f"(attendue : {STATE_VERSION})")
    items = {k: Item(**v) for k, v in data.get("items", {}).items()}
    return data.get("last_success"), items


def save(path: Path, last_success: str, items: dict[str, Item]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": STATE_VERSION,
        "last_success": last_success,
        "items": {k: asdict(v) for k, v in sorted(items.items())},
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # écriture atomique : pas d'état à moitié écrit
    