"""Modèle d'une CVE retenue et fusion avec l'état existant."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Item:
    cve_id: str
    title: str
    summary: str = ""
    # Chaque raison : {"source": "kev", "detail": "..."} ; sert aussi à dédoublonner.
    reasons: list[dict[str, str]] = field(default_factory=list)
    links: dict[str, str] = field(default_factory=dict)
    first_seen: str = ""
    updated: str = ""


def merge(store: dict[str, Item], new_items: list[Item], now: str) -> int:
    """Fusionne new_items dans store. Retourne le nombre d'items créés ou modifiés."""
    changed = 0
    for item in new_items:
        current = store.get(item.cve_id)
        if current is None:
            item.first_seen = item.updated = now
            store[item.cve_id] = item
            changed += 1
            continue
        added = [r for r in item.reasons if r not in current.reasons]
        if added:
            current.reasons.extend(added)
            current.links.update(item.links)
            current.updated = now
            changed += 1
    return changed
