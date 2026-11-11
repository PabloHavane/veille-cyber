"""Modèle d'une CVE retenue, fusion avec l'état existant et purge."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Item:
    cve_id: str
    title: str
    summary: str = ""
    # Chaque raison : {"source": "kev", "detail": "..."} ; au plus une raison par source.
    reasons: list[dict[str, str]] = field(default_factory=list)
    links: dict[str, str] = field(default_factory=dict)
    first_seen: str = ""
    updated: str = ""


def _upsert_reasons(current: list[dict[str, str]], new: list[dict[str, str]]) -> bool:
    """Ajoute ou remplace les raisons de current, une par source. Retourne True si modifié."""
    changed = False
    for reason in new:
        idx = next((i for i, r in enumerate(current) if r["source"] == reason["source"]), None)
        if idx is None:
            current.append(reason)
            changed = True
        elif current[idx] != reason:
            current[idx] = reason  # ex. statut « rançongiciel » passé à Known
            changed = True
    return changed


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
        if _upsert_reasons(current.reasons, item.reasons):
            current.links.update(item.links)
            current.updated = now
            changed += 1
    return changed


def prune(store: dict[str, Item], cutoff: datetime) -> int:
    """Supprime les items non modifiés depuis cutoff (datetime aware). Retourne le nombre supprimé."""
    stale = [k for k, item in store.items()
             if item.updated and datetime.fromisoformat(item.updated) < cutoff]
    for k in stale:
        del store[k]
    return len(stale)
