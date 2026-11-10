"""Source CISA KEV : CVE ajoutées au catalogue depuis une date donnée."""
from __future__ import annotations

import json
import logging
import urllib.request
from collections.abc import Collection
from datetime import date

from ..items import Item

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

log = logging.getLogger(__name__)


def fetch(url: str = KEV_URL, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "veille-cyber"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _to_item(v: dict) -> tuple[date, Item]:
    """Convertit une entrée du catalogue. Lève KeyError/TypeError/ValueError si elle est mal formée."""
    cve_id = v["cveID"]
    added = date.fromisoformat(v["dateAdded"])
    detail = f"ajoutée au KEV le {added.isoformat()}"
    if v.get("knownRansomwareCampaignUse") == "Known":
        detail += " (utilisée par des rançongiciels)"
    return added, Item(
        cve_id=cve_id,
        title=f"{cve_id} — {v['vendorProject']} {v['product']}",
        summary=v.get("shortDescription", ""),
        reasons=[{"source": "kev", "detail": detail}],
        links={"KEV": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}"},
    )


def select(catalog: dict, since: date, known: Collection[str] = ()) -> list[Item]:
    """Retourne les entrées dont dateAdded >= since, plus celles déjà suivies (known),
    pour que merge() voie les changements sur des CVE plus anciennes que la fenêtre."""
    vulns = catalog.get("vulnerabilities") if isinstance(catalog, dict) else None
    if not isinstance(vulns, list):
        # Format inattendu : on échoue pour ne pas faire avancer l'état sur un catalogue vide.
        raise ValueError("catalogue KEV invalide : clé 'vulnerabilities' absente ou mal typée")

    items, skipped = [], 0
    for v in vulns:
        try:
            added, item = _to_item(v)
        except (KeyError, TypeError, ValueError) as exc:
            skipped += 1
            cve = v.get("cveID", "?") if isinstance(v, dict) else "?"
            log.warning("entrée KEV ignorée (%s) : %s: %s", cve, type(exc).__name__, exc)
            continue
        if added >= since or item.cve_id in known:
            items.append(item)
    if skipped:
        log.warning("%d entrée(s) KEV mal formée(s) ignorée(s) sur %d", skipped, len(vulns))
    return items
