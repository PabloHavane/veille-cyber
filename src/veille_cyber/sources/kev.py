"""Source CISA KEV : CVE ajoutées au catalogue depuis une date donnée."""
from __future__ import annotations

import json
import urllib.request
from datetime import date

from ..items import Item

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(url: str = KEV_URL, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "veille-cyber"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def select(catalog: dict, since: date) -> list[Item]:
    """Retourne les entrées dont dateAdded >= since."""
    items = []
    for v in catalog.get("vulnerabilities", []):
        added = date.fromisoformat(v["dateAdded"])
        if added < since:
            continue
        detail = f"ajoutée au KEV le {v['dateAdded']}"
        if v.get("knownRansomwareCampaignUse") == "Known":
            detail += " (utilisée par des rançongiciels)"
        items.append(Item(
            cve_id=v["cveID"],
            title=f"{v['cveID']} — {v['vendorProject']} {v['product']}",
            summary=v.get("shortDescription", ""),
            reasons=[{"source": "kev", "detail": detail}],
            links={"KEV": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={v['cveID']}"},
        ))
    return items
