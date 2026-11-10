"""Génération du flux Atom (RFC 4287) à partir des CVE retenues."""
from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from html import escape

from .items import Item

ATOM_NS = "http://www.w3.org/2005/Atom"
FEED_ID = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "veille-cyber:feed"))


def _entry_id(cve_id: str) -> str:
    # Identifiant stable et déterministe : FreshRSS reconnaît l'entrée d'une exécution à l'autre.
    return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"veille-cyber:{cve_id}"))


def _content_html(item: Item) -> str:
    reasons = "".join(f"<li>{escape(r['detail'])}</li>" for r in item.reasons)
    links = "".join(
        f'<li><a href="{escape(url)}">{escape(name)}</a></li>' for name, url in item.links.items()
    )
    return (f"<p>{escape(item.summary)}</p>"
            f"<p><strong>Pourquoi :</strong></p><ul>{reasons}</ul>"
            f"<p><strong>Liens :</strong></p><ul>{links}</ul>")


def build(items: list[Item], now: str, max_entries: int = 200) -> bytes:
    ET.register_namespace("", ATOM_NS)
    feed = ET.Element(f"{{{ATOM_NS}}}feed")
    ET.SubElement(feed, f"{{{ATOM_NS}}}id").text = FEED_ID
    ET.SubElement(feed, f"{{{ATOM_NS}}}title").text = "veille-cyber — CVE prioritaires"
    ET.SubElement(feed, f"{{{ATOM_NS}}}updated").text = now
    author = ET.SubElement(feed, f"{{{ATOM_NS}}}author")
    ET.SubElement(author, f"{{{ATOM_NS}}}name").text = "veille-cyber"

    recent = sorted(items, key=lambda i: i.updated, reverse=True)[:max_entries]
    for item in recent:
        entry = ET.SubElement(feed, f"{{{ATOM_NS}}}entry")
        ET.SubElement(entry, f"{{{ATOM_NS}}}id").text = _entry_id(item.cve_id)
        ET.SubElement(entry, f"{{{ATOM_NS}}}title").text = item.title
        ET.SubElement(entry, f"{{{ATOM_NS}}}updated").text = item.updated
        ET.SubElement(entry, f"{{{ATOM_NS}}}published").text = item.first_seen
        ET.SubElement(entry, f"{{{ATOM_NS}}}link",
                      href=f"https://nvd.nist.gov/vuln/detail/{item.cve_id}", rel="alternate")
        content = ET.SubElement(entry, f"{{{ATOM_NS}}}content", type="html")
        content.text = _content_html(item)  # ElementTree échappe le HTML, comme l'exige type="html"
    return ET.tostring(feed, encoding="utf-8", xml_declaration=True)
