import json
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

from veille_cyber import feed, state
from veille_cyber.__main__ import main
from veille_cyber.items import merge
from veille_cyber.sources import kev

FIXTURE = Path(__file__).parent / "fixtures" / "kev_sample.json"
ATOM = "{http://www.w3.org/2005/Atom}"


def load_catalog():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_kev_select_respects_window():
    items = kev.select(load_catalog(), since=date(2026, 11, 1))
    assert [i.cve_id for i in items] == ["CVE-2026-0003", "CVE-2026-0002"]


def test_kev_flags_ransomware():
    items = kev.select(load_catalog(), since=date(2026, 11, 3))
    assert "rançongiciels" in items[0].reasons[0]["detail"]


def test_merge_is_idempotent():
    store = {}
    assert merge(store, kev.select(load_catalog(), date(2026, 11, 1)), "2026-11-04T07:00:00Z") == 2
    # Même données au run suivant : rien de nouveau, updated inchangé.
    assert merge(store, kev.select(load_catalog(), date(2026, 11, 1)), "2026-11-05T07:00:00Z") == 0
    assert store["CVE-2026-0003"].updated == "2026-11-04T07:00:00Z"


def test_feed_is_valid_atom_with_stable_ids():
    store = {}
    merge(store, kev.select(load_catalog(), date(2026, 11, 1)), "2026-11-04T07:00:00Z")
    root = ET.fromstring(feed.build(list(store.values()), "2026-11-04T07:00:00Z"))
    assert root.tag == f"{ATOM}feed"
    for tag in ("id", "title", "updated"):
        assert len(root.findall(f"{ATOM}{tag}")) == 1
    entries = root.findall(f"{ATOM}entry")
    assert len(entries) == 2
    for e in entries:
        for tag in ("id", "title", "updated"):
            assert len(e.findall(f"{ATOM}{tag}")) == 1
    ids_1 = [e.find(f"{ATOM}id").text for e in entries]
    root2 = ET.fromstring(feed.build(list(store.values()), "2026-11-05T07:00:00Z"))
    assert ids_1 == [e.find(f"{ATOM}id").text for e in root2.findall(f"{ATOM}entry")]


def test_cli_run_offline_writes_feed_and_state(tmp_path):
    rc = main(["run", "--data-dir", str(tmp_path), "--kev-file", str(FIXTURE),
               "--initial-days", "100000"])
    assert rc == 0
    assert (tmp_path / "feed" / "feed.xml").exists()
    last_success, items = state.load(tmp_path / "state.json")
    assert last_success is not None
    assert set(items) == {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}
    