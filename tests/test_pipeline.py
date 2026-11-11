import argparse
import json
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from veille_cyber import feed, state
from veille_cyber.__main__ import loop, main
from veille_cyber.items import Item, merge, prune
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


def test_kev_skips_malformed_entries(caplog):
    catalog = load_catalog()
    catalog["vulnerabilities"].append({"cveID": "CVE-2026-9999", "dateAdded": "pas-une-date"})
    catalog["vulnerabilities"].append({"dateAdded": "2026-11-05"})  # cveID manquant
    items = kev.select(catalog, since=date(2026, 11, 1))
    assert [i.cve_id for i in items] == ["CVE-2026-0003", "CVE-2026-0002"]
    assert "CVE-2026-9999" in caplog.text
    assert "2 entrée(s) KEV mal formée(s)" in caplog.text


@pytest.mark.parametrize("catalog", [{}, {"vulnerabilities": None}, []])
def test_kev_rejects_invalid_catalog(catalog):
    with pytest.raises(ValueError):
        kev.select(catalog, since=date(2026, 11, 1))


def test_kev_includes_known_cves_outside_window():
    items = kev.select(load_catalog(), since=date(2026, 11, 3), known={"CVE-2026-0001"})
    assert [i.cve_id for i in items] == ["CVE-2026-0003", "CVE-2026-0001"]


def test_merge_updates_reason_instead_of_duplicating():
    store = {}
    catalog = load_catalog()
    merge(store, kev.select(catalog, date(2026, 11, 1)), "2026-11-04T07:00:00Z")
    catalog["vulnerabilities"][1]["knownRansomwareCampaignUse"] = "Known"  # CVE-2026-0002
    assert merge(store, kev.select(catalog, date(2026, 11, 1)), "2026-11-05T07:00:00Z") == 1
    reasons = store["CVE-2026-0002"].reasons
    assert len(reasons) == 1
    assert "rançongiciels" in reasons[0]["detail"]
    assert store["CVE-2026-0002"].updated == "2026-11-05T07:00:00Z"


def test_state_rejects_unknown_version(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"version": 99, "items": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="version"):
        state.load(path)


def test_prune_removes_stale_items():
    store = {
        "CVE-OLD": Item("CVE-OLD", "old", updated="2026-01-01T00:00:00Z"),
        "CVE-NEW": Item("CVE-NEW", "new", updated="2026-11-01T00:00:00Z"),
    }
    assert prune(store, datetime(2026, 6, 1, tzinfo=timezone.utc)) == 1
    assert set(store) == {"CVE-NEW"}


def test_cli_run_prunes_state(tmp_path):
    old = Item("CVE-2020-0001", "ancienne", reasons=[{"source": "kev", "detail": "x"}],
               first_seen="2020-01-01T00:00:00Z", updated="2020-01-01T00:00:00Z")
    state.save(tmp_path / "state.json", "2026-11-03T00:00:00Z", {old.cve_id: old})
    assert main(["run", "--data-dir", str(tmp_path), "--kev-file", str(FIXTURE)]) == 0
    _, items = state.load(tmp_path / "state.json")
    assert "CVE-2020-0001" not in items
    assert "CVE-2026-0003" in items


class StopLoop:
    """Faux sleep : enregistre les délais et interrompt la boucle après n appels."""

    def __init__(self, n):
        self.n, self.delays = n, []

    def __call__(self, delay):
        self.delays.append(delay)
        if len(self.delays) >= self.n:
            raise KeyboardInterrupt


def loop_args(tmp_path, kev_file, **overrides):
    args = argparse.Namespace(data_dir=tmp_path, initial_days=100000, max_entries=200,
                              retention_days=90, kev_file=kev_file,
                              interval_hours=6, retry_minutes=30)
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def test_loop_runs_then_waits_interval(tmp_path):
    sleep = StopLoop(2)
    assert loop(loop_args(tmp_path, FIXTURE), sleep=sleep) == 0
    assert sleep.delays == [6 * 3600, 6 * 3600]
    assert (tmp_path / "feed" / "feed.xml").exists()


def test_loop_survives_failure_and_retries_sooner(tmp_path, caplog):
    sleep = StopLoop(2)
    bad = tmp_path / "absent.json"
    assert loop(loop_args(tmp_path, bad), sleep=sleep) == 0
    assert sleep.delays == [30 * 60, 30 * 60]
    assert "échec de la collecte" in caplog.text
    assert not (tmp_path / "state.json").exists()


def test_loop_retry_never_exceeds_interval(tmp_path):
    sleep = StopLoop(1)
    loop(loop_args(tmp_path, tmp_path / "absent.json", interval_hours=0.25), sleep=sleep)
    assert sleep.delays == [0.25 * 3600]


@pytest.mark.parametrize("value", ["0", "-1"])
def test_cli_loop_rejects_non_positive_interval(value):
    with pytest.raises(SystemExit):
        main(["loop", "--interval-hours", value])
