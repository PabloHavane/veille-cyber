"""Point d'entrée : python -m veille_cyber run"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import feed, state
from .items import merge, prune
from .sources import kev

DEFAULT_DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "veille-cyber"


def run(args: argparse.Namespace) -> int:
    now_dt = datetime.now(timezone.utc).replace(microsecond=0)
    now = now_dt.isoformat().replace("+00:00", "Z")
    state_path = args.data_dir / "state.json"
    feed_path = args.data_dir / "feed" / "feed.xml"

    last_success, items = state.load(state_path)
    since_dt = (datetime.fromisoformat(last_success.replace("Z", "+00:00"))
                if last_success else now_dt - timedelta(days=args.initial_days))
    since = since_dt.date()

    catalog = (json.loads(args.kev_file.read_text(encoding="utf-8"))
               if args.kev_file else kev.fetch())
    changed = merge(items, kev.select(catalog, since, known=items.keys()), now)
    pruned = (prune(items, now_dt - timedelta(days=args.retention_days))
              if args.retention_days > 0 else 0)

    feed_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = feed_path.with_suffix(".xml.tmp")
    tmp.write_bytes(feed.build(list(items.values()), now, args.max_entries))
    os.replace(tmp, feed_path)
    state.save(state_path, now, items)  # en dernier : l'état n'avance que si tout a réussi
    print(f"{changed} CVE nouvelles ou mises à jour depuis {since}, {pruned} purgée(s) ; "
          f"flux : {feed_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veille_cyber")
    sub = parser.add_subparsers(dest="command", required=True)
    p_run = sub.add_parser("run", help="collecte, sélection et génération du flux")
    p_run.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    p_run.add_argument("--initial-days", type=int, default=7,
                       help="fenêtre de la toute première exécution (jours)")
    p_run.add_argument("--max-entries", type=int, default=200)
    p_run.add_argument("--retention-days", type=int, default=90,
                       help="purge de l'état les CVE non modifiées depuis N jours (0 = jamais)")
    p_run.add_argument("--kev-file", type=Path, help="catalogue KEV local (hors ligne)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
