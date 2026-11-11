"""Point d'entrée : python -m veille_cyber run | loop"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import feed, state
from .items import merge, prune
from .sources import kev

DEFAULT_DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "veille-cyber"

log = logging.getLogger("veille_cyber")


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


def loop(args: argparse.Namespace, sleep: Callable[[float], None] = time.sleep) -> int:
    """Exécute run() indéfiniment : un premier run immédiat, puis toutes les interval_hours.
    Un échec est journalisé puis retenté après retry_minutes, sans arrêter la boucle."""
    interval = args.interval_hours * 3600
    retry = min(args.retry_minutes * 60, interval)
    log.info("collecte automatique toutes les %g h (nouvel essai %g min après un échec)",
             args.interval_hours, retry / 60)
    try:
        while True:
            try:
                run(args)
                delay = interval
            except Exception:
                log.exception("échec de la collecte, nouvel essai dans %g min", retry / 60)
                delay = retry
            sleep(delay)
    except KeyboardInterrupt:  # SIGINT : signal d'arrêt du conteneur (stop_signal)
        log.info("arrêt demandé")
        return 0


def _positive(cast: Callable[[str], float]) -> Callable[[str], float]:
    def parse(value: str) -> float:
        number = cast(value)
        if number <= 0:
            raise argparse.ArgumentTypeError(f"doit être strictement positif : {value}")
        return number
    return parse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veille_cyber")
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    common.add_argument("--initial-days", type=int, default=7,
                        help="fenêtre de la toute première exécution (jours)")
    common.add_argument("--max-entries", type=int, default=200)
    common.add_argument("--retention-days", type=int, default=90,
                        help="purge de l'état les CVE non modifiées depuis N jours (0 = jamais)")
    common.add_argument("--kev-file", type=Path, help="catalogue KEV local (hors ligne)")
    sub.add_parser("run", parents=[common], help="collecte, sélection et génération du flux")
    p_loop = sub.add_parser("loop", parents=[common], help="exécute run à intervalle régulier")
    p_loop.add_argument("--interval-hours", type=_positive(float), default=6,
                        help="intervalle entre deux collectes réussies (heures)")
    p_loop.add_argument("--retry-minutes", type=_positive(float), default=30,
                        help="délai avant un nouvel essai après un échec (minutes)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return loop(args) if args.command == "loop" else run(args)


if __name__ == "__main__":
    sys.exit(main())
