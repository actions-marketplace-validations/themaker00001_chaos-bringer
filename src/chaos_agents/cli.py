from __future__ import annotations

import argparse
import sys

from chaos_agents import registry, report
from chaos_agents.campaign import Campaign
from chaos_agents.corpus import Corpus
from chaos_agents.orchestrator import run_campaign


def _cmd_run(args: argparse.Namespace) -> int:
    campaign = Campaign.from_yaml(args.campaign)
    corpus = Corpus(campaign.name, root=args.runs_dir)
    records = run_campaign(campaign, corpus)
    print(report.render(campaign.name, records))
    print(f"\nFull trace: {corpus.results_path}")
    return 1 if any(not r.passed for r in records) else 0


def _cmd_plugins(args: argparse.Namespace) -> int:
    for group in ("providers", "adapters", "vectors", "judges"):
        names = registry.available(f"chaos_agents.{group}")
        print(f"{group}:")
        for name, target in sorted(names.items()):
            print(f"  {name:<16} {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chaos-agents")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run a campaign against its target")
    run_p.add_argument("campaign", help="path to a campaign YAML file")
    run_p.add_argument("--runs-dir", default="runs", help="where to write the corpus (default: ./runs)")
    run_p.set_defaults(func=_cmd_run)

    plugins_p = sub.add_parser("plugins", help="list installed plugins by surface")
    plugins_p.set_defaults(func=_cmd_plugins)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
