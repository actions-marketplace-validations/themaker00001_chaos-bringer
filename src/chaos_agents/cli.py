from __future__ import annotations

import argparse
import sys

from chaos_agents import registry, report
from chaos_agents.campaign import Campaign, CampaignError
from chaos_agents.corpus import Corpus
from chaos_agents.orchestrator import run_campaign


def _load_valid_campaign(path: str) -> Campaign:
    """Parse and fully validate a campaign before anything runs. Raises
    CampaignError with an actionable message."""
    campaign = Campaign.from_yaml(path)
    campaign.check_plugins()
    return campaign


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        campaign = _load_valid_campaign(args.campaign)
    except CampaignError as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 2
    tags = f" [{campaign.category}/{campaign.technique}]" if campaign.category else ""
    print(f"ok: {campaign.name}{tags}  "
          f"adapter={campaign.adapter.plugin} vector={campaign.vector.plugin} judge={campaign.judge.plugin}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        campaign = _load_valid_campaign(args.campaign)
    except CampaignError as exc:
        print(f"invalid campaign: {exc}", file=sys.stderr)
        return 2
    corpus = Corpus(campaign.name, root=args.runs_dir)

    if args.fancy:
        from rich.console import Console

        from chaos_agents import report_rich

        console = Console()
        with report_rich.NergalStatus(console, mascot=not args.no_mascot, campaign=campaign) as status:
            records = run_campaign(campaign, corpus, on_step=status.thinking, on_result=status.result)
            status.done(records)
        report_rich.render(campaign.name, records)
        if args.svg:
            report_rich.render_svg(campaign.name, records, args.svg)
            print(f"\nSVG written to: {args.svg}")
    else:
        records = run_campaign(campaign, corpus)
        print(report.render(campaign.name, records))

    print(f"Full trace: {corpus.results_path}")
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
    run_p.add_argument("--fancy", action="store_true", help="render with rich (requires: pip install chaos-agents[rich])")
    run_p.add_argument("--svg", metavar="PATH", help="also save the --fancy report as a terminal-styled SVG")
    run_p.add_argument("--no-mascot", action="store_true", help="with --fancy, skip the animated Nergal and show only the status line")
    run_p.set_defaults(func=_cmd_run)

    validate_p = sub.add_parser("validate", help="check a campaign file without running it")
    validate_p.add_argument("campaign", help="path to a campaign YAML file")
    validate_p.set_defaults(func=_cmd_validate)

    plugins_p = sub.add_parser("plugins", help="list installed plugins by surface")
    plugins_p.set_defaults(func=_cmd_plugins)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
