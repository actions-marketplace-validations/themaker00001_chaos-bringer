from __future__ import annotations

import argparse
import sys
from pathlib import Path

from chaos_agents import attackgraph, registry, report
from chaos_agents.campaign import Campaign, CampaignError
from chaos_agents.corpus import Corpus
from chaos_agents.interfaces import FAIL
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
    if campaign.policy:
        n = len(campaign.policy.capabilities)
        print(f"policy: {n} capabilit{'y' if n == 1 else 'ies'}, default {campaign.policy.default}")
    return 0


def _print_graphs(records, style: str) -> None:
    """The attack graph of every confirmed finding, boxed or as Mermaid."""
    render = attackgraph.to_mermaid if style == "mermaid" else attackgraph.render_box
    graphs = [g for g in (render(r) for r in records) if g]
    for graph in graphs:
        print("\n" + graph)


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        campaign = _load_valid_campaign(args.campaign)
    except CampaignError as exc:
        print(f"invalid campaign: {exc}", file=sys.stderr)
        return 2
    corpus = Corpus(campaign.name, root=args.runs_dir)
    fmt = args.format

    if args.fancy and fmt == "terminal":
        from rich.console import Console

        from chaos_agents import report_rich

        console = Console()
        try:
            with report_rich.NergalStatus(console, mascot=not args.no_mascot, campaign=campaign) as status:
                records = run_campaign(campaign, corpus, on_step=status.thinking, on_result=status.result)
                status.done(records)
        except CampaignError as exc:
            print(f"invalid campaign: {exc}", file=sys.stderr)
            return 2
        report_rich.render(campaign.name, records)
        if args.svg:
            report_rich.render_svg(campaign.name, records, args.svg)
            print(f"\nSVG written to: {args.svg}")
    else:
        try:
            records = run_campaign(campaign, corpus)
        except CampaignError as exc:
            print(f"invalid campaign: {exc}", file=sys.stderr)
            return 2
        if fmt == "terminal":
            print(report.render(campaign.name, records))

    if args.graph and fmt == "terminal":
        _print_graphs(records, args.graph)

    if fmt != "terminal":
        from chaos_agents import export

        rendered = export.FORMATS[fmt](campaign.name, records, run_id=corpus.run_id)
        if args.output:
            Path(args.output).write_text(rendered)
            print(f"{fmt} written to: {args.output}", file=sys.stderr)
        else:
            print(rendered)

    if args.promote:
        from chaos_agents import regression

        promoted = 0
        for r in records:
            if r.status == FAIL:
                regression.promote(r, campaign, args.promote, do_minimize=args.minimize)
                promoted += 1
        print(f"promoted {promoted} finding(s) to {args.promote}", file=sys.stderr)

    print(f"Full trace: {corpus.results_path}", file=sys.stderr)
    # exit non-zero only for a confirmed finding -- not for inconclusive/errored trials
    return 1 if any(r.status == FAIL for r in records) else 0


def _bench_progress(total: int):
    """A minimal carriage-return progress bar on stderr, one tick per probe."""
    from chaos_agents.interfaces import FAIL as _F
    from chaos_agents.interfaces import PASS as _P

    state = {"done": 0}
    width = 24

    def on_probe(outcome) -> None:
        state["done"] += 1
        done = state["done"]
        filled = int(width * done / total) if total else width
        bar = "#" * filled + "-" * (width - filled)
        mark = {_P: "held", _F: "LEAK"}.get(outcome.status, "skip")
        sys.stderr.write(f"\rChaosBench [{bar}] {done}/{total}  {outcome.probe.id:<6} {mark:<4}")
        sys.stderr.flush()
        if done == total:
            sys.stderr.write("\n")
            sys.stderr.flush()

    return on_probe


def _cmd_bench(args: argparse.Namespace) -> int:
    from chaos_agents import benchmark, benchreport, registry

    if args.suite not in benchmark.SUITES:
        print(f"unknown suite {args.suite!r}; available: {', '.join(benchmark.SUITES)}", file=sys.stderr)
        return 2
    try:
        campaign = Campaign.from_yaml(args.campaign)
    except CampaignError as exc:
        print(f"invalid campaign: {exc}", file=sys.stderr)
        return 2

    adapter = registry.load("chaos_agents.adapters", campaign.adapter.plugin, **campaign.adapter.config)
    suite = benchmark.SUITES[args.suite]
    # a live progress bar while probes run (useful when the target is a real
    # model and each probe takes a second or two); only when stderr is a TTY,
    # so CI logs and piped output stay clean.
    progress = _bench_progress(len(suite.probes)) if sys.stderr.isatty() else None
    card = benchmark.run_benchmark(suite, adapter, on_probe=progress)

    rendered = benchreport.FORMATS[args.format](card)
    if args.output:
        Path(args.output).write_text(rendered)
        print(f"{args.format} scorecard written to: {args.output}", file=sys.stderr)
    else:
        print(rendered)

    # gate: --min-resilience sets the bar; otherwise any failed probe is non-zero
    if args.min_resilience is not None:
        r = card.resilience
        return 1 if (r is not None and r < args.min_resilience) else 0
    return 1 if card.counts[FAIL] > 0 else 0


def _cmd_regression(args: argparse.Namespace) -> int:
    from chaos_agents import regression

    results = regression.run_regression(args.baseline)
    print(regression.summarize(results))
    return 1 if any(r.still_vulnerable for r in results) else 0


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
    run_p.add_argument("--format", choices=["terminal", "json", "sarif", "junit"], default="terminal",
                       help="output format (default: terminal). json/sarif/junit are for CI.")
    run_p.add_argument("--output", metavar="PATH", help="write the --format output to a file instead of stdout")
    run_p.add_argument("--graph", nargs="?", const="box", choices=["box", "mermaid"],
                       help="also draw each finding's attack graph (box, or mermaid for docs/PRs)")
    run_p.add_argument("--promote", metavar="DIR", help="promote confirmed findings into a regression corpus directory")
    run_p.add_argument("--minimize", action="store_true", help="with --promote, shrink each finding to a minimal reproducer first")
    run_p.set_defaults(func=_cmd_run)

    bench_p = sub.add_parser("bench", help="score a target against a ChaosBench suite (the adapter comes from a campaign file)")
    bench_p.add_argument("campaign", help="a campaign YAML; only its adapter block is used to build the target")
    bench_p.add_argument("--suite", default="chaos-bench-core", help="benchmark suite to run (default: chaos-bench-core)")
    bench_p.add_argument("--format", choices=["text", "json"], default="text", help="scorecard format (default: text)")
    bench_p.add_argument("--output", metavar="PATH", help="write the scorecard to a file instead of stdout")
    bench_p.add_argument("--min-resilience", type=float, metavar="PCT",
                         help="gate: exit non-zero if resilience is below PCT (default gate: any failed probe)")
    bench_p.set_defaults(func=_cmd_bench)

    reg_p = sub.add_parser("regression", help="re-run a regression corpus; non-zero if any reproducer still fires")
    reg_p.add_argument("baseline", help="path to a regression corpus directory (as written by run --promote)")
    reg_p.set_defaults(func=_cmd_regression)

    validate_p = sub.add_parser("validate", help="check a campaign file without running it")
    validate_p.add_argument("campaign", help="path to a campaign YAML file")
    validate_p.set_defaults(func=_cmd_validate)

    plugins_p = sub.add_parser("plugins", help="list installed plugins by surface")
    plugins_p.set_defaults(func=_cmd_plugins)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
