import pytest

from chaos_agents.corpus import Record

pytest.importorskip("rich")


def _records(passed: bool) -> list[Record]:
    return [
        Record(payload="p", response="r", passed=passed, severity="high", reason="x", details={}),
    ]


def test_render_svg_with_findings(tmp_path):
    from chaos_agents import report_rich

    out = tmp_path / "report.svg"
    report_rich.render_svg("demo", _records(passed=False), str(out))

    svg = out.read_text()
    assert svg.startswith("<svg")
    assert "demo" in svg
    assert report_rich.PLAGUE in svg  # findings use the "finding" color


def test_render_svg_with_no_findings(tmp_path):
    from chaos_agents import report_rich

    out = tmp_path / "report.svg"
    report_rich.render_svg("demo", _records(passed=True), str(out))

    svg = out.read_text()
    assert "findings" in svg  # rich encodes the space as &#160;, so match loosely
    assert report_rich.POISON in svg  # a clean run uses the "survived" color


def test_announce_prints_a_themed_line_for_each_verdict():
    from rich.console import Console

    from chaos_agents import report_rich

    console = Console(record=True, width=100)
    report_rich.announce(console, Record(payload="p1", response="r", passed=True, severity="info", reason="", details={}))
    report_rich.announce(console, Record(payload="p2", response="r", passed=False, severity="high", reason="", details={}))

    text = console.export_text()
    assert "recoils" in text and "p1" in text
    assert "swallows it whole" in text and "p2" in text
