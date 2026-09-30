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
