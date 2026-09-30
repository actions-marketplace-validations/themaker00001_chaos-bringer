import pytest

pytest.importorskip("rich")

from rich.console import Console  # noqa: E402

from chaos_agents import mascot  # noqa: E402
from chaos_agents import mascot_data  # noqa: E402


@pytest.mark.parametrize("which", ["full", "small"])
def test_frame_data_decodes_to_full_frames(which):
    frames = mascot._frames(which)
    cols, rows = mascot.size(which)
    assert len(frames) == mascot_data.FRAMES == 8
    assert all(len(f) == cols * rows * 2 for f in frames)
    assert all(max(f) < len(mascot_data.PALETTE) for f in frames)


def test_frames_actually_differ():
    # the animation is the point: every frame must change something
    frames = mascot._frames("full")
    assert len(set(frames)) == len(frames)


@pytest.mark.parametrize("which", ["full", "small"])
def test_renders_one_cell_per_two_pixels_on_a_clear_background(which):
    cols, rows = mascot.size(which)
    lines = mascot._frame_lines(which)[3]
    assert len(lines) == rows
    assert all(len(row) == cols for row in lines)
    glyphs = {seg.text for row in lines for seg in row}
    assert glyphs <= {" ", "▀", "▄"}
    # clear background: empty cells carry no colour at all, so the terminal's
    # own background shows through instead of a box
    empty = [seg for row in lines for seg in row if seg.text == " "]
    assert empty and all(seg.style is None for seg in empty)
    assert all(seg.style is None or seg.style.bgcolor is None for seg in (lines[0][0], lines[-1][-1]))


def test_corners_are_transparent():
    for which in ("full", "small"):
        frame = mascot._frames(which)[0]
        w = mascot.size(which)[0]
        assert frame[0] == mascot_data.TRANSPARENT
        assert frame[w - 1] == mascot_data.TRANSPARENT


def test_eye_glow_survives_palette_reduction():
    assert "#ff2e5b" in mascot_data.PALETTE
    assert "#ffd166" in mascot_data.PALETTE


def _console(width, height, terminal=True, colors="truecolor"):
    return Console(width=width, height=height, force_terminal=terminal, color_system=colors, file=open("/dev/null", "w"))


def test_pick_size_falls_back_as_the_terminal_shrinks():
    full_cols, full_rows = mascot.size("full")
    small_cols, small_rows = mascot.size("small")
    assert mascot.pick_size(_console(full_cols + 10, full_rows + 10)) == "full"
    assert mascot.pick_size(_console(small_cols + 10, small_rows + 10)) == "small"
    assert mascot.pick_size(_console(40, 15)) is None


def test_pick_size_is_none_when_not_a_terminal():
    assert mascot.pick_size(_console(300, 200, terminal=False)) is None


def test_pick_size_is_none_on_a_basic_colour_terminal():
    # 8/16-colour terminals collapse the art into a black blob
    assert mascot.pick_size(_console(300, 200, colors="standard")) is None
    assert mascot.pick_size(_console(300, 200, colors="256")) == "full"


def test_small_fits_a_27_row_panel():
    # the real Terminal panel this was built against: 131x27
    assert mascot.pick_size(_console(131, 27)) == "small"


def test_why_not_explains_each_failure_and_stays_quiet_otherwise():
    assert "basic colours" in mascot.why_not(_console(300, 200, colors="standard"))
    assert "40x15" in mascot.why_not(_console(40, 15))
    assert mascot.why_not(_console(300, 200)) is None
    assert mascot.why_not(_console(300, 200, terminal=False)) is None  # piped: nobody to tell


def test_unknown_size_is_rejected():
    with pytest.raises(ValueError):
        mascot.Mascot("huge")
