"""
tests/test_logo.py — the interactive mode's logo (gittrace.cli.logo): rotation,
perspective projection, shading and frame generation. Pure math, no Textual.
"""

from __future__ import annotations

import math
import time

import pytest

from gittrace.cli import logo
from gittrace.cli.logo import (ASPECT, COLS, DISTANCE, FRAMES, PALETTE, ROWS, ease, focal, frames, project,
                               render, rotate_x, rotate_y, shade, static_frame)


def _close(a, b, tol=1e-9):
    return all(abs(x - y) <= tol for x, y in zip(a, b))


class TestRotation:
    def test_full_turn_is_the_identity(self):
        p = (0.3, -0.7, 0.5)
        assert _close(rotate_y(p, 2 * math.pi), p)
        assert _close(rotate_x(p, 2 * math.pi), p)

    def test_quarter_turns(self):
        assert _close(rotate_y((1, 0, 0), math.pi / 2), (0, 0, -1))
        assert _close(rotate_x((0, 1, 0), math.pi / 2), (0, 0, 1))

    def test_rotation_keeps_lengths(self):
        p = (0.3, -0.7, 0.5)
        for angle in (0.1, 1.3, 4.0):
            assert math.dist(rotate_y(p, angle), (0, 0, 0)) == pytest.approx(math.dist(p, (0, 0, 0)))
            assert math.dist(rotate_x(p, angle), (0, 0, 0)) == pytest.approx(math.dist(p, (0, 0, 0)))

    def test_y_rotation_keeps_the_height(self):
        assert rotate_y((0.4, 0.9, -0.2), 2.0)[1] == pytest.approx(0.9)


class TestProjection:
    F = 10.0

    def test_origin_lands_in_the_centre(self):
        assert project((0, 0, 0), self.F) == (COLS / 2, ROWS / 2, DISTANCE)

    def test_right_is_right_and_up_is_up(self):
        col, row, _ = project((0.5, 0.5, 0), self.F)
        assert col > COLS / 2 and row < ROWS / 2          # rows grow downwards

    def test_cells_are_twice_as_tall_as_wide(self):
        col, _, _ = project((0.2, 0, 0), self.F)
        _, row, _ = project((0, 0.2, 0), self.F)
        assert (col - COLS / 2) == pytest.approx(ASPECT * (ROWS / 2 - row))

    def test_perspective_shrinks_with_distance(self):
        near = project((0.5, 0, -1), self.F)
        far = project((0.5, 0, 1), self.F)
        assert near[0] - COLS / 2 > far[0] - COLS / 2 > 0
        # offset from the centre is inversely proportional to depth
        assert (near[0] - COLS / 2) * near[2] == pytest.approx((far[0] - COLS / 2) * far[2])
        assert near[2] < far[2]

    def test_behind_the_camera_is_none(self):
        assert project((0, 0, -DISTANCE - 0.1), self.F) is None
        assert project((0, 0, -DISTANCE), self.F) is None

    def test_every_node_stays_inside_the_frame_at_every_angle(self):
        f = focal()
        for angle in [2 * math.pi * ease(i / FRAMES) for i in range(FRAMES)] + [0.123, 2.5, 5.9]:
            for centre, radius in logo.NODES:
                col, row, z = project(rotate_x(rotate_y(centre, angle), logo.TILT), f)
                rr = f * radius / z
                assert 0 <= row - rr and row + rr <= ROWS
                assert 0 <= col - rr * ASPECT and col + rr * ASPECT <= COLS


class TestEaseAndShade:
    def test_ease_ends_and_middle(self):
        assert ease(0) == 0 and ease(1) == pytest.approx(1) and ease(0.5) == pytest.approx(0.5)

    def test_ease_is_monotonic_and_clamped(self):
        values = [ease(i / 50) for i in range(51)]
        assert values == sorted(values)
        assert ease(-1) == 0 and ease(2) == pytest.approx(1)

    def test_shade_uses_the_palette_without_the_blank(self):
        assert shade(0) == PALETTE[1] and shade(1) == PALETTE[-1]
        assert shade(-5) == PALETTE[1] and shade(5) == PALETTE[-1]
        assert {shade(i / 20) for i in range(21)} <= set(PALETTE[1:])


class TestFrames:
    def test_logo_area_is_at_most_14_rows(self):
        assert ROWS <= 14

    def test_one_turn_is_two_seconds_at_twenty_fps(self):
        assert logo.FPS == 20 and logo.SPIN_SECONDS == 2.0 and len(frames()) == FRAMES == 40

    def test_frame_shape_and_characters(self):
        for frame in frames():
            assert len(frame) == ROWS
            assert all(len(line) == COLS for line in frame)
            assert set("".join(frame)) <= set(PALETTE)

    def test_frames_are_not_empty(self):
        for frame in frames():
            assert sum(ch != " " for line in frame for ch in line) > 40

    def test_turn_starts_and_ends_at_rest(self):
        assert frames()[0] == static_frame()
        assert tuple(render(2 * math.pi)) == static_frame()      # a full turn comes back

    def test_frames_move(self):
        fr = frames()
        changed = sum(fr[i] != fr[i + 1] for i in range(len(fr) - 1))
        assert changed >= len(fr) - 3          # the eased ends may repeat a frame
        assert fr[len(fr) // 2] != fr[0]

    def test_frames_are_deterministic(self):
        assert tuple(render(1.0)) == tuple(render(1.0))

    def test_spheres_are_lit_from_the_upper_left(self):
        frame = render(0.0, nodes=(((0.0, 0.0, 0.0), 1.0),), edges=())
        cells = [(r, c, PALETTE.index(ch)) for r, line in enumerate(frame) for c, ch in enumerate(line) if ch != " "]
        top_left = min(cells, key=lambda x: x[0] + x[1] / ASPECT)
        bottom_right = max(cells, key=lambda x: x[0] + x[1] / ASPECT)
        assert top_left[2] > bottom_right[2]

    def test_nearest_surface_wins_a_cell(self):
        chars, depth = [[" "]], [[math.inf]]
        logo._plot(chars, depth, 0, 0, 5.0, ".")
        logo._plot(chars, depth, 0, 0, 3.0, "@")
        logo._plot(chars, depth, 0, 0, 4.0, ":")
        assert chars[0][0] == "@" and depth[0][0] == 3.0
        logo._plot(chars, depth, 5, 5, 1.0, "#")           # off the frame: ignored
        assert chars == [["@"]]

    def test_a_node_smaller_than_a_cell_is_still_drawn(self):
        frame = render(0.0, nodes=(((0.0, 0.0, 0.0), 1.0), ((0.9, 0.0, 0.0), 0.01)), edges=())
        assert sum(ch != " " for line in frame for ch in line) > 0

    def test_cheap(self):
        frames.cache_clear()
        start = time.perf_counter()
        frames()
        assert time.perf_counter() - start < 0.5               # all 40 frames, once
        assert frames() is frames()                            # then cached: a tick only swaps text
