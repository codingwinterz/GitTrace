"""
gittrace.cli.logo — the interactive mode's logo: a small cluster of connected
nodes (a code graph), rotated in 3D and drawn in characters.

Pure math, no Textual: `frames()` returns one full turn about the vertical axis
as lists of strings, `ROWS` x `COLS` characters each, and the widget in
gittrace.cli.interactive only swaps them. The turn is eased in and out, so it
starts and ends at rest on frame 0, which is also the static frame.

Nodes are spheres, shaded per cell by ray casting: a cell's offset from the
projected centre gives the sphere's normal there, and the Lambert term picks a
character from PALETTE (darkest first). Edges are a wireframe of points along
each segment, lighter the farther away they are. A depth buffer keeps the
nearest surface in each cell.

Coordinates: x right, y up, z away from the viewer; the camera sits at
z = -DISTANCE looking along +z. A character cell is about twice as tall as it
is wide (ASPECT), so x is stretched by ASPECT when projected.
"""

from __future__ import annotations

import math
from functools import lru_cache

Vec = tuple[float, float, float]

PALETTE = " .:-=+*#%@"
ROWS = 12                       # the logo area may be at most 14 rows tall
COLS = 28
ASPECT = 2.0                    # cell height / cell width
DISTANCE = 4.0                  # camera to the scene's centre
TILT = 0.38                     # radians about x, so the turn is seen slightly from above
FPS = 20
SPIN_SECONDS = 2.0
HOLD_SECONDS = 5.0
FRAMES = round(FPS * SPIN_SECONDS)
LIGHT: Vec = (-0.45, 0.65, -0.62)   # towards the light: upper left, in front

# A hub and five neighbours: (centre, radius).
NODES: tuple[tuple[Vec, float], ...] = (
    ((0.0, 0.0, 0.0), 0.36),
    ((0.05, 0.82, 0.12), 0.27),
    ((0.8, 0.22, -0.3), 0.25),
    ((0.55, -0.62, 0.38), 0.25),
    ((-0.72, -0.48, -0.22), 0.27),
    ((-0.66, 0.42, 0.42), 0.23),
)
EDGES: tuple[tuple[int, int], ...] = ((0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (1, 2), (2, 3), (4, 5))

_AMBIENT = 0.12
_EDGE_NEAR, _EDGE_FAR = 0.3, 0.0      # edge brightness at the front and back of the scene
_EDGE_STEP = 0.03                     # spacing of the points along an edge (scene units)
_MARGIN = 0.6                         # cells kept free at the border


def _normalise(v: Vec) -> Vec:
    n = math.sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2])
    return (v[0] / n, v[1] / n, v[2] / n)


def rotate_y(p: Vec, angle: float) -> Vec:
    c, s = math.cos(angle), math.sin(angle)
    return (c * p[0] + s * p[2], p[1], -s * p[0] + c * p[2])


def rotate_x(p: Vec, angle: float) -> Vec:
    c, s = math.cos(angle), math.sin(angle)
    return (p[0], c * p[1] - s * p[2], s * p[1] + c * p[2])


def ease(t: float) -> float:
    """Ease in and out over 0..1 (zero speed at both ends)."""
    t = min(max(t, 0.0), 1.0)
    return 0.5 - 0.5 * math.cos(math.pi * t)


def bounding_radius(nodes=NODES) -> float:
    return max(math.dist(c, (0.0, 0.0, 0.0)) + r for c, r in nodes)


@lru_cache(maxsize=16)
def focal(cols: int = COLS, rows: int = ROWS, nodes=NODES, tilt: float = TILT,
          distance: float = DISTANCE) -> float:
    """The largest focal length that keeps every node inside the frame (less
    _MARGIN) at every angle of the turn, sampled each degree. Projection is
    linear in the focal length, so the limit is the tightest node and angle."""
    best = math.inf
    for step in range(360):
        for centre, radius in nodes:
            x, y, z = rotate_x(rotate_y(centre, math.radians(step)), tilt)
            z += distance
            if abs(y) + radius > 0:
                best = min(best, (rows / 2 - _MARGIN) * z / (abs(y) + radius))
            if abs(x) + radius > 0:
                best = min(best, (cols / 2 - _MARGIN) * z / (ASPECT * (abs(x) + radius)))
    return best


def project(p: Vec, f: float, cols: int = COLS, rows: int = ROWS,
            distance: float = DISTANCE) -> tuple[float, float, float] | None:
    """Perspective projection to (column, row, depth); None behind the camera.
    The frame's centre is (cols / 2, rows / 2); rows grow downwards."""
    z = p[2] + distance
    if z <= 1e-6:
        return None
    return cols / 2 + f * ASPECT * p[0] / z, rows / 2 - f * p[1] / z, z


def shade(level: float) -> str:
    """A brightness in 0..1 as a visible character (never the blank)."""
    level = min(max(level, 0.0), 1.0)
    return PALETTE[1 + round(level * (len(PALETTE) - 2))]


def _plot(chars: list[list[str]], depth: list[list[float]], row: int, col: int, z: float, ch: str) -> None:
    if 0 <= row < len(chars) and 0 <= col < len(chars[0]) and z < depth[row][col]:
        depth[row][col] = z
        chars[row][col] = ch


def render(angle: float, cols: int = COLS, rows: int = ROWS, nodes=NODES, edges=EDGES,
           tilt: float = TILT, distance: float = DISTANCE) -> list[str]:
    """One frame: the scene turned by `angle` radians about the vertical axis."""
    f = focal(cols, rows, nodes, tilt, distance)
    light = _normalise(LIGHT)
    chars = [[" "] * cols for _ in range(rows)]
    depth = [[math.inf] * cols for _ in range(rows)]
    placed = [(rotate_x(rotate_y(c, angle), tilt), r) for c, r in nodes]

    r_max = bounding_radius(nodes)
    for a, b in edges:
        (pa, ra), (pb, rb) = placed[a], placed[b]
        length = math.dist(pa, pb)
        if length <= ra + rb:
            continue
        steps = max(2, int((length - ra - rb) / _EDGE_STEP))
        for i in range(steps + 1):
            t = (ra + (length - ra - rb) * i / steps) / length       # outside both spheres
            p = (pa[0] + (pb[0] - pa[0]) * t, pa[1] + (pb[1] - pa[1]) * t, pa[2] + (pb[2] - pa[2]) * t)
            q = project(p, f, cols, rows, distance)
            if q is None:
                continue
            near = 1 - (q[2] - (distance - r_max)) / (2 * r_max)       # 1 at the front, 0 at the back
            _plot(chars, depth, int(q[1]), int(q[0]), q[2], shade(_EDGE_FAR + (_EDGE_NEAR - _EDGE_FAR) * near))

    for centre, radius in placed:
        q = project(centre, f, cols, rows, distance)
        if q is None:
            continue
        col0, row0, z = q
        rr = f * radius / z                 # projected radius in rows
        rc = rr * ASPECT                    # ... and in columns
        drawn = False
        for row in range(int(row0 - rr), int(row0 + rr) + 1):
            for col in range(int(col0 - rc), int(col0 + rc) + 1):
                u = (col + 0.5 - col0) / rc
                v = (row0 - (row + 0.5)) / rr
                d = u * u + v * v
                if d > 1:
                    continue
                w = math.sqrt(1 - d)
                lambert = max(0.0, u * light[0] + v * light[1] - w * light[2])
                _plot(chars, depth, row, col, z - radius * w, shade(_AMBIENT + (1 - _AMBIENT) * lambert))
                drawn = True
        if not drawn:                       # smaller than a cell: still a dot
            _plot(chars, depth, int(row0), int(col0), z - radius, shade(0.5))
    return ["".join(line) for line in chars]


@lru_cache(maxsize=4)
def frames(count: int = FRAMES, cols: int = COLS, rows: int = ROWS) -> tuple[tuple[str, ...], ...]:
    """One full turn in `count` frames, eased; frame 0 is the scene at rest."""
    return tuple(tuple(render(2 * math.pi * ease(i / count), cols, rows)) for i in range(count))


def static_frame(cols: int = COLS, rows: int = ROWS) -> tuple[str, ...]:
    return tuple(render(0.0, cols, rows))
