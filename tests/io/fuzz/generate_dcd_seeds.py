#!/usr/bin/env python3
"""Write the seed corpus for fuzz_dcd.

The DCD reader's only avogadrodata file is a 1 MB trajectory, far too big a
seed, so these small files cover the reader's branches instead: X-PLOR and
CHARMM headers, the unit-cell and fourth-dimension records, fixed atoms,
both byte orders, one or several frames, and a truncated last frame.
Usage: generate_dcd_seeds.py [output directory]
(default: dcd-small/ next to this script).
"""
import os
import struct
import sys


def record(payload, e):
    marker = struct.pack(e + "i", len(payload))
    return marker + payload + marker


def header(e, charmm, natoms, nfixed=0, cell=False, fourd=False, nframes=1):
    h = bytearray(84)
    h[0:4] = b"CORD"
    struct.pack_into(e + "i", h, 4, nframes)   # NSET
    struct.pack_into(e + "i", h, 8, 100)       # ISTART
    struct.pack_into(e + "i", h, 12, 10)       # NSAVC
    struct.pack_into(e + "i", h, 36, nfixed)   # NAMNF
    if charmm:
        struct.pack_into(e + "f", h, 40, 0.5)  # DELTA, AKMA units
        struct.pack_into(e + "i", h, 44, 1 if cell else 0)
        struct.pack_into(e + "i", h, 48, 1 if fourd else 0)
        struct.pack_into(e + "i", h, 80, 24)   # CHARMM version
    else:
        struct.pack_into(e + "d", h, 40, 0.001)  # DELTA, ps
    return record(bytes(h), e)


def title(e, lines=2):
    body = struct.pack(e + "i", lines)
    for i in range(lines):
        body += (b"* seed title line %d" % i).ljust(80)
    return record(body, e)


def coords(n, step):
    return [[0.1 * i + 0.01 * step * (a + 1) for i in range(n)]
            for a in range(3)]


def frame(e, n, step, cell=None, fourd=False, free=None):
    out = b""
    if cell is not None:
        out += record(struct.pack(e + "6d", *cell), e)
    xyz = coords(n, step)
    for axis in xyz:
        vals = axis if free is None else [axis[i - 1] for i in free]
        out += record(struct.pack(e + "%df" % len(vals), *vals), e)
    if fourd:
        out += record(struct.pack(e + "%df" % n, *([0.0] * n)), e)
    return out


def build(e=">", charmm=False, natoms=4, nfixed=0, cell=None, fourd=False,
          nframes=1, truncate=0):
    free = None
    out = header(e, charmm, natoms, nfixed, cell is not None, fourd, nframes)
    out += title(e)
    out += record(struct.pack(e + "i", natoms), e)
    if nfixed:
        free = list(range(nfixed + 1, natoms + 1))
        out += record(struct.pack(e + "%di" % len(free), *free), e)
    for f in range(nframes):
        out += frame(e, natoms, f, cell, fourd, free if f else None)
    return out[:len(out) - truncate] if truncate else out


# A, gamma, B, beta, alpha, C: CHARMM stores cosines (or degrees in some
# files); all-zero lengths mean "no cell".
CELL_COS = (10.0, 0.0, 12.0, 0.0, 0.0, 14.0)
CELL_DEG = (10.0, 90.0, 12.0, 90.0, 90.0, 14.0)
CELL_NONE = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

SEEDS = {
    "xplor_be_1frame": build(">", False, 4),
    "xplor_le_3frames": build("<", False, 5, nframes=3),
    "charmm_le_cell_cos": build("<", True, 4, cell=CELL_COS, nframes=3),
    "charmm_be_cell_deg": build(">", True, 4, cell=CELL_DEG, nframes=2),
    "charmm_le_nocell_record": build("<", True, 3, cell=CELL_NONE),
    "charmm_le_4d": build("<", True, 4, fourd=True, nframes=2),
    "charmm_be_cell_4d": build(">", True, 3, cell=CELL_COS, fourd=True,
                               nframes=2),
    "xplor_le_fixed": build("<", False, 6, nfixed=2, nframes=3),
    "charmm_be_fixed_cell": build(">", True, 6, nfixed=3, cell=CELL_COS,
                                  nframes=3),
    "xplor_le_truncated": build("<", False, 4, nframes=3, truncate=20),
}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "dcd-small")
    os.makedirs(out, exist_ok=True)
    for name, data in SEEDS.items():
        with open(os.path.join(out, name + ".dcd"), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main()
