#!/usr/bin/env python3
import sys, os
from scour import scour

def optimize_svg_file(in_path, out_path, options=None):
    if options is None:
        options = scour.sanitizeOptions()
        # remove comments, metadata, defs you don’t need:
        options.remove_metadata = True
        options.remove_descriptive_elements = True
        options.shorten_ids = True
        options.strip_ids = True   # mangle <g id="…">
        options.indent_depth = None # compact output
    with open(in_path, 'r', encoding='utf-8') as fin:
        svg = fin.read()
    out_svg = scour.scourString(svg, options=options)
    with open(out_path, 'w', encoding='utf-8') as fout:
        fout.write(out_svg)

def batch_optimize(directory):
    for fname in os.listdir(directory):
        if fname.lower().endswith('.svg'):
            inp = os.path.join(directory, fname)
            out = os.path.join(directory, 'opt', fname)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            optimize_svg_file(inp, out)
            print(f"Optimized {fname}")

if __name__ == "__main__":
    src_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    batch_optimize(src_dir)
