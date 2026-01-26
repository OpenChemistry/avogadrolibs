#!/usr/bin/env python3
"""
Fill empty msgstr entries in PO files with msgid values.
Usage: python copy-default.py [po-file] [--backup]

Requires: pip install polib
"""

import sys
from pathlib import Path

try:
    import polib
except ImportError:
    print("Error: polib module not found.", file=sys.stderr)
    print("Install it with: pip install polib", file=sys.stderr)
    sys.exit(1)


def fill_empty_translations(filepath):
    """Fill empty msgstr with msgid values."""
    path = Path(filepath)

    if not path.exists():
        print(f"Error: File '{filepath}' not found.", file=sys.stderr)
        return False

    po = polib.pofile(filepath)
    filled_count = 0

    for entry in po:
        # Skip the header entry
        if entry.msgid == '':
            continue

        # If msgstr is empty, fill with msgid
        if entry.msgstr == '':
            entry.msgstr = entry.msgid
            filled_count += 1

    po.save(filepath)

    print(f"Processed: {path.name}")
    print(f"Filled {filled_count} empty msgstr entries.")
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python copy-default.py [po-file]")
        print("\nOptions:")
        sys.exit(1)

    po_file = sys.argv[1]

    success = fill_empty_translations(po_file)
    sys.exit(0 if success else 1)
