#!/usr/bin/env python3
"""
Fill and respell the English variant PO files (en_GB, en_AU, en_CA, en_US).

Usage: python copy-default.py [--locale LOCALE] [--dry-run] po-file [po-file ...]

For each entry (the header and obsolete entries are skipped):
  - an empty msgstr is filled with the msgid, converted to the spelling of
    the locale (e.g. "Color" -> "Colour" for en_GB)
  - a msgstr identical to the msgid (the untouched copy from an earlier run)
    is respelled the same way
  - plural entries are handled the same way, form by form: a form that is
    empty or still identical to its source (msgid for form 0, msgid_plural
    for form 1) is regenerated, a form that differs was edited and is kept.
    Regenerated forms also resolve "(s)": "%n atom(s)" becomes "%n atom"
    and "%n atoms". Verb agreement cannot be automated ("file(s) have
    been"), so a warning is printed for each generated singular containing
    have/are/were/do/these/them; fix those by hand.
  - anything else was edited by a human and is NEVER modified

The locale comes from --locale, otherwise from the file name (en_GB.po or
en-GB.po), otherwise from the 'Language' header of the file. Locales other
than en_GB, en_AU and en_CA (including en_US) get a plain copy with no
respelling; en_US exists to supply correct singular and plural forms.

Spelling rules are plain tables below (COMMON_SPELLING, ISE_STEMS, YSE_STEMS)
and are easy to extend. Rich text markup (tags, <style> blocks, HTML
entities and URLs) is never rewritten, only the plain text around it.

With --dry-run nothing is saved; every changed entry is printed as
"old -> new" so the respelled ones can be reviewed.

The file is saved unwrapped and then rewrapped with gettext's msgcat (if it
is on the PATH), which reproduces the Weblate layout exactly, so the diff
shows only real changes. Without msgcat, polib's own line wrapping is used.

Requires: pip install polib (and optionally gettext for msgcat)
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import polib
except ImportError:
    print("Error: polib module not found.", file=sys.stderr)
    print("Install it with: pip install polib", file=sys.stderr)
    sys.exit(1)


SUPPORTED_LOCALES = ('en_GB', 'en_AU', 'en_CA', 'en_US')

# Locales that get respelling (en_US is the source spelling)
RESPELL_LOCALES = ('en_GB', 'en_AU', 'en_CA')

# Locales that use -ise / -yse (Canadian English keeps -ize / -yze)
ISE_LOCALES = ('en_GB', 'en_AU')

# Spellings shared by en_GB, en_AU and en_CA.
# Whole words only, lowercase keys, and every inflection listed explicitly:
# there are deliberately no prefix or substring rules (they produce things
# like "centreed"). Case of the source word is preserved when applied.
COMMON_SPELLING = {
    # -or -> -our
    'color': 'colour',
    'colors': 'colours',
    'colored': 'coloured',
    'coloring': 'colouring',
    'colorful': 'colourful',
    'colorless': 'colourless',
    'colormap': 'colourmap',
    'colormaps': 'colourmaps',
    'colorize': 'colourize',
    'colorized': 'colourized',
    'colorizes': 'colourizes',
    'colorizing': 'colourizing',
    'behavior': 'behaviour',
    'behaviors': 'behaviours',
    'behavioral': 'behavioural',
    'neighbor': 'neighbour',
    'neighbors': 'neighbours',
    'neighboring': 'neighbouring',
    'neighborhood': 'neighbourhood',
    'neighborhoods': 'neighbourhoods',
    'favorite': 'favourite',
    'favorites': 'favourites',
    'vapor': 'vapour',
    'vapors': 'vapours',
    'odor': 'odour',
    'odors': 'odours',
    # -er -> -re
    'center': 'centre',
    'centers': 'centres',
    'centered': 'centred',
    'centering': 'centring',
    'fiber': 'fibre',
    'fibers': 'fibres',
    'liter': 'litre',
    'liters': 'litres',
    'nanometer': 'nanometre',
    'nanometers': 'nanometres',
    'picometer': 'picometre',
    'picometers': 'picometres',
    'micrometer': 'micrometre',
    'micrometers': 'micrometres',
    'millimeter': 'millimetre',
    'millimeters': 'millimetres',
    'centimeter': 'centimetre',
    'centimeters': 'centimetres',
    # gray -> grey
    'gray': 'grey',
    'grays': 'greys',
    'grayscale': 'greyscale',
    # doubled consonant before a suffix
    'canceled': 'cancelled',
    'canceling': 'cancelling',
    'labeled': 'labelled',
    'labeling': 'labelling',
    'modeled': 'modelled',
    'modeling': 'modelling',
    'modeler': 'modeller',
    'modelers': 'modellers',
    'leveled': 'levelled',
    'leveling': 'levelling',
    'traveled': 'travelled',
    'traveling': 'travelling',
    'tunneled': 'tunnelled',
    'tunneling': 'tunnelling',
    'channeled': 'channelled',
    'channeling': 'channelling',
    # -og -> -ogue
    'catalog': 'catalogue',
    'catalogs': 'catalogues',
    'analog': 'analogue',
    'analogs': 'analogues',
    'dialog': 'dialogue',
    'dialogs': 'dialogues',
    # noun only: "licensed" and "licensing" are the same in both spellings
    'license': 'licence',
    'licenses': 'licences',
    # IUPAC element names
    'aluminum': 'aluminium',
    'cesium': 'caesium',
}

# -ize -> -ise (en_GB and en_AU only). Only these explicit stems are
# converted; a generic rule would break size, prize, seize, capsize, ...
# The stem is followed by "iz" and one of ISE_SUFFIXES.
ISE_STEMS = [
    'optim', 'minim', 'maxim', 'symmetr', 'visual', 'initial',
    'conventional', 'general', 'hybrid', 'recogn', 'unrecogn', 'normal',
    'organ', 'custom', 'serial', 'deserial', 'synchron', 'random',
    'summar', 'priorit', 'final', 'util', 'local', 'character',
    'parameter', 'parametr', 'polar', 'ion', 'neutral', 'real',
    'special', 'standard', 'emphas', 'crystall', 'discret', 'linear',
    'categor', 'author', 'capital', 'equal', 'stabil', 'colour',
    'regular', 'vector', 'quant', 'canonical', 'harmon', 'kekul',
]
ISE_SUFFIXES = ['e', 'es', 'ed', 'er', 'ers', 'ing', 'ation', 'ations',
                'able', 'ability']

# -yze -> -yse (en_GB and en_AU only)
YSE_STEMS = ['anal', 'catal', 'hydrol', 'electrol', 'paral']
YSE_SUFFIXES = ['e', 'es', 'ed', 'er', 'ers', 'ing']

# Markup that must never be rewritten: <style> blocks, tags, HTML entities
# (must end in ';') and URLs. The capturing group makes re.split keep them,
# so the odd-numbered pieces are markup and the even-numbered are plain text.
MARKUP_RE = re.compile(
    r'(<style\b.*?</style>|</?[A-Za-z!][^>]*>|&(?:#[0-9]+|#[xX][0-9a-fA-F]+|'
    r'[A-Za-z][A-Za-z0-9]*);|\w+://\S+)',
    re.IGNORECASE | re.DOTALL)

WORD_RE = re.compile(r'(?<![A-Za-z0-9_])[A-Za-z]+(?![A-Za-z0-9_])')

# The stem must start at a word boundary and the suffix must end at one,
# so "ion" cannot match inside another word.
ISE_RE = re.compile(
    r'\b(' + '|'.join(sorted(ISE_STEMS, key=len, reverse=True)) + r')i([zZ])('
    + '|'.join(sorted(ISE_SUFFIXES, key=len, reverse=True)) + r')\b',
    re.IGNORECASE)
YSE_RE = re.compile(
    r'\b(' + '|'.join(YSE_STEMS) + r')y([zZ])('
    + '|'.join(sorted(YSE_SUFFIXES, key=len, reverse=True)) + r')\b',
    re.IGNORECASE)


def match_case(source, replacement):
    """Give the replacement the capitalisation style of the source word."""
    if len(source) > 1 and source.isupper():
        return replacement.upper()
    if source[0].isupper():
        return replacement[0].upper() + replacement[1:]
    return replacement


def common_word(match):
    word = match.group(0)
    replacement = COMMON_SPELLING.get(word.lower())
    if replacement is None:
        return word
    return match_case(word, replacement)


def swap_z(match):
    """Replace only the z with s (keeping case); the rest is kept as written."""
    stem, z, suffix = match.group(1), match.group(2), match.group(3)
    keep = match.group(0)[:len(stem) + 1]
    return keep + ('S' if z == 'Z' else 's') + suffix


def respell_text(text, locale):
    """Respell a run of plain text (no markup) for the locale."""
    text = WORD_RE.sub(common_word, text)
    if locale in ISE_LOCALES:
        text = ISE_RE.sub(swap_z, text)
        text = YSE_RE.sub(swap_z, text)
    return text


def respell(text, locale):
    """Respell text for the locale, leaving markup and URLs untouched."""
    if locale not in RESPELL_LOCALES or not text:
        return text
    pieces = MARKUP_RE.split(text)
    for i in range(0, len(pieces), 2):
        pieces[i] = respell_text(pieces[i], locale)
    return ''.join(pieces)


PLURAL_S_RE = re.compile(r'([A-Za-z])\(s\)')

# Words that signal verb or pronoun agreement a script cannot fix
AGREEMENT_RE = re.compile(r'\b(have|are|were|do|these|them)\b', re.IGNORECASE)


def resolve_plural(text, singular):
    """Resolve "(s)" in the plain text of a plural entry's form."""
    if not text:
        return text
    replacement = r'\1' if singular else r'\1s'
    pieces = MARKUP_RE.split(text)
    for i in range(0, len(pieces), 2):
        pieces[i] = PLURAL_S_RE.sub(replacement, pieces[i])
    return ''.join(pieces)


def normalize_locale(name):
    """Turn 'en-GB' or 'en_gb' into 'en_GB'; return None if not a locale."""
    if not name:
        return None
    parts = re.split(r'[-_]', name.strip())
    if len(parts) != 2:
        return None
    return parts[0].lower() + '_' + parts[1].upper()


def detect_locale(path, po, override):
    """Work out the locale: --locale, then file name, then PO header."""
    if override:
        return normalize_locale(override) or override
    from_name = normalize_locale(path.stem)
    if from_name in SUPPORTED_LOCALES:
        return from_name
    from_header = normalize_locale(po.metadata.get('Language', ''))
    if from_header:
        return from_header
    return from_name or ''


def process_entry(entry, locale, warnings=None):
    """Fill or respell one entry. Returns (kind, old, new) or None.

    kind is 'filled' or 'respelled'. Plural forms are decided one by one;
    forms edited by a human are kept. Singular forms generated here that
    need manual verb agreement are appended to the warnings list.
    """
    if entry.msgid_plural:
        forms = entry.msgstr_plural
        sources = {0: entry.msgid, 1: entry.msgid_plural}
        generated = {0: resolve_plural(respell(entry.msgid, locale), True),
                     1: resolve_plural(respell(entry.msgid_plural, locale),
                                       False)}
        old_forms = {k: forms.get(k, '') for k in (0, 1)}
        all_empty = all(v == '' for v in forms.values())
        new_forms = {}
        for k in (0, 1):
            if old_forms[k] == '' or old_forms[k] == sources[k]:
                new_forms[k] = generated[k]
            else:
                new_forms[k] = old_forms[k]
        changed = [k for k in (0, 1) if new_forms[k] != old_forms[k]]
        if not changed:
            return None
        if 0 in changed and warnings is not None:
            if AGREEMENT_RE.search(new_forms[0]):
                warnings.append(new_forms[0])
        entry.msgstr_plural = new_forms
        if all_empty:
            return ('filled', sources[0] + ' | ' + sources[1],
                    new_forms[0] + ' | ' + new_forms[1])
        return ('respelled', old_forms[0] + ' | ' + old_forms[1],
                new_forms[0] + ' | ' + new_forms[1])

    if entry.msgstr == '':
        entry.msgstr = respell(entry.msgid, locale)
        return ('filled', entry.msgid, entry.msgstr)
    if entry.msgstr == entry.msgid:
        new = respell(entry.msgid, locale)
        if new != entry.msgstr:
            entry.msgstr = new
            return ('respelled', entry.msgid, new)
    return None


def rewrap(path):
    """Rewrap a saved PO file with msgcat to match the Weblate layout."""
    msgcat = shutil.which('msgcat')
    if msgcat is None:
        print("Warning: msgcat (gettext) not found; line wrapping will "
              "differ from Weblate's.", file=sys.stderr)
        return
    result = subprocess.run([msgcat, '-o', str(path), str(path)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Warning: msgcat failed: {result.stderr.strip()}",
              file=sys.stderr)


def process_file(filepath, locale_override=None, dry_run=False):
    """Fill empty msgstr entries and respell the untouched copies."""
    path = Path(filepath)

    if not path.exists():
        print(f"Error: File '{filepath}' not found.", file=sys.stderr)
        return False

    # wrapwidth=0 saves unwrapped; msgcat then rewraps the gettext way
    po = polib.pofile(str(path), wrapwidth=0)
    locale = detect_locale(path, po, locale_override)

    if locale not in SUPPORTED_LOCALES:
        print(f"Notice: locale '{locale or 'unknown'}' has no spelling "
              f"rules; copying msgid without respelling.", file=sys.stderr)

    print(f"Processed: {path.name}")
    print(f"Locale: {locale or 'unknown'}")

    filled_count = 0
    respelled_count = 0

    for entry in po:
        # Skip the header entry and obsolete entries
        if entry.msgid == '' or entry.obsolete:
            continue

        warnings = []
        result = process_entry(entry, locale, warnings)
        for text in warnings:
            print(f"Warning: {path.name}: check verb agreement in "
                  f"singular form: {text!r}", file=sys.stderr)
        if result is None:
            continue

        kind, old, new = result
        if kind == 'filled':
            filled_count += 1
        else:
            respelled_count += 1
        if dry_run and old != new:
            print(f"  {old!r} -> {new!r}")

    if not dry_run:
        po.save(str(path))
        rewrap(path)

    print(f"Filled {filled_count} empty msgstr entries.")
    print(f"Respelled {respelled_count} entries.")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Fill empty msgstr entries in en_GB/en_AU/en_CA/en_US PO '
                    'files with the msgid, using local spelling.')
    parser.add_argument('po_files', nargs='+', metavar='po-file',
                        help='PO file(s) to process')
    parser.add_argument('--locale',
                        help='locale (en_GB, en_AU, en_CA, en_US); default is '
                             'taken from the file name or PO header')
    parser.add_argument('--dry-run', action='store_true',
                        help="don't save; print each changed entry as "
                             "'old -> new'")
    args = parser.parse_args()

    success = True
    for po_file in args.po_files:
        if not process_file(po_file, args.locale, args.dry_run):
            success = False

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
