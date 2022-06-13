import sys
import argparse
import json
import re
from globber import match


def fail(msg):
    print(msg)
    sys.exit(-1)


def match_path_and_rule(path, rule, patterns):
    result = True
    for s, fp, rp in patterns:
        if match(rp, rule) and match(fp, path):
            result = s
    return result


def parse_pattern(line):
    sepchar = ':'
    escchar = '\\'
    file_pattern = ''
    rule_pattern = ''
    seen_separator = False
    sign = True

    # inclusion or exclusion pattern?
    uline = line
    if line:
        if line[0] == '-':
            sign = False
            uline = line[1:]
        elif line[0] == '+':
            uline = line[1:]

    i = 0
    while i < len(uline):
        c = uline[i]
        i = i + 1
        if c == sepchar:
            if seen_separator:
                raise Exception('Invalid pattern: "' + line + '" Contains more than one separator!')
            seen_separator = True
            continue
        elif c == escchar:
            nextc = uline[i] if (i < len(uline)) else None
            if nextc in ['+' , '-', escchar, sepchar]:
                i = i + 1
                c = nextc
        if seen_separator:
            rule_pattern = rule_pattern + c
        else:
            file_pattern = file_pattern + c

    if not rule_pattern:
        rule_pattern = '**'

    return sign, file_pattern, rule_pattern


def filter_sarif(args):
    if args.split_lines:
        tmp = []
        for p in args.patterns:
            tmp = tmp + re.split('\r?\n', p)
        args.patterns = tmp

    args.patterns = [parse_pattern(p) for p in args.patterns if p]

    print('Given patterns:')
    for s, fp, rp in args.patterns:
        print(
            'files: {file_pattern}    rules: {rule_pattern} ({sign})'.format(
                file_pattern=fp,
                rule_pattern=rp,
                sign='positive' if s else 'negative'
            )
        )

    with open(args.input, 'r') as f:
        s = json.load(f)

    for run in s.get('runs', []):
        if run.get('results', []):
            new_results = []
            for r in run['results']:
                if r.get('locations', []):
                    new_locations = []
                    for l in r['locations']:
                        # TODO: The uri field is optional. We might have to fetch the actual uri from "artifacts" via "index"
                        # (see https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#-linking-results-to-artifacts)
                        uri = l.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', None)
                        # TODO: The ruleId field is optional and potentially ambiguous. We might have to fetch the actual
                        # ruleId from the rule metadata via the ruleIndex field.
                        # (see https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#rule-metadata)
                        ruleId = r['ruleId']
                        if uri is None or match_path_and_rule(uri, ruleId, args.patterns):
                            new_locations.append(l)
                    r['locations'] = new_locations
                    if new_locations:
                        new_results.append(r)
                else:
                    # locations array doesn't exist or is empty, so we can't match on anything
                    # therefore, we include the result in the output
                    new_results.append(r)
            run['results'] = new_results

    with open(args.output, 'w') as f:
        json.dump(s, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        prog='filter-sarif'
    )
    parser.add_argument(
        '--input',
        help='Input SARIF file',
        required=True
    )
    parser.add_argument(
        '--output',
        help='Output SARIF file',
        required=True
    )
    parser.add_argument(
        '--split-lines',
        default=False,
        action='store_true',
        help='Split given patterns on newlines.'
    )
    parser.add_argument(
        'patterns',
        help='Inclusion and exclusion patterns.',
        nargs='+'
    )

    def print_usage(args):
        print(parser.format_usage())

    args = parser.parse_args()
    filter_sarif(args)


main()
