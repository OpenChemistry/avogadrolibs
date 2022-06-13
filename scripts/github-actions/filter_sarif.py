#!/usr/bin/env python
# -*- coding: utf-8 -*-
# From https://github.com/zbazztian/filter-sarif/blob/master/filter_sarif.py
# Some modifications by Geoffrey Hutchison

import argparse
import json
import re
from globber import match


def match_path_and_rule(path, rule, patterns):
    result = True
    for sign, file_pattern, rule_pattern in patterns:
        if match(rule_pattern, rule) and match(file_pattern, path):
            result = sign
    return result


def parse_pattern(line):
    sep_char = ":"
    esc_char = "\\"
    file_pattern = ""
    rule_pattern = ""
    seen_separator = False
    sign = True

    # inclusion or exclusion pattern?
    uline = line
    if line:
        if line[0] == "-":
            sign = False
            uline = line[1:]
        elif line[0] == "+":
            uline = line[1:]

    i = 0
    while i < len(uline):
        char = uline[i]
        i = i + 1
        if char == sep_char:
            if seen_separator:
                raise Exception(
                    'Invalid pattern: "' + line + '" Contains more than one separator!'
                )
            seen_separator = True
            continue

        if char == esc_char:
            next_char = uline[i] if (i < len(uline)) else None
            if next_char in ["+", "-", esc_char, sep_char]:
                i = i + 1
                char = next_char

        if seen_separator:
            rule_pattern = rule_pattern + char
        else:
            file_pattern = file_pattern + char

    if not rule_pattern:
        rule_pattern = "**"

    return sign, file_pattern, rule_pattern


def filter_sarif(args):
    if args.split_lines:
        tmp = []
        for pattern in args.patterns:
            tmp = tmp + re.split("\r?\n", pattern)
        args.patterns = tmp

    args.patterns = [parse_pattern(pattern) for pattern in args.patterns if pattern]

    print("Given patterns:")
    for sign, file_pattern, rule_pattern in args.patterns:
        sign_text = "positive" if sign else "negative"
        print(f"files: {file_pattern}    rules: {rule_pattern} ({sign_text})")

    with open(args.input, "r", encoding="UTF-8") as file:
        sarif = json.load(file)

    for run in sarif.get("runs", []):
        if run.get("results", []):
            new_results = []
            for result in run["results"]:
                if result.get("locations", []):
                    new_locations = []
                    for location in result["locations"]:
                        # TODO: The uri field is optional. We might have to fetch the
                        #  actual uri from "artifacts" via "index"
                        # (https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md)
                        uri = (
                            location.get("physicalLocation", {})
                            .get("artifactLocation", {})
                            .get("uri", None)
                        )
                        # TODO: The ruleId field is optional and potentially ambiguous.
                        # We might have to fetch the actual ruleId from the rule metadata
                        # via the ruleIndex field.
                        # (https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md)
                        rule_id = result["ruleId"]
                        if uri is None or match_path_and_rule(
                            uri, rule_id, args.patterns
                        ):
                            new_locations.append(location)
                    result["locations"] = new_locations
                    if new_locations:
                        new_results.append(result)
                else:
                    # locations array doesn't exist or is empty, so we can't match on anything
                    # therefore, we include the result in the output
                    new_results.append(result)
            run["results"] = new_results

    with open(args.output, "w", encoding="UTF-8") as file:
        json.dump(sarif, file, indent=args.indent)


def main():
    parser = argparse.ArgumentParser(prog="filter-sarif")
    parser.add_argument("--input", help="Input SARIF file", required=True)
    parser.add_argument("--output", help="Output SARIF file", required=True)
    parser.add_argument(
        "--split-lines",
        default=False,
        action="store_true",
        help="Split given patterns on newlines.",
    )
    parser.add_argument(
        "--indent", default=None, type=int, help="Indentation level for JSON output."
    )
    parser.add_argument("patterns", help="Inclusion and exclusion patterns.", nargs="+")

    def print_usage():
        print(parser.format_usage())

    args = parser.parse_args()
    filter_sarif(args)


if __name__ == "__main__":
    main()
