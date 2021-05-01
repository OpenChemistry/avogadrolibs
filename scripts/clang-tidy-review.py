#!/usr/bin/env python3

# clang-tidy review
# Copyright (c) 2020 Peter Hill
# SPDX-License-Identifier: MIT
# See LICENSE for more information

import argparse
import itertools
import fnmatch
import json
import os
from operator import itemgetter
import pprint
import re
import requests
import subprocess
import textwrap
import unidiff
from github import Github

BAD_CHARS_APT_PACKAGES_PATTERN = "[;&|($]"
DIFF_HEADER_LINE_LENGTH = 5


def make_file_line_lookup(diff):
    """Get a lookup table for each file in diff, to convert between source
    line number to line number in the diff

    """
    lookup = {}
    for file in diff:
        filename = file.target_file[2:]
        lookup[filename] = {}
        for hunk in file:
            for line in hunk:
                if line.diff_line_no is None:
                    continue
                if not line.is_removed:
                    lookup[filename][line.target_line_no] = (
                        line.diff_line_no - DIFF_HEADER_LINE_LENGTH
                    )
    return lookup


def make_review(contents, lookup):
    """Construct a Github PR review given some warnings and a lookup table"""
    root = os.getcwd()
    comments = []
    for num, line in enumerate(contents):
        if "warning" in line:
            if line.startswith("warning"):
                # Some warnings don't have the file path, skip them
                # FIXME: Find a better way to handle this
                continue
            full_path, source_line, _, warning = line.split(":", maxsplit=3)
            rel_path = os.path.relpath(full_path, root)
            body = ""
            for line2 in contents[num + 1 :]:
                if "warning" in line2:
                    break
                body += "\n" + line2.replace(full_path, rel_path)

            comment_body = f"""{warning.strip().replace("'", "`")}

```cpp
{textwrap.dedent(body).strip()}
```
"""
            try:
                comments.append(
                    {
                        "path": rel_path,
                        "body": comment_body,
                        "position": lookup[rel_path][int(source_line)],
                    }
                )
            except KeyError:
                print(
                    f"WARNING: Skipping comment for file '{rel_path}' not in PR changeset. Comment body is:\n{comment_body}"
                )

    review = {
        "body": "clang-tidy made some suggestions",
        "event": "COMMENT",
        "comments": comments,
    }
    return review


def get_pr_diff(repo, pr_number, token):
    """Download the PR diff, return a list of PatchedFile"""

    headers = {
        "Accept": "application/vnd.github.v3.diff",
        "Authorization": f"token {token}",
    }
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"

    pr_diff_response = requests.get(url, headers=headers)
    pr_diff_response.raise_for_status()

    # PatchSet is the easiest way to construct what we want, but the
    # diff_line_no property on lines is counted from the top of the
    # whole PatchSet, whereas GitHub is expecting the "position"
    # property to be line count within each file's diff. So we need to
    # do this little bit of faff to get a list of file-diffs with
    # their own diff_line_no range
    diff = [
        unidiff.PatchSet(str(file))[0]
        for file in unidiff.PatchSet(pr_diff_response.text)
    ]
    return diff


def get_line_ranges(diff, files):
    """Return the line ranges of added lines in diff, suitable for the
    line-filter argument of clang-tidy

    """

    lines_by_file = {}
    for filename in diff:
        if filename.target_file[2:] not in files:
            continue
        added_lines = []
        for hunk in filename:
            for line in hunk:
                if line.is_added:
                    added_lines.append(line.target_line_no)

        for _, group in itertools.groupby(
            enumerate(added_lines), lambda ix: ix[0] - ix[1]
        ):
            groups = list(map(itemgetter(1), group))
            lines_by_file.setdefault(filename.target_file[2:], []).append(
                [groups[0], groups[-1]]
            )

    line_filter_json = []
    for name, lines in lines_by_file.items():
        line_filter_json.append(str({"name": name, "lines": lines}))
    return json.dumps(line_filter_json, separators=(",", ":"))


def get_clang_tidy_warnings(
    line_filter, build_dir, clang_tidy_checks, clang_tidy_binary, files
):
    """Get the clang-tidy warnings"""

    command = f"{clang_tidy_binary} -p={build_dir} -checks={clang_tidy_checks} -line-filter={line_filter} {files}"
    print(f"Running:\n\t{command}")

    try:
        output = subprocess.run(
            command, capture_output=True, shell=True, check=True, encoding="utf-8"
        )
    except subprocess.CalledProcessError as e:
        print(
            f"\n\nclang-tidy failed with return code {e.returncode} and error:\n{e.stderr}\nOutput was:\n{e.stdout}"
        )
        raise

    return output.stdout.splitlines()


def post_lgtm_comment(pull_request):
    """Post a "LGTM" comment if everything's clean, making sure not to spam"""

    BODY = 'clang-tidy review says "All clean, LGTM! :+1:"'

    comments = pull_request.get_issue_comments()

    for comment in comments:
        if comment.body == BODY:
            print("Already posted, no need to update")
            return

    pull_request.create_issue_comment(BODY)


def cull_comments(pull_request, review, max_comments):
    """Remove comments from review that have already been posted, and keep
    only the first max_comments

    """

    comments = pull_request.get_review_comments()

    for comment in comments:
        review["comments"] = list(
            filter(
                lambda review_comment: not (
                    review_comment["path"] == comment.path
                    and review_comment["position"] == comment.position
                    and review_comment["body"] == comment.body
                ),
                review["comments"],
            )
        )

    if len(review["comments"]) > max_comments:
        review["body"] += (
            "\n\nThere were too many comments to post at once. "
            f"Showing the first {max_comments} out of {len(review['comments'])}. "
            "Check the log or trigger a new build to see more."
        )
        review["comments"] = review["comments"][:max_comments]

    return review


def main(
    repo,
    pr_number,
    build_dir,
    clang_tidy_checks,
    clang_tidy_binary,
    token,
    include,
    exclude,
    max_comments,
):

    diff = get_pr_diff(repo, pr_number, token)
    print(f"\nDiff from GitHub PR:\n{diff}\n")

    changed_files = [filename.target_file[2:] for filename in diff]
    files = []
    for pattern in include:
        files.extend(fnmatch.filter(changed_files, pattern))
        print(f"include: {pattern}, file list now: {files}")
    for pattern in exclude:
        files = [f for f in files if not fnmatch.fnmatch(f, pattern)]
        print(f"exclude: {pattern}, file list now: {files}")

    if files == []:
        print("No files to check!")
        return

    print(f"Checking these files: {files}", flush=True)

    line_ranges = get_line_ranges(diff, files)
    if line_ranges == "[]":
        print("No lines added in this PR!")
        return

    print(f"Line filter for clang-tidy:\n{line_ranges}\n")

    clang_tidy_warnings = get_clang_tidy_warnings(
        line_ranges, build_dir, clang_tidy_checks, clang_tidy_binary, " ".join(files)
    )
    print("clang-tidy had the following warnings:\n", clang_tidy_warnings, flush=True)

    lookup = make_file_line_lookup(diff)
    review = make_review(clang_tidy_warnings, lookup)

    print("Created the following review:\n", pprint.pformat(review), flush=True)

    github = Github(token)
    repo = github.get_repo(f"{repo}")
    pull_request = repo.get_pull(pr_number)

    if review["comments"] == []:
        post_lgtm_comment(pull_request)
        return

    print("Removing already posted or extra comments", flush=True)
    trimmed_review = cull_comments(pull_request, review, max_comments)

    print(f"::set-output name=total_comments::{len(review['comments'])}")

    if trimmed_review["comments"] == []:
        print("Everything already posted!")
        return review

    print("Posting the review:\n", pprint.pformat(trimmed_review), flush=True)
    pull_request.create_review(**trimmed_review)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create a review from clang-tidy warnings"
    )
    parser.add_argument("--repo", help="Repo name in form 'owner/repo'")
    parser.add_argument("--pr", help="PR number", type=int)
    parser.add_argument(
        "--clang_tidy_binary", help="clang-tidy binary", default="clang-tidy-11"
    )
    parser.add_argument(
        "--build_dir", help="Directory with compile_commands.json", default="."
    )
    parser.add_argument(
        "--path_prefix", help="Directory path to remove from filenames", default=""
    )
    parser.add_argument(
        "--src_dir", help="Directory path to source files", default=""
    )
    parser.add_argument(
        "--clang_tidy_checks",
        help="checks argument",
        default="'-*,performance-*,readability-*,bugprone-*,clang-analyzer-*,cppcoreguidelines-*,mpi-*,misc-*'",
    )
    parser.add_argument(
        "--include",
        help="Comma-separated list of files or patterns to include",
        type=str,
        nargs="?",
        default="*.[ch],*.[ch]xx,*.[ch]pp,*.[ch]++,*.cc,*.hh",
    )
    parser.add_argument(
        "--exclude",
        help="Comma-separated list of files or patterns to exclude",
        nargs="?",
        default="",
    )
    parser.add_argument(
        "--apt-packages",
        help="Comma-separated list of apt packages to install",
        type=str,
        default="",
    )
    parser.add_argument(
        "--max-comments",
        help="Maximum number of comments to post at once",
        type=int,
        default=25,
    )
    parser.add_argument("--token", help="github auth token")

    args = parser.parse_args()

    # Remove any enclosing quotes and extra whitespace
    exclude = args.exclude.strip(""" "'""").split(",")
    include = args.include.strip(""" "'""").split(",")

    if args.apt_packages:
        # Try to make sure only 'apt install' is run
        apt_packages = re.split(BAD_CHARS_APT_PACKAGES_PATTERN, args.apt_packages)[
            0
        ].split(",")
        print("Installing additional packages:", apt_packages)
        subprocess.run(
            ["apt", "install", "-y", "--no-install-recommends"] + apt_packages
        )

    build_compile_commands = f"{args.build_dir}/compile_commands.json"

    if os.path.exists(build_compile_commands):
        print(f"Found '{build_compile_commands}', updating absolute paths")
        # We might need to change some absolute paths if we're inside
        # a docker container
        with open(build_compile_commands, "r") as f:
            compile_commands = json.load(f)

        original_directory = compile_commands[0]["directory"]

        if args.path_prefix:
            basedir = args.path_prefix
        else:
            # directory should either end with the build directory,
            # unless it's '.', in which case use all of directory
            if original_directory.endswith(args.build_dir):
                build_dir_index = -(len(args.build_dir) + 1)
            elif args.build_dir == ".":
                build_dir_index = -1
            else:
                raise RuntimeError(
                    f"compile_commands.json contains absolute paths that I don't know how to deal with: '{original_directory}'"
                )
            basedir = original_directory[:build_dir_index]

        if args.src_dir:
            newbasedir = args.src_dir
        else:
            newbasedir = os.getcwd()

        print(f"Replacing '{basedir}' with '{newbasedir}'", flush=True)
        print("Current directory: ", os.listdir(os.getcwd()))

        modified_compile_commands = json.dumps(compile_commands).replace(
            basedir, newbasedir
        )

        with open(build_compile_commands, "w") as f:
            f.write(modified_compile_commands)

    main(
        repo=args.repo,
        pr_number=args.pr,
        build_dir=args.build_dir,
        clang_tidy_checks=args.clang_tidy_checks,
        clang_tidy_binary=args.clang_tidy_binary,
        token=args.token,
        include=include,
        exclude=exclude,
        max_comments=args.max_comments,
    )
