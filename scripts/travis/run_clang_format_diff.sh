#!/bin/bash
DIFF=`git diff -U0 $1...$2 -- '*.h' '*.cpp' | clang-format-diff-6.0 -p1`
if [ -z "$DIFF" ]; then
  exit 0
else
  printf "ERROR: clang-format-diff detected formatting issues. Please run clang-format on your branch.\nThe following formatting changes are suggested:\n\n%s" "$DIFF"
  exit 1
fi
