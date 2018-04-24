#!/bin/bash
DIFF=`git diff -U0 $1...$2 -- '*.h' '*.cpp' | clang-format-diff-3.8 -p1`
if [ -z "$DIFF" ]; then
  exit 0
else
  printf "ERROR: clang-format-diff detected formatting issues. Please run clang-format on your branch.\nThe following formatting changes are suggested:\n\n%s" "$DIFF"
  printf "\n\nThe following is the clang-format configuration:\n%s\n" "`clang-format-3.8 -dump-config`"
  exit 1
fi
