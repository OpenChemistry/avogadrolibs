# gemmi (CIF reader and writer only, header-only)

Upstream: https://github.com/project-gemmi/gemmi
Commit: 97c8082 (2026-09-22)

This is the header-only CIF reader and writer of gemmi, a library for
macromolecular and small-molecule crystallography. It reads CIF,
small-molecule CIF and mmCIF files into a generic block/loop/pair document
(`gemmi/cif.hpp`) and writes such a document back (`gemmi/to_cif.hpp`).
There are no compiled sources, no zlib, and nothing for mmCIF models, MTZ or
CCP4 maps. It keeps gemmi's layout so `#include <gemmi/cif.hpp>` works.

## Contents

- `include/gemmi/`: `cif.hpp` (reader), `cifdoc.hpp` (document), `to_cif.hpp`
  (writer), `atox.hpp`, `fail.hpp`,
  `fileutil.hpp`, `iterator.hpp`, `util.hpp`, and `utf.hpp` (included by
  `fileutil.hpp` only under `_WIN32`).
- `include/gemmi/third_party/tao/`: the whole PEGTL 2.8.3 tree as shipped by
  gemmi (including the Windows-only headers), not just the closure of
  `cif.hpp` on one platform.
- `LICENSE.txt`: gemmi's license.

All files are unmodified copies of the upstream files.

## Deliberately excluded

`numb.hpp` and gemmi's `third_party/fast_float.h` are not bundled. Gemmi's
copy is fast_float 8.2, and avogadrolibs already bundles fast_float 8.3 in the
same `fast_float` namespace. Two different copies in one library are an ODR
violation. Do not include `<gemmi/numb.hpp>`; parse numbers with Avogadro's
own parser.

## Usage notes

Gemmi throws `std::runtime_error` on syntax errors (and for some invalid
lookups), so callers must catch it.

## Licenses

- gemmi: MPL-2.0 (`LICENSE.txt`)
- PEGTL: MIT (`include/gemmi/third_party/tao/LICENSE`)

## Updating

1. Check out the new gemmi commit.
2. Copy the listed headers from `include/gemmi/`, and replace the whole
   `include/gemmi/third_party/tao/` tree. Copy `LICENSE.txt` and update the
   commit above.
3. Check that every quoted include resolves, from `thirdparty/gemmi/include`:

       for f in $(find . -type f); do d=$(dirname $f)
         grep -h '#\s*include "' $f | sed 's/.*include "\([^"]*\)".*/\1/' |
         while read i; do
           [ -e "$d/$i" ] || [ -e "$i" ] || [ -e "gemmi/$i" ] ||
             echo "MISSING in $f: $i"
         done
       done

   Two hits are expected and come from upstream itself: a commented-out
   `contrib/tracer.hpp` include in `cif.hpp`, and
   `internal/file_mapper_win32.hpp` in `mmap_input.hpp`, which gemmi does not
   ship and nothing reaches. Anything else means a header is missing.
4. Also run the preprocessor with `-D_WIN32` and
   `-D_MSC_VER=1930` added to catch headers reached only on Windows.
5. Build and run the `GemmiCifTest` cases in `tests/io/gemmiciftest.cpp`.
