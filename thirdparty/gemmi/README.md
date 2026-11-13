# gemmi (trimmed copy)

Upstream: https://github.com/project-gemmi/gemmi
Commit: 97c8082 (2026-09-22)

This is a subset of gemmi, a library for macromolecular and small-molecule
crystallography, built as a small static library. It serves:

- CIF parsing (`cif.hpp`, `cifdoc.hpp`, `numb.hpp`), header-only
- small-molecule CIF (`smcif.hpp`)
- mmCIF and PDB (`mmcif.hpp`, `mmread.hpp`)
- CCP4/MRC density maps (`ccp4.hpp`)
- MTZ reflection files and the MTZ-to-map FFT (`mtz.hpp`, `fourier.hpp`)

## Contents

- `include/gemmi/`: the header closure of the headers above plus
  `calculate.hpp`, and the headers the `.cpp` files below include. It keeps
  gemmi's layout so `#include <gemmi/cif.hpp>` works.
- `include/gemmi/third_party/`: PEGTL 2.8.3 (`tao/`), fast_float and
  pocketfft, only the files in the closure.
- `src/`: `symmetry.cpp`, `mmcif.cpp`, `polyheur.cpp`, `resinfo.cpp`,
  `mtz.cpp`, `sprintf.cpp`, `gz.cpp`
- `third_party/stb_sprintf.h`: included by `src/sprintf.cpp`
- `zlib/`: gemmi's zlib 1.3.2 subset (inflate and gzip reading only), used
  only when no system zlib is found

All files are unmodified copies of the upstream files.

## Licenses

- gemmi: MPL-2.0 (`LICENSE.txt`)
- PEGTL: MIT (`include/gemmi/third_party/tao/LICENSE`)
- fast_float: Apache-2.0 / MIT / BSL-1.0 (see the header)
- pocketfft: BSD-3-Clause (see the header)
- stb_sprintf: public domain / MIT (see the header)
- zlib: zlib license (`zlib/LICENSE`)

## Updating

1. Check out the new gemmi commit.
2. List the headers the bundled features need and copy them:

       c++ -std=c++17 -I<gemmi>/include -M probe.cpp

   where `probe.cpp` includes `cif.hpp smcif.hpp mmcif.hpp mmread.hpp mtz.hpp
   ccp4.hpp fourier.hpp numb.hpp calculate.hpp`. Run the same command on each
   `.cpp` file in `src/` (add `-I<gemmi>/third_party`) to catch headers only
   they include.
3. Copy the `.cpp` files, `third_party/stb_sprintf.h`, `third_party/zlib/` and
   `LICENSE.txt`, update the commit above, and build the `GemmiTest` cases in
   `tests/io/gemmitest.cpp`.
