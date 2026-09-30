# fast_float

Locale-independent, correctly rounded parsing of floating-point numbers
(`fast_float::from_chars`). Used by `Avogadro::Core` (`parseDouble`,
`parseFloat`), because `strtod` follows the C locale that Qt sets from the
environment.

- Upstream: https://github.com/fastfloat/fast_float
- Version: v8.3.0
- Commit: b0ab987b3dfdde13fa1915f65ef2a5c068d9208c
- License: MIT, Apache-2.0 or BSL-1.0 (your choice); see `LICENSE-MIT`,
  `LICENSE-APACHE` and `LICENSE-BOOST`
- The headers are copied unmodified from `include/fast_float/` in the
  upstream tag. Include them as `#include <fast_float/fast_float.h>`.
