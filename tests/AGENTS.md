# tests

GoogleTest unit tests, one directory per library: `core`, `calc`, `io`,
`quantumio`, `rendering`, `qtgui`, `qtopengl`, `qtplugins`. Each directory
builds a single test executable, and `ctest` runs it once per test name with a
`--gtest_filter`.

See the top-level [AGENTS.md](../AGENTS.md) for build commands.

## Adding a test

1. Add the name to the `set(tests ...)` list in that directory's
   `CMakeLists.txt`, for example `Widget`.
2. Create the lowercase source file, `widgettest.cpp`.
3. **Name the test suite `WidgetTest`**: `TEST(WidgetTest, ...)` or
   `TEST_F(WidgetTest, ...)`. ctest runs `--gtest_filter=WidgetTest.*`, so a
   suite with any other name compiles and passes locally when you run the
   executable directly, but **ctest and CI never run it**. If a file needs a
   second suite, or a parameterized one (`TEST_P` names look like
   `Prefix/WidgetTest.case/0`), add an explicit filter as the existing special
   cases in `tests/calc/CMakeLists.txt` and `tests/core/CMakeLists.txt` do.
4. Run it through ctest, not only the executable, to confirm it is picked up:
   `ctest --test-dir build -R Core-Widget -V`.

ctest names are `<Module>-<Name>`, for example `Core-Molecule`,
`Io-Xyz`, `QtGui-RWMolecule`, `QtPlugins-Select`.

## Test data

Sample files come from the
[avogadrodata](https://github.com/OpenChemistry/avogadrodata) repository.
Each directory configures a header (`iotests.h`, `quantumiotests.h`, ...) that
defines `AVOGADRO_DATA`:

```cpp
EXPECT_TRUE(xyz.readFile(AVOGADRO_DATA "/data/xyz/methane.xyz", molecule));
```

A test that needs a new sample file needs a matching change in avogadrodata,
merged first. Keep sample files small.

## What to test

- A regression test for every bug fix, which fails without the fix.
- Degenerate input: no atoms, one atom, coincident or collinear atoms,
  periodic and non-periodic structures, truncated or malformed files.
- For numerical code, compare with an independent value (a finite-difference
  gradient, a literature or reference-program result) and give tolerances
  that are meaningful, with the units in a comment.
- Test library logic directly, without going through the GUI or a file when
  that is not what is being tested.
- `tests/core/shadowmolecule.h` checks that molecule edits keep every value
  attached to the right atom or bond. Use it for changes to `Molecule` or
  `RWMolecule`.
- `tests/qtplugins/` has harnesses for plugin commands and tool interaction;
  see [avogadro/qtplugins/AGENTS.md](../avogadro/qtplugins/AGENTS.md).

## Fuzzing

`fuzz-*.cpp` files and the per-format `fuzz` lists in `tests/io` and
`tests/quantumio` build libFuzzer targets when `ENABLE_FUZZ` is on (or
`LIB_FUZZING_ENGINE` is set, as on OSS-Fuzz), and they run nightly in CI. Fuzz
builds turn off the `FileFormat` exception guard so that escaping exceptions
are reported as crashes. Add a new reader's extension to the fuzz list.
