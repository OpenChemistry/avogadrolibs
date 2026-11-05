# Avogadro Libraries: Guide for Contributors and Coding Agents

Avogadro is an open source, cross-platform C++ desktop application for
building, editing and visualizing molecules and materials, running simple
simulations and geometry optimizations, and analyzing results. This repository,
avogadrolibs, holds the libraries and plugins; the application shell lives in
`avogadroapp`.

This file explains how the code is organized and **why**, so that new code
lands in the right place. Each library directory has its own `AGENTS.md` with
the rules that apply there; read the one for the directory you are working in.

## AI use policy

Code needs to be **correct**, particularly for science: force fields, molecular
dynamics, surfaces, orbitals, unit conversions and file parsing all need
careful human review.

Our policy (see [CONTRIBUTING.md](CONTRIBUTING.md#ai-usage)) is that only
**levels 0 and 1** of AI assistance are accepted: autocomplete, and small
snippets or boilerplate that a human reviews in full. Agents are welcome to
explain code, suggest approaches, help debug and help review. A human must
write, or fully understand and own, every line that is contributed, and all
chemistry-specific and mathematical code gets close review. Contributions that
appear to be mostly machine-generated may be rejected.

## Where does this code go?

The libraries are layered so that the non-GUI parts can be used without Qt or
OpenGL. That is not theoretical: the Python package (`pip install avogadro`,
built from [python/](python/)) and the command-line tools in
[avogadro/command/](avogadro/command/) link only `Core`, `Calc`, `IO` and
`QuantumIO`, and the wheel build configures with `USE_QT=OFF` and
`USE_OPENGL=OFF`. A Qt type in `core` breaks those builds.

Ask these questions in order:

1. **Does it compute energies, gradients or charges?** `calc`.
2. **Is it a data structure or algorithm on molecules, with no UI?** It goes in
   `core` (data model, perception, geometry, basis sets, cubes, meshes).
3. **Does it read or write a file format?** `io` for structure and trajectory
   formats; `quantumio` for quantum chemistry program output (orbitals,
   basis sets, spectra).
4. **Does it issue OpenGL calls or define geometry for drawing?** `rendering`.
   It knows about spheres, cylinders and meshes, not molecules.
5. **Does it need Qt, and is it shared by more than one plugin or by
   avogadroapp?** `qtgui` (or `qtopengl` if it needs both Qt and OpenGL).
6. **Is it a user-facing feature: a menu action, an interactive tool or a
   display type?** A new directory under `qtplugins/`.
7. **Does it mainly drive an external program, or is it best written in
   Python?** Consider a Python plugin in its own repository instead of C++
   here (see "A Quick Note About Plugins" in
   [CONTRIBUTING.md](CONTRIBUTING.md)).

If a helper in one plugin is needed by a second plugin, move it into `qtgui`
(or lower, if it has no Qt dependency). Plugins must not include each other's
source files.

## Modules

| Directory | Library | Links against | Purpose |
|-----------|---------|---------------|---------|
| `core/` | `Core` | Eigen (public); spglib, threads (private) | Data model: `Molecule`, `Atom`/`Bond` proxies, `Graph`, `Elements`, `UnitCell`, `Residue`, `Layer`, `BasisSet`, `Cube`, `Mesh` |
| `calc/` | `Calc` | `Core` | `EnergyCalculator` (UFF, Lennard-Jones), optimizers, charge models |
| `io/` | `IO` | `Core` | `FileFormat` readers/writers and `FileFormatManager` |
| `quantumio/` | `QuantumIO` | `IO` | Quantum chemistry outputs: GAMESS, Gaussian, Molden, MOPAC, NWChem, ORCA, QCSchema |
| `rendering/` | `Rendering` | core headers only (no Qt) | OpenGL 4.0 Core scene graph, GLSL shaders, export visitors |
| `qtgui/` | `QtGui` | `IO`, `Calc`, Qt Widgets | `QtGui::Molecule` (signals), `RWMolecule` (undo), plugin base classes, shared widgets |
| `qtopengl/` | `QtOpenGL` | `Rendering`, `QtGui` | `GLWidget` and Qt text rendering |
| `molequeue/` | `MoleQueue` | `QtGui`, Qt Network | Input generator dialogs and the MoleQueue job client |
| `qtplugins/` | one target per plugin | `QtGui` plus whatever it needs | Extensions, tools and scene (display) plugins |
| `command/` | executables | `IO` or `QuantumIO` | Small command-line converters (`avobabel`, `qube`, `avocjsontocml`) |

Some consequences of this layering:

- **`rendering` cannot see a `Molecule`.** Scene plugins in `qtplugins`
  (ball-and-stick, cartoons, surfaces) translate the molecule into geometry
  nodes in `ScenePlugin::process()`. The renderer just draws geometry.
- **Changing an installed header in `qtgui` (or any library) is an API change**
  for avogadroapp and for out-of-tree code. Plugins are leaf nodes and can be
  changed freely.
- **GPL-licensed code may only live in `qtplugins`**, behind the
  `BUILD_GPL_PLUGINS` option (off by default; `qtaim` is the current example).
  The libraries themselves are 3-clause BSD.
- **Optional dependencies** (spglib, libarchive, HDF5, libmsym, MMTF, the
  plotter) sit behind `USE_*` CMake options, and the Python wheel build turns
  most of them off. Code must still compile when they are disabled.

## Rules that apply everywhere

- **Never crash.** No exceptions and no asserts in production code. Validate
  input (especially from files and scripts), check indices and sizes, and
  return an error instead.
- C++17, portable across MSVC, Clang and GCC on Windows, macOS, Linux and BSD.
  Be cautious with the newest library features.
- Qt 6 only. Prefer Qt facilities over Boost or other new dependencies in
  Qt-based code, and ask before adding a third-party library.
- Use `override`, `nullptr`, `constexpr`, `noexcept` and `enum class`. Use C++
  casts (`static_cast`, and `qobject_cast` for QObjects), never C-style casts.
- Prefer smart pointers or Qt parent ownership over manual `new`/`delete`;
  prefer composition over deep inheritance.
- Headers: public includes use angle brackets
  (`#include <avogadro/core/molecule.h>`), local ones use quotes. Order: local,
  other Avogadro modules, Qt (specific classes, not whole modules), STL.
  Forward-declare in headers. Private headers end in `_p.h`. Never put `using`
  in a public header.
- Use descriptive argument names in headers; they show up in IDE completion
  and in the API docs.
- Every user-visible string goes through `tr()` (or `QCoreApplication::translate`
  outside QObjects). Avogadro ships in more than 60 languages.
- In GUI code, prefer non-modal dialogs and dock widgets. A modal dialog
  blocks the RPC interface used for scripting and automation.

### Science and numerics

- **State units in comments and doc strings.** Coordinates are in Ångström;
  energies from energy models are in kJ/mol (users pick display units
  separately).
  Use the constants in [avogadrocore.h](avogadro/core/avogadrocore.h)
  (`BOHR_TO_ANGSTROM`, `HARTREE_TO_EV`, `KCAL_TO_KJ`, `DEG_TO_RAD`, ...)
  rather than literals.
- Consider the degenerate cases: molecules with no atoms, a single atom,
  collinear atoms in angles and dihedrals, coincident atoms, periodic versus
  non-periodic structures, and atoms with no bonds.
- When parsing numbers, use `Core::lexicalCast<double>`/`<float>` from
  [utilities.h](avogadro/core/utilities.h). It is locale-independent, reads
  Fortran `D` exponents and handles subnormals. Do not use `stream >> double`
  or `strtod`, which depend on locale.
- Use `Core::getLine` rather than `std::getline` in parsing loops that wait
  for a blank or sentinel line; `std::getline` does not clear the string at end
  of file, so the loop never ends.

## Build, test and format

Most developers build through the `openchemistry` superbuild; see the
[build instructions](https://two.avogadro.cc/develop/build.html). For a
standalone build:

```sh
cmake -S . -B build -DENABLE_TESTING=ON -DAVOGADRO_DATA_ROOT=/path/to/avogadrodata
cmake --build build
ctest --test-dir build                 # all tests
ctest --test-dir build -R Core-Molecule  # one suite
```

Testing needs a checkout of
[avogadrodata](https://github.com/OpenChemistry/avogadrodata). CMake looks for
it next to avogadrolibs (where the superbuild puts it), then in the
`AVOGADRO_DATA_ROOT` environment variable, and stops with an error if
`ENABLE_TESTING` is on and the data is not found. See
[tests/AGENTS.md](tests/AGENTS.md) for how to add a test.

Before submitting:

- Format the changed lines with `clang-format` (Mozilla-based style in
  [.clang-format](.clang-format)): `git clang-format origin/master`, or the
  pre-commit hook in [.pre-commit-config.yaml](.pre-commit-config.yaml). CI
  rejects formatting differences on changed lines.
- Add a unit test for new behavior and a regression test for each bug fix.
- Build and test with warnings visible, and ideally under a sanitizer: the
  build types `ASAN`, `UBSAN`, `TSAN`, `LSAN` and `MSAN` are defined in
  [cmake/BuildType.cmake](cmake/BuildType.cmake). CI also runs `clang-tidy`
  with the checks in [.clang-tidy](.clang-tidy).
- Commit messages: a short imperative sentence, optionally followed by a blank
  line and details.

## References

- API documentation: https://two.avogadro.cc/develop/classlist.html
- Build guide: https://two.avogadro.cc/develop/build.html
- Forum: https://discuss.avogadro.cc/
- [CONTRIBUTING.md](CONTRIBUTING.md) and [STYLE.md](STYLE.md)
