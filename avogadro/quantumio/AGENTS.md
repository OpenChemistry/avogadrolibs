# avogadro/quantumio

Readers for quantum chemistry program output: GAMESS, Gaussian (formatted
checkpoint and cube), Molden, MOPAC `.aux`, NWChem (log and JSON), ORCA,
QCSchema, and `GenericOutput`, which picks one of these for generic `.out` and
`.log` files. They fill in basis sets, molecular orbitals, densities,
vibrations, spectra and energies, as well as geometry.

See the top-level [AGENTS.md](../../AGENTS.md) and
[io/AGENTS.md](../io/AGENTS.md); every rule there about untrusted input
applies here too.

## Why it is separate

These formats are built on `IO` (they are `FileFormat` subclasses), but they
mostly populate the quantum side of `Core` (`GaussianSet`, `SlaterSet`,
`Cube`) and use nlohmann JSON. Keeping them out of `IO` keeps the core format
library small. `QuantumIO` has no Qt dependency and is used by the Python
package and the `qube` command-line tool.

They are **not** registered by `FileFormatManager`. The GUI registers them in
the `Surfaces` plugin (`qtplugins/surfaces/surfaces.cpp`), and the Python
bindings register most of them in `python/io.cpp`. The `qube` tool has its own
list in `main()` in `avogadro/command/qube.cpp`. Add a new reader to the GUI
and Python lists, to `qube` if it should be readable with `qube -i`, and to
`GenericOutput` if it should handle `.out` and `.log` files.

## This code needs human review

Basis-set and orbital code is easy to get subtly wrong. A coefficient in the
wrong order or a missing normalization still gives orbitals that render, just
the wrong ones. Check every change against the program's documentation and
against a reference result.

- **AO ordering and normalization differ between programs** (Cartesian versus
  spherical functions, the order of d, f and g components, and whether
  contraction coefficients are already normalized). Write down which
  convention the program uses and convert it explicitly.
- **Units:** coordinates in these files are often in Bohr; store Ångström
  (`BOHR_TO_ANGSTROM`). Record the energy unit you actually stored with
  `Core::setEnergyUnit()`: what the values are after any conversion, not what
  the file said.
- Programs print several geometries, energies and frequency blocks in one
  file (optimizations, multi-job inputs). Decide which one you are reading and
  test with a file that has more than one.
- Size fields in a file (number of basis functions, MOs, grid points) are
  untrusted: check them against the rest of the file before allocating.

## Tests

`tests/quantumio/` has a test per reader, using sample outputs from
avogadrodata. Add the extension to the `fuzz` list in
[tests/quantumio/CMakeLists.txt](../../tests/quantumio/CMakeLists.txt). The
list holds extensions, not format names; QCSchema's extension is `qcjson`.
