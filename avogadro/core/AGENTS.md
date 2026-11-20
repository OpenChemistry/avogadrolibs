# avogadro/core

The data model and the algorithms that run on it: `Molecule`, `Atom`/`Bond`,
`Graph`, `Elements`, `UnitCell`, `Residue`, `Layer`, basis sets, `Cube`,
`Mesh`, ring and bond-order perception, symmetry helpers.

See the top-level [AGENTS.md](../../AGENTS.md) for the module map and the
rules that apply everywhere.

## Why it is separate

`Core` is linked by everything, including the Python package, the
command-line tools and the Qt-free wheel build. Anything added here must build
with only the C++ standard library and Eigen.

- **No Qt, no OpenGL, no new public dependencies.** spglib and threads are
  linked privately, and spglib is optional (`USE_SPGLIB`). Code that uses an
  optional dependency must compile when it is turned off.
- If you need a `QString`, a signal or an undo command, the code belongs in
  `qtgui`, not here.

## Things to know

- **`Atom` and `Bond` are proxies**: an index plus a pointer to the molecule.
  They are invalidated when atoms or bonds are removed.
- **Removing an atom moves the last atom into the freed index** (swap and pop).
  When removing several atoms, remove from the highest index down. In GUI code,
  `QtGui::Molecule` adds unique IDs and `PersistentAtom` for references that
  must survive removals.
- **Per-atom data lives in parallel arrays.** If you add a new per-atom array
  to `Molecule`, update every place that keeps them parallel: `addAtom`,
  `removeAtom`, `swapAtom`, `clearAtoms`, copy and move, and
  `QtGui::RWMolecule`'s undo commands. Missing one causes out-of-bounds reads
  later, far from the bug.
- **Optional per-atom arrays may be shorter than `atomCount()`** (labels,
  formal charges, colors, ...): an atom added after the array was last set has
  no entry. Check the size before indexing.
- **`Core::Array` is copy-on-write.** Copies are cheap until written to, and
  any non-const access detaches. Hold `const` references
  (`const auto& positions = molecule.atomPositions3d();`) to avoid copies.
  In a hot write loop, call `data()` once before the loop and write through
  the pointer: every non-const `operator[]` re-checks whether the storage is
  shared, which is several times slower per element.
- Use `Real`, `Vector3` and friends from [avogadrocore.h](avogadrocore.h) and
  [vector.h](vector.h), and the unit constants in `avogadrocore.h`.
- Shared parsing helpers live in [utilities.h](utilities.h): `lexicalCast`,
  `getLine`, `split`, `trimmed`. File formats use them, so keep them free of
  locale dependence.

## Tests

`tests/core/` has a test file per class (`moleculetest.cpp` and so on) and
libFuzzer harnesses (`fuzz-*.cpp`).
[shadowmolecule.h](../../tests/core/shadowmolecule.h) is a simple reference
model used by `moleculetest.cpp` and `tests/qtgui/rwmoleculetest.cpp` to check
that every value stays attached to the right atom or bond through add, swap,
remove, copy, move, undo and redo. Extend it when you add per-atom or per-bond
data.
