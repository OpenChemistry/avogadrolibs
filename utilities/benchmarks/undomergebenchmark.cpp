/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Time taken by undo commands that merge (2.2 plan M3.5).
//
//   select N          selects every atom of an N-atom molecule one at a time,
//                     as a "select all" plugin does, then undoes and redoes.
//   drag N MOVES      an interactive drag: MOVES sweeps over all N atoms,
//                     each atom moved with its own setAtomPosition3d() call.
//
// Times are in milliseconds. Measure a Release build.
//
// Usage: AvogadroUndoMergeBenchmark select N
//        AvogadroUndoMergeBenchmark drag N MOVES

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

using Clock = std::chrono::steady_clock;

double elapsedMs(Clock::time_point start)
{
  return std::chrono::duration<double, std::milli>(Clock::now() - start)
    .count();
}

bool parseCount(const char* text, long& value)
{
  char* end = nullptr;
  value = std::strtol(text, &end, 10);
  return end != text && *end == '\0' && value >= 1 && value <= 100000000L;
}

void fill(Avogadro::QtGui::Molecule& molecule, long atoms)
{
  for (long i = 0; i < atoms; ++i) {
    molecule.addAtom(6, Avogadro::Vector3(0.1 * static_cast<double>(i), 0.5,
                                          0.25 * static_cast<double>(i % 7)));
  }
}

int runSelect(long atoms)
{
  using namespace Avogadro;
  QtGui::Molecule molecule;
  fill(molecule, atoms);
  QtGui::RWMolecule& editable = *molecule.undoMolecule();

  auto start = Clock::now();
  for (long i = 0; i < atoms; ++i)
    editable.setAtomSelected(static_cast<Index>(i), true);
  const double select = elapsedMs(start);

  const int count = editable.undoStack().count();
  bool allSelected = true;
  for (long i = 0; i < atoms; ++i)
    allSelected = allSelected && molecule.atomSelected(i);

  start = Clock::now();
  editable.undoStack().undo();
  const double undo = elapsedMs(start);
  bool noneSelected = true;
  for (long i = 0; i < atoms; ++i)
    noneSelected = noneSelected && !molecule.atomSelected(i);

  start = Clock::now();
  editable.undoStack().redo();
  const double redo = elapsedMs(start);
  bool selectedAgain = true;
  for (long i = 0; i < atoms; ++i)
    selectedAgain = selectedAgain && molecule.atomSelected(i);

  std::printf("select %ld atoms\n", atoms);
  std::printf("select %.1f ms, undo %.1f ms, redo %.1f ms\n", select, undo,
              redo);
  std::printf("undo stack count %d\n", count);
  const bool ok = allSelected && noneSelected && selectedAgain;
  std::printf("check %s\n", ok ? "ok" : "FAILED");
  return ok ? 0 : 1;
}

int runDrag(long atoms, long moves)
{
  using namespace Avogadro;
  QtGui::Molecule molecule;
  fill(molecule, atoms);
  QtGui::RWMolecule& editable = *molecule.undoMolecule();

  Core::Array<Vector3> original = molecule.atomPositions3d();

  editable.setInteractive(true);
  auto start = Clock::now();
  for (long move = 1; move <= moves; ++move) {
    for (long i = 0; i < atoms; ++i) {
      editable.setAtomPosition3d(
        static_cast<Index>(i),
        original[i] + Vector3(0.01 * static_cast<double>(move), 0.0, 0.0));
    }
  }
  const double drag = elapsedMs(start);
  editable.setInteractive(false);

  const int count = editable.undoStack().count();

  start = Clock::now();
  editable.undoStack().undo();
  const double undo = elapsedMs(start);
  bool restored = true;
  for (long i = 0; i < atoms; ++i)
    restored = restored && molecule.atomPosition3d(i) == original[i];

  start = Clock::now();
  editable.undoStack().redo();
  const double redo = elapsedMs(start);
  const Vector3 expected =
    original[0] + Vector3(0.01 * static_cast<double>(moves), 0.0, 0.0);
  const bool redone = molecule.atomPosition3d(0) == expected;

  std::printf("drag %ld atoms x %ld sweeps (%ld calls)\n", atoms, moves,
              atoms * moves);
  std::printf("drag %.1f ms, undo %.1f ms, redo %.1f ms\n", drag, undo, redo);
  std::printf("undo stack count %d\n", count);
  const bool ok = restored && redone && count == 1;
  std::printf("check %s\n", ok ? "ok" : "FAILED");
  return ok ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
  long atoms = 0;
  long moves = 0;
  if (argc == 3 && std::strcmp(argv[1], "select") == 0 &&
      parseCount(argv[2], atoms))
    return runSelect(atoms);
  if (argc == 4 && std::strcmp(argv[1], "drag") == 0 &&
      parseCount(argv[2], atoms) && parseCount(argv[3], moves))
    return runDrag(atoms, moves);

  std::fprintf(stderr, "usage: %s select N\n       %s drag N MOVES\n", argv[0],
               argv[0]);
  return 2;
}
