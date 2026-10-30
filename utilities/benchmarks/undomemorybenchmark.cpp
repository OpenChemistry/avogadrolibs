/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Resident memory added by whole-molecule undo steps (2.2 plan M3.1, P§4).
//
// Builds a small molecule with one N^3 cube, then
// makes K edits through RWMolecule::modifyMolecule(), the path used by Open
// Babel operations, crystal edits and every script command. Each edit moves
// one atom. Before copy-on-write every edit deep-copies the cube twice (one
// copy for undo, one for redo); after it, the copies share.
//
// With a Gaussian fchk or Molden file (e.g. avogadrodata/data/fchk/c240.fchk)
// the molecule is read from it instead, so its basis set is copied (or
// shared) as well. Pass a cube edge of 1 to measure the basis set on its own.
//
// Usage: AvogadroUndoMemoryBenchmark [cube-edge=200] [edits=10] [orbitals]
// Measure a Release build without sanitizers or libc++ hardening.

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/mesh.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>

#if defined(__APPLE__)
#include <mach/mach.h>
#elif defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <fstream>
#endif

namespace {

// Current resident set size in bytes, or 0 if unavailable.
std::size_t residentBytes()
{
#if defined(__APPLE__)
  mach_task_basic_info info;
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                reinterpret_cast<task_info_t>(&info), &count) != KERN_SUCCESS)
    return 0;
  return static_cast<std::size_t>(info.resident_size);
#elif defined(_WIN32)
  PROCESS_MEMORY_COUNTERS counters;
  if (!GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters)))
    return 0;
  return static_cast<std::size_t>(counters.WorkingSetSize);
#else
  std::ifstream statm("/proc/self/statm");
  std::size_t pages = 0, resident = 0;
  if (!(statm >> pages >> resident))
    return 0;
  return resident * static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
#endif
}

double mib(std::size_t bytes)
{
  return static_cast<double>(bytes) / (1024.0 * 1024.0);
}

int parseArg(int argc, char** argv, int index, int fallback)
{
  if (argc <= index)
    return fallback;
  char* end = nullptr;
  const long value = std::strtol(argv[index], &end, 10);
  if (end == argv[index] || *end != '\0' || value < 1 || value > 2000)
    return fallback;
  return static_cast<int>(value);
}

} // namespace

int main(int argc, char** argv)
{
  using namespace Avogadro;

  const int edge = parseArg(argc, argv, 1, 200);
  const int edits = parseArg(argc, argv, 2, 10);

  QtGui::Molecule molecule;
  std::size_t basisBytes = 0;
  if (argc > 3) {
    const std::string path(argv[3]);
    const bool molden =
      path.size() > 7 && path.compare(path.size() - 7, 7, ".molden") == 0;
    QuantumIO::GaussianFchk fchk;
    QuantumIO::MoldenFile moldenFile;
    Io::FileFormat& format =
      molden ? static_cast<Io::FileFormat&>(moldenFile) : fchk;
    if (!format.readFile(path, molecule)) {
      std::fprintf(stderr, "could not read %s\n", argv[3]);
      return 1;
    }
    const auto* basis = dynamic_cast<const Core::GaussianSet*>(
      std::as_const(molecule).basisSet());
    if (basis == nullptr) {
      std::fprintf(stderr, "%s has no Gaussian basis set\n", argv[3]);
      return 1;
    }
    // The MO coefficients dominate; the shell data is small.
    for (auto type : { Core::BasisSet::Alpha, Core::BasisSet::Beta })
      basisBytes +=
        static_cast<std::size_t>(basis->moMatrix(type).size()) * sizeof(double);
  } else {
    molecule.addAtom(8).setPosition3d(Vector3(0.0, 0.0, 0.0));
    molecule.addAtom(1).setPosition3d(Vector3(0.96, 0.0, 0.0));
    molecule.addAtom(1).setPosition3d(Vector3(-0.24, 0.93, 0.0));
  }

  Core::Cube* cube = molecule.addCube();
  cube->setLimits(Vector3(-5.0, -5.0, -5.0), Vector3i(edge, edge, edge),
                  10.0 / edge);
  cube->fill(0.5);
  const std::size_t cubeBytes =
    static_cast<std::size_t>(edge) * edge * edge * sizeof(float);

  QtGui::RWMolecule& editable = *molecule.undoMolecule();

  const std::size_t before = residentBytes();
  for (int i = 0; i < edits; ++i) {
    QtGui::Molecule next(molecule);
    next.atom(0).setPosition3d(Vector3(0.01 * (i + 1), 0.0, 0.0));
    editable.modifyMolecule(next,
                            QtGui::Molecule::Atoms | QtGui::Molecule::Moved,
                            QStringLiteral("Benchmark edit"));
  }
  const std::size_t after = residentBytes();

  const double perEdit = edits > 0 ? (mib(after) - mib(before)) / edits : 0.0;
  std::printf("cube edge %d (%.1f MiB), %d edits\n", edge, mib(cubeBytes),
              edits);
  if (basisBytes > 0)
    std::printf("basis set from %s: %zu atoms, MO coefficients %.1f MiB\n",
                argv[3], static_cast<std::size_t>(molecule.atomCount()),
                mib(basisBytes));
  std::printf("RSS before %.1f MiB, after %.1f MiB, growth %.1f MiB\n",
              mib(before), mib(after), mib(after) - mib(before));
  if (basisBytes > 0)
    std::printf("growth per edit %.1f MiB (%.2f MO coefficient sizes)\n",
                perEdit, perEdit / mib(basisBytes));
  else
    std::printf("growth per edit %.1f MiB (%.2f cube sizes)\n", perEdit,
                cubeBytes > 0 ? perEdit / mib(cubeBytes) : 0.0);
  std::printf("undo stack count %d\n", editable.undoStack().count());
  return 0;
}
