/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/mopacaux.h>

#include <algorithm>
#include <cmath>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Molecule;
using Avogadro::QuantumIO::MopacAux;

namespace {

// A minimal AUX file for a two atom molecule: 3N = 6 modes, each holding one
// displacement per atom. Every displacement of mode m is (m, m, m), so a mode
// that has picked up its neighbour's values is obvious. The counts in the
// brackets are numbers of doubles, which is what the reader expects.
std::string twoAtomAux(const std::string& extra = std::string())
{
  std::ostringstream aux;
  aux << " ATOM_EL[2]=\n H H\n"
      << " ATOM_X:ANGSTROMS[6]=\n 0.0 0.0 0.0 0.0 0.0 0.74\n"
      << " VIB._FREQ[6]=\n 100.0 200.0 300.0 400.0 500.0 600.0\n"
      << " NORMAL_MODES[36]=\n";
  for (int mode = 0; mode < 6; ++mode)
    for (int entry = 0; entry < 6; ++entry) // 2 atoms x 3 components
      aux << " " << static_cast<double>(mode);
  aux << "\n" << extra;
  return aux.str();
}

} // namespace

// Regression test: the normal modes arrive flattened, one displacement per
// atom per mode, and must be chunked every atomCount entries. Testing
// i % atomCount == 0 instead produced a first mode holding a single
// displacement and left every later mode straddling two real modes, so the
// animated motion was a mixture of neighbouring modes.
TEST(MopacAuxTest, normalModesAreChunkedPerAtomNotOffByOne)
{
  MopacAux reader;
  Molecule molecule;
  ASSERT_TRUE(reader.readString(twoAtomAux(), molecule));

  ASSERT_EQ(molecule.atomCount(), 2);
  ASSERT_EQ(molecule.vibrationFrequencies().size(), 6u);

  for (int mode = 0; mode < 6; ++mode) {
    auto lx = molecule.vibrationLx(mode);
    ASSERT_EQ(lx.size(), molecule.atomCount()) << "mode " << mode;
    const Vector3 expected(mode, mode, mode);
    for (size_t atom = 0; atom < lx.size(); ++atom)
      EXPECT_EQ(lx[atom], expected) << "mode " << mode << " atom " << atom;
  }
}

// An optimization keeps every step as a conformer.
TEST(MopacAuxTest, optimizationStepsAreKeptAsConformers)
{
  MopacAux reader;
  Molecule molecule;
  ASSERT_TRUE(
    reader.readFile(AVOGADRO_DATA "/data/mopac/diborane.aux", molecule));

  EXPECT_EQ(molecule.atomCount(), 8);
  EXPECT_EQ(molecule.coordinate3dCount(), 51u);
}

// Regression test: the atoms are added from the last block in the file
// (ATOM_X_OPT, the optimized geometry), so the active conformer index has to
// name that set. It was left at 0 - the input geometry - which meant anything
// reading the active conformer, vibrations included, described a different
// structure than the one on screen.
TEST(MopacAuxTest, activeConformerIsTheGeometryOnScreen)
{
  // Every one of these optimizations moves, so conformer 0 and the last
  // conformer are genuinely different structures.
  const char* files[] = { "/data/mopac/diborane.aux", "/data/mopac/c50.aux",
                          "/data/mopac/hexatriene.aux",
                          "/data/mopac/tpy-Ru.aux" };

  for (const char* file : files) {
    MopacAux reader;
    Molecule molecule;
    ASSERT_TRUE(reader.readFile(std::string(AVOGADRO_DATA) + file, molecule))
      << file;
    ASSERT_GT(molecule.coordinate3dCount(), 1u) << file;

    const int active = molecule.coordinate3d();
    EXPECT_EQ(active, static_cast<int>(molecule.coordinate3dCount()) - 1)
      << file;

    // The displayed positions are the active conformer's.
    auto displayed = molecule.atomPositions3d();
    auto activeSet = molecule.coordinate3d(static_cast<size_t>(active));
    ASSERT_EQ(displayed.size(), activeSet.size()) << file;
    for (size_t i = 0; i < displayed.size(); ++i)
      EXPECT_LT((displayed[i] - activeSet[i]).norm(), 1e-9)
        << file << " atom " << i;

    // And the optimization actually moved, so this is not trivially true of
    // any index.
    auto first = molecule.coordinate3d(0);
    double moved = 0.0;
    for (size_t i = 0; i < first.size(); ++i)
      moved = std::max(moved, (first[i] - activeSet[i]).norm());
    EXPECT_GT(moved, 1e-3) << file;
  }
}

// The same chunking check against a real FORCE calculation. Acetylene is
// linear D(inf)h with the chain H(3)-C(0)#C(1)-H(2), so its modes have
// symmetry that a mis-chunked array cannot reproduce.
TEST(MopacAuxTest, acetyleneNormalModesArePhysical)
{
  MopacAux reader;
  Molecule molecule;
  ASSERT_TRUE(
    reader.readFile(AVOGADRO_DATA "/data/mopac/acetylene.aux", molecule));

  ASSERT_EQ(molecule.atomCount(), 4);
  // 3N modes, and they belong to the geometry the molecule opens on - the
  // frame MOPAC reorients to for the vibrational analysis.
  ASSERT_TRUE(molecule.hasVibrations());
  auto frequencies = molecule.vibrationFrequencies();
  ASSERT_EQ(frequencies.size(), 12u);
  for (int mode = 0; mode < 12; ++mode)
    ASSERT_EQ(molecule.vibrationLx(mode).size(), molecule.atomCount())
      << "mode " << mode;

  // The C#C stretch: the carbons move against each other along the axis and
  // dominate the motion.
  EXPECT_NEAR(frequencies[4], 2235.93, 0.05);
  auto cc = molecule.vibrationLx(4);
  EXPECT_LT(cc[0][0] * cc[1][0], 0.0);               // opposite directions
  EXPECT_GT(std::abs(cc[0][0]), std::abs(cc[2][0])); // carbon over hydrogen

  // The lowest modes are the translations, where every atom moves the same
  // way. A mode array chunked one entry out of step cannot produce this.
  auto translation = molecule.vibrationLx(7);
  EXPECT_LT(std::abs(frequencies[7]), 1.0);
  for (size_t atom = 1; atom < translation.size(); ++atom)
    EXPECT_GT(translation[atom][0] * translation[0][0], 0.0) << "atom " << atom;

  // The 939 cm-1 pair is the cis bend: both carbons move one way and both
  // hydrogens the other, perpendicular to the molecular axis.
  EXPECT_NEAR(frequencies[2], 939.35, 0.05);
  auto bend = molecule.vibrationLx(2);
  EXPECT_GT(bend[0][1] * bend[1][1], 0.0); // carbons together
  EXPECT_GT(bend[2][1] * bend[3][1], 0.0); // hydrogens together
  EXPECT_LT(bend[0][1] * bend[2][1], 0.0); // against each other
}

// Regression test: a job holding more than one Hessian must keep each against
// the geometry it was computed at, rather than appending them into one list
// of twice the modes the molecule has.
TEST(MopacAuxTest, separateHessiansDoNotAccumulate)
{
  // A second geometry followed by a second Hessian.
  std::ostringstream second;
  second << " ATOM_X:ANGSTROMS[6]=\n 0.0 0.0 0.0 0.0 0.0 0.80\n"
         << " VIB._FREQ[6]=\n 110.0 210.0 310.0 410.0 510.0 610.0\n"
         << " NORMAL_MODES[36]=\n";
  for (int mode = 0; mode < 6; ++mode)
    for (int entry = 0; entry < 6; ++entry)
      second << " " << static_cast<double>(mode);
  second << "\n";

  MopacAux reader;
  Molecule molecule;
  ASSERT_TRUE(reader.readString(twoAtomAux(second.str()), molecule));

  ASSERT_EQ(molecule.atomCount(), 2);
  ASSERT_EQ(molecule.coordinate3dCount(), 2u);

  // Each Hessian keeps its own modes, against its own geometry.
  ASSERT_EQ(molecule.vibrationConformerCount(), 2u);
  EXPECT_EQ(molecule.vibrationFrequencies(0).size(), 6u);
  EXPECT_EQ(molecule.vibrationFrequencies(1).size(), 6u);
  EXPECT_EQ(molecule.vibrationFrequencies(0)[0], 100.0);
  EXPECT_EQ(molecule.vibrationFrequencies(1)[0], 110.0);
}
