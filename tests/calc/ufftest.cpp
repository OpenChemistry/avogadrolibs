/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/uff.h>
#include <avogadro/calc/uffdata.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/xyzformat.h>

#include <cctype>
#include <cmath>
#include <iterator>
#include <string>
#include <vector>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using namespace Avogadro;

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Core::UnitCell;
using Avogadro::Io::XyzFormat;

// basic idea - go through a bunch of molecules
// calculate gradients and numeric gradients
// make sure the gradients are close for each atom

// Use a parameterized test fixture
class UffGradientTest : public ::testing::TestWithParam<const char*>
{};

// Parameterized test that works with any molecule file
TEST_P(UffGradientTest, GradientComparison)
{
  const char* filename = GetParam();

  XyzFormat xyz;
  Molecule molecule;

  std::string filepath = std::string(AVOGADRO_DATA) + "/data/xyz/" + filename;
  EXPECT_TRUE(xyz.readFile(filepath, molecule));
  ASSERT_EQ(xyz.error(), std::string());
  ASSERT_GT(molecule.atomCount(), 0);

  UFF uff;
  uff.setMolecule(&molecule);

  // get the positions
  unsigned int n = molecule.atomCount();
  Core::Array<Vector3> pos = molecule.atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> positions(p, 3 * n);

  Eigen::VectorXd analytical = Eigen::VectorXd::Zero(3 * n);
  Eigen::VectorXd numeric = Eigen::VectorXd::Zero(3 * n);
  uff.gradient(positions, analytical);
  uff.finiteGradient(positions, numeric);

  // assert that the components of each are finite
  ASSERT_TRUE(analytical.allFinite());
  ASSERT_TRUE(numeric.allFinite());

  // check numeric to analytic gradient for all atoms in a molecule
  for (int i = 0; i < 3 * n; i++) {
    // are these components within 10% of each other?
    EXPECT_NEAR(analytical[i], numeric[i],
                std::max(2.5e-5, 0.1 * std::fabs(analytical[i])));
  }
}

TEST_P(UffGradientTest, EvaluateMatchesValueAndGradient)
{
  const char* filename = GetParam();

  XyzFormat xyz;
  Molecule molecule;
  std::string filepath = std::string(AVOGADRO_DATA) + "/data/xyz/" + filename;
  EXPECT_TRUE(xyz.readFile(filepath, molecule));
  ASSERT_EQ(xyz.error(), std::string());
  ASSERT_GT(molecule.atomCount(), 0);

  UFF uff;
  uff.setMolecule(&molecule);

  const unsigned int n = molecule.atomCount();
  Core::Array<Vector3> pos = molecule.atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> positions(p, 3 * n);

  const Real expectedEnergy = uff.value(positions);
  Eigen::VectorXd expectedGradient = Eigen::VectorXd::Zero(3 * n);
  uff.gradient(positions, expectedGradient);

  Eigen::VectorXd fusedGradient(1); // intentional wrong size to validate resize
  const Real fusedEnergy = uff.evaluate(positions, &fusedGradient);

  EXPECT_NEAR(fusedEnergy, expectedEnergy,
              std::max(1e-8, 1e-10 * std::fabs(expectedEnergy)));
  ASSERT_EQ(fusedGradient.size(), expectedGradient.size());
  for (int i = 0; i < expectedGradient.size(); ++i) {
    EXPECT_NEAR(fusedGradient[i], expectedGradient[i],
                std::max(1e-7, 1e-8 * std::fabs(expectedGradient[i])));
  }
}

// Instantiate the test suite with different molecule files
INSTANTIATE_TEST_SUITE_P(
  UffTest, UffGradientTest,
  ::testing::Values("acetylene.xyz", "c2h2f2.xyz", "methane.xyz",
                    "formaldehyde.xyz", "H2O.xyz", "H2S.xyz", "H2Se.xyz",
                    "hooh.xyz", "PF5.xyz", "SF4.xyz", "SF6.xyz", "XeF4.xyz"
                    // Add more molecule files here as needed
                    ));

// XeF4.xyz (above) has trans F-Xe-F angles within 1e-7 radians of 180
// degrees, where the gradient used to be dropped. Check a distorted copy too.
TEST(UffGradientDistortedTest, XenonTetrafluoride)
{
  XyzFormat xyz;
  Molecule molecule;
  std::string filepath = std::string(AVOGADRO_DATA) + "/data/xyz/XeF4.xyz";
  ASSERT_TRUE(xyz.readFile(filepath, molecule));
  ASSERT_EQ(molecule.atomCount(), 5u);

  // deterministic displacements of a few tenths of an Angstrom
  const double shifts[5][3] = { { 0.05, -0.03, 0.04 },
                                { 0.20, 0.15, -0.10 },
                                { -0.15, 0.25, 0.20 },
                                { 0.10, -0.20, 0.15 },
                                { -0.25, -0.10, -0.20 } };
  for (Index i = 0; i < 5; ++i) {
    molecule.setAtomPosition3d(
      i, molecule.atomPosition3d(i) +
           Vector3(shifts[i][0], shifts[i][1], shifts[i][2]));
  }

  UFF uff;
  uff.setMolecule(&molecule);
  ASSERT_EQ(uff.atomTypeLabel(0), "Xe4+4");

  const Eigen::Index n = 3 * 5;
  Core::Array<Vector3> pos = molecule.atomPositions3d();
  Eigen::Map<Eigen::VectorXd> positions(pos[0].data(), n);
  Eigen::VectorXd analytical = Eigen::VectorXd::Zero(n);
  Eigen::VectorXd numeric = Eigen::VectorXd::Zero(n);
  uff.gradient(positions, analytical);
  uff.finiteGradient(positions, numeric);
  ASSERT_TRUE(analytical.allFinite());
  ASSERT_TRUE(numeric.allFinite());
  for (Eigen::Index i = 0; i < n; ++i) {
    EXPECT_NEAR(analytical[i], numeric[i],
                std::max(2.5e-5, 0.1 * std::fabs(analytical[i])));
  }
}

// Restraints are documented in kJ/mol (core/constraint.h), the same units as
// the UFF energy, so adding one must raise the energy by exactly k * delta^2
// and the gradient by the restraint's own gradient.
TEST(UffConstraintTest, RestraintEnergyAndGradientAreInKilojoules)
{
  Molecule molecule;
  Atom o = molecule.addAtom(8);
  Atom h1 = molecule.addAtom(1);
  Atom h2 = molecule.addAtom(1);
  o.setPosition3d(Vector3(0.0, 0.0, 0.0));
  h1.setPosition3d(Vector3(1.0, 0.1, 0.0));
  h2.setPosition3d(Vector3(-0.2, 0.95, 0.05));
  molecule.addBond(o, h1, 1);
  molecule.addBond(o, h2, 1);

  Eigen::VectorXd x(9);
  for (Index i = 0; i < 3; ++i)
    x.segment<3>(3 * i) = molecule.atomPosition3d(i);

  UFF uff;
  uff.setMolecule(&molecule);
  Eigen::VectorXd grad0;
  const Real e0 = uff.evaluate(x, &grad0);

  // O-H1 distance restraint 0.1 A shorter than the current bond
  const Vector3 oh = x.segment<3>(3) - x.segment<3>(0);
  const Real distance = oh.norm();
  const Real distanceDelta = 0.1;
  const Real distanceK = 50.0; // kJ/mol/A^2
  Constraint bond(0, 1, MaxIndex, MaxIndex, distance - distanceDelta);
  bond.setK(distanceK);

  // H1-O-H2 angle restraint 5 degrees smaller than the current angle
  const Vector3 oh2 = x.segment<3>(6) - x.segment<3>(0);
  const Real angle = std::acos(oh.dot(oh2) / (oh.norm() * oh2.norm()));
  const Real angleDelta = 5.0 * DEG_TO_RAD_D;
  const Real angleK = 20.0; // kJ/mol/rad^2
  Constraint bend(1, 0, 2, MaxIndex, (angle - angleDelta) / DEG_TO_RAD_D);
  bend.setK(angleK);

  uff.setConstraints({ bond, bend });
  Eigen::VectorXd grad1;
  const Real e1 = uff.evaluate(x, &grad1);

  const Real expected = distanceK * distanceDelta * distanceDelta +
                        angleK * angleDelta * angleDelta;
  EXPECT_NEAR(e1 - e0, expected, 1e-9);
  EXPECT_NEAR(uff.value(x) - e0, expected, 1e-9);

  // the distance restraint alone pulls H1 toward O by 2 k delta
  uff.setConstraints({ bond });
  Eigen::VectorXd grad2;
  uff.evaluate(x, &grad2);
  const Vector3 expectedH1 = 2.0 * distanceK * distanceDelta * oh / distance;
  for (int i = 0; i < 3; ++i) {
    EXPECT_NEAR(grad2[3 + i] - grad0[3 + i], expectedH1[i], 1e-9);
    EXPECT_NEAR(grad2[i] - grad0[i], -expectedH1[i], 1e-9);
  }
}

namespace {
Molecule bentWater()
{
  Molecule molecule;
  Atom o = molecule.addAtom(8);
  Atom h1 = molecule.addAtom(1);
  Atom h2 = molecule.addAtom(1);
  o.setPosition3d(Vector3(0.0, 0.0, 0.0));
  h1.setPosition3d(Vector3(1.2, 0.1, 0.0));
  h2.setPosition3d(Vector3(-0.2, 1.1, 0.05));
  molecule.addBond(o, h1, 1);
  molecule.addBond(o, h2, 1);
  return molecule;
}

Eigen::VectorXd positionsOf(const Molecule& molecule)
{
  Eigen::VectorXd x(3 * molecule.atomCount());
  for (Index i = 0; i < molecule.atomCount(); ++i)
    x.segment<3>(3 * i) = molecule.atomPosition3d(i);
  return x;
}
} // namespace

// Same contract as LennardJonesTest.SetMoleculeUsesFrozenAtomMask
TEST(UffMaskTest, SetMoleculeUsesFrozenAtomMask)
{
  Molecule molecule = bentWater();
  molecule.setFrozenAtom(0, true);

  UFF uff;
  uff.setMolecule(&molecule);

  const Eigen::VectorXd mask = uff.mask();
  ASSERT_EQ(mask.rows(), 9);
  EXPECT_TRUE(mask.head<3>().isZero());
  EXPECT_TRUE(mask.tail<6>().isOnes());

  // the frozen atom feels no force
  Eigen::VectorXd grad;
  uff.gradient(positionsOf(molecule), grad);
  EXPECT_TRUE(grad.head<3>().isZero());
  EXPECT_FALSE(grad.tail<6>().isZero());
}

TEST(UffMaskTest, SetMoleculeWithoutFrozenAtomsFreesEveryAtom)
{
  Molecule molecule = bentWater();

  UFF uff;
  uff.setMolecule(&molecule);

  const Eigen::VectorXd mask = uff.mask();
  ASSERT_EQ(mask.rows(), 9);
  EXPECT_TRUE(mask.isOnes());
}

TEST(UffMaskTest, SetMaskAfterSetMoleculeOverridesAndSetMoleculeResets)
{
  Molecule molecule = bentWater();
  UFF uff;
  uff.setMolecule(&molecule);

  Eigen::VectorXd mask = Eigen::VectorXd::Ones(9);
  mask.segment<3>(3).setZero(); // freeze H1
  uff.setMask(mask);
  Eigen::VectorXd grad;
  uff.gradient(positionsOf(molecule), grad);
  EXPECT_TRUE(grad.segment<3>(3).isZero());

  // a new setMolecule() starts again from the molecule's frozen atoms
  uff.setMolecule(&molecule);
  EXPECT_TRUE(uff.mask().isOnes());
}

TEST(UffMaskTest, SingleAtomMoleculeGetsMaskOfTheRightSize)
{
  Molecule molecule;
  molecule.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  UFF uff;
  uff.setMolecule(&molecule);
  EXPECT_EQ(uff.mask().rows(), 3);
}

// ---- UFF atom typing and parameter table ----------------------------------

namespace {
// The leading element symbol of a UFF label. One-letter symbols are padded
// ("C_3", "I_", "H_b"); two-letter symbols are not ("Cl", "Ti3+4", "He4+4").
std::string labelSymbol(const std::string& label)
{
  std::string symbol = label.substr(0, 1);
  if (label.size() > 1 && std::islower(static_cast<unsigned char>(label[1])))
    symbol += label[1];
  return symbol;
}

// Find the (first) row of uffparams with this label, or -1.
int rowForLabel(const std::string& label)
{
  for (size_t i = 0; i < std::size(uffparams); ++i) {
    if (uffparams[i].label == label)
      return static_cast<int>(i);
  }
  return -1;
}

// The UFF atom type labels the molecule's atoms are given.
std::vector<std::string> uffTypes(Molecule& molecule)
{
  UFF uff;
  uff.setMolecule(&molecule);
  std::vector<std::string> types;
  for (Index i = 0; i < molecule.atomCount(); ++i)
    types.push_back(uff.atomTypeLabel(i));
  return types;
}

// Add an atom at the given position and return its index.
Index addAt(Molecule& molecule, unsigned char z, double x, double y, double zz)
{
  Atom atom = molecule.addAtom(z);
  atom.setPosition3d(Vector3(x, y, zz));
  return atom.index();
}

void bond(Molecule& molecule, Index a, Index b, unsigned char order = 1)
{
  molecule.addBond(a, b, order);
}
} // namespace

// Every row's element number must agree with the symbol in its label. This is
// the regression test for Sb..Lr being one atomic number too low.
TEST(UffTableTest, ElementNumbersMatchLabels)
{
  int previous = 0;
  for (const parameter& row : uffparams) {
    if (row.element == 0) // "Du" dummy atom
      continue;
    std::string expected = Elements::symbol(row.element);
    // the original UFF paper (and Open Babel) label lawrencium "Lw"
    if (row.element == 103)
      expected = "Lw";
    EXPECT_EQ(labelSymbol(row.label), expected)
      << "row " << row.label << " has element " << row.element;
    // rows are grouped by element in increasing order
    EXPECT_GE(row.element, previous) << row.label;
    previous = row.element;
  }
}

TEST(UffTableTest, EveryElementFrom1To103HasAType)
{
  for (int z = 1; z <= 103; ++z) {
    bool found = false;
    for (const parameter& row : uffparams)
      found = found || row.element == z;
    EXPECT_TRUE(found) << "no UFF row for element " << z;
  }
  // and nothing beyond Lr
  for (const parameter& row : uffparams)
    EXPECT_LE(row.element, 103) << row.label;
}

TEST(UffTableTest, SupportedElementsCoverTheTable)
{
  UFF uff;
  for (int z = 1; z <= 103; ++z)
    EXPECT_TRUE(uff.elements().test(z)) << "element " << z;
  EXPECT_FALSE(uff.elements().test(104));
}

// For every element, whatever the bonding (single, double or triple bond to
// the same element, or six hydrogens), the type must belong to that element.
// The coordination scan used to run into the next element's rows.
TEST(UffTypingTest, EveryElementGetsOneOfItsOwnTypes)
{
  for (int z = 1; z <= 103; ++z) {
    for (int order = 1; order <= 3; ++order) {
      Molecule molecule;
      Index a = addAt(molecule, static_cast<unsigned char>(z), 0.0, 0.0, 0.0);
      Index b = addAt(molecule, static_cast<unsigned char>(z), 2.0, 0.0, 0.0);
      bond(molecule, a, b, static_cast<unsigned char>(order));
      for (const std::string& type : uffTypes(molecule)) {
        int row = rowForLabel(type);
        ASSERT_GE(row, 0) << "Z=" << z << " order " << order << ": '" << type
                          << "'";
        EXPECT_EQ(uffparams[row].element, z)
          << "Z=" << z << " order " << order << " got " << type;
      }
    }

    // six hydrogens around the element (octahedron)
    Molecule molecule;
    Index center =
      addAt(molecule, static_cast<unsigned char>(z), 0.0, 0.0, 0.0);
    const double dirs[6][3] = { { 1, 0, 0 },  { -1, 0, 0 }, { 0, 1, 0 },
                                { 0, -1, 0 }, { 0, 0, 1 },  { 0, 0, -1 } };
    for (int count = 1; count <= 6; ++count) {
      const double* d = dirs[count - 1];
      Index h = addAt(molecule, 1, 2.0 * d[0], 2.0 * d[1], 2.0 * d[2]);
      bond(molecule, center, h);
      std::vector<std::string> types = uffTypes(molecule);
      ASSERT_FALSE(types.empty());
      int row = rowForLabel(types[0]);
      ASSERT_GE(row, 0) << "Z=" << z << " with " << count << " ligands";
      EXPECT_EQ(uffparams[row].element, z)
        << "Z=" << z << " with " << count << " ligands got " << types[0];
    }
  }
}

TEST(UffTypingTest, AtomsBeyondLawrenciumHaveNoType)
{
  Molecule molecule;
  Index a = addAt(molecule, 104, 0.0, 0.0, 0.0);
  Index b = addAt(molecule, 1, 1.5, 0.0, 0.0);
  bond(molecule, a, b);
  EXPECT_EQ(uffTypes(molecule)[0], "");
}

// Sulfur with two double bonds (SO2). Rappe et al. (1992) and the Open Babel
// UFF.prm comment ("S+4 (SO2)") give S_3+4. (Open Babel itself assigns
// S_3+2 here because its SMARTS needs an explicit +4 formal charge.)
TEST(UffTypingTest, SulfurDioxide)
{
  Molecule molecule;
  Index s = addAt(molecule, 16, 0.0, 0.0, 0.0);
  Index o1 = addAt(molecule, 8, 1.43, 0.0, 0.0);
  Index o2 = addAt(molecule, 8, -0.7, 1.25, 0.0);
  bond(molecule, s, o1, 2);
  bond(molecule, s, o2, 2);
  std::vector<std::string> types = uffTypes(molecule);
  EXPECT_EQ(types[0], "S_3+4");
  EXPECT_EQ(types[1], "O_2");
  EXPECT_EQ(types[2], "O_2");
}

// Sulfuric acid, drawn with two S=O. The UFF.prm comment gives S_3+6
// ("SO3 / H2SO4"); Open Babel itself assigns S_3+2.
TEST(UffTypingTest, SulfuricAcid)
{
  Molecule molecule;
  Index s = addAt(molecule, 16, 0.0, 0.0, 0.0);
  Index o1 = addAt(molecule, 8, 1.4, 0.0, 0.0);
  Index o2 = addAt(molecule, 8, -1.4, 0.0, 0.0);
  Index o3 = addAt(molecule, 8, 0.0, 1.6, 0.0);
  Index o4 = addAt(molecule, 8, 0.0, -1.6, 0.0);
  bond(molecule, s, o1, 2);
  bond(molecule, s, o2, 2);
  bond(molecule, s, o3);
  bond(molecule, s, o4);
  EXPECT_EQ(uffTypes(molecule)[0], "S_3+6");

  // The same molecule with only single bonds, as when S=O bonds were never
  // perceived (e.g., from XYZ). Types follow the bond order sum, so this gets
  // S_3+4; that is a bond perception problem, not a typing one.
  Molecule single;
  Index s2 = addAt(single, 16, 0.0, 0.0, 0.0);
  for (int k = 0; k < 4; ++k) {
    Index o = addAt(single, 8, k < 2 ? (k ? 1.5 : -1.5) : 0.0,
                    k >= 2 ? (k == 2 ? 1.5 : -1.5) : 0.0, 0.0);
    bond(single, s2, o);
  }
  EXPECT_EQ(uffTypes(single)[0], "S_3+4");
}

// Dimethyl sulfoxide: S(=O) with two carbons is tetrahedral-like S(IV);
// S_3+4 (it used to get the planar thione type S_2).
TEST(UffTypingTest, DimethylSulfoxide)
{
  Molecule molecule;
  Index s = addAt(molecule, 16, 0.0, 0.0, 0.0);
  Index o = addAt(molecule, 8, 0.0, 0.0, 1.5);
  Index c1 = addAt(molecule, 6, 1.8, 0.0, -0.5);
  Index c2 = addAt(molecule, 6, -0.9, 1.6, -0.5);
  bond(molecule, s, o, 2);
  bond(molecule, s, c1);
  bond(molecule, s, c2);
  std::vector<std::string> types = uffTypes(molecule);
  EXPECT_EQ(types[0], "S_3+4");
  EXPECT_EQ(types[2], "C_3");
}

// A thioketone sulfur keeps the planar sp2 type, and divalent sulfur the
// generic type.
TEST(UffTypingTest, ThioneAndThioether)
{
  Molecule thione;
  Index c = addAt(thione, 6, 0.0, 0.0, 0.0);
  Index s = addAt(thione, 16, 1.6, 0.0, 0.0);
  bond(thione, c, s, 2);
  EXPECT_EQ(uffTypes(thione)[1], "S_2");

  Molecule thioether;
  Index c1 = addAt(thioether, 6, -1.0, 1.0, 0.0);
  Index s2 = addAt(thioether, 16, 0.0, 0.0, 0.0);
  Index c2 = addAt(thioether, 6, 1.0, 1.0, 0.0);
  bond(thioether, c1, s2);
  bond(thioether, s2, c2);
  EXPECT_EQ(uffTypes(thioether)[1], "S_3+2");
}

// Trimethyl phosphate O=P(OMe)3. UFF P_3+5 is the 109.47 degree
// pentavalent phosphorus (Open Babel only assigns it to five-coordinate P and
// gives this P_3+3). It used to run past the P rows and get S_2.
TEST(UffTypingTest, Phosphate)
{
  Molecule molecule;
  Index p = addAt(molecule, 15, 0.0, 0.0, 0.0);
  Index o = addAt(molecule, 8, 0.0, 0.0, 1.5);
  bond(molecule, p, o, 2);
  for (int k = 0; k < 3; ++k) {
    double angle = 2.0 * PI_D * k / 3.0;
    Index ester =
      addAt(molecule, 8, 1.6 * std::cos(angle), 1.6 * std::sin(angle), -0.5);
    bond(molecule, p, ester);
  }
  std::vector<std::string> types = uffTypes(molecule);
  EXPECT_EQ(types[0], "P_3+5");
  EXPECT_EQ(types[1], "O_2");
  EXPECT_EQ(types[2], "O_3");

  // phosphine stays P_3+3
  Molecule phosphine;
  Index p3 = addAt(phosphine, 15, 0.0, 0.0, 0.0);
  for (int k = 0; k < 3; ++k) {
    double angle = 2.0 * PI_D * k / 3.0;
    Index h =
      addAt(phosphine, 1, 1.4 * std::cos(angle), 1.4 * std::sin(angle), -0.4);
    bond(phosphine, p3, h);
  }
  EXPECT_EQ(uffTypes(phosphine)[0], "P_3+3");
}

// Benzonitrile: the nitrile C and N are sp (C_1, N_1) and must not be changed
// to sp2 / resonant types by the resonance pass just because the ipso carbon
// is aromatic.
TEST(UffTypingTest, BenzonitrileKeepsSpTypes)
{
  Molecule molecule;
  Index ring[6];
  for (int k = 0; k < 6; ++k) {
    double angle = 2.0 * PI_D * k / 6.0;
    ring[k] =
      addAt(molecule, 6, 1.4 * std::cos(angle), 1.4 * std::sin(angle), 0.0);
  }
  for (int k = 0; k < 6; ++k)
    bond(molecule, ring[k], ring[(k + 1) % 6], (k % 2 == 0) ? 2 : 1);
  Index c = addAt(molecule, 6, 2.86, 0.0, 0.0);
  Index n = addAt(molecule, 7, 4.02, 0.0, 0.0);
  bond(molecule, ring[0], c);
  bond(molecule, c, n, 3);

  std::vector<std::string> types = uffTypes(molecule);
  for (int k = 0; k < 6; ++k)
    EXPECT_EQ(types[ring[k]], "C_R");
  EXPECT_EQ(types[c], "C_1");
  EXPECT_EQ(types[n], "N_1");
}

// Allene and ketene: the central sp carbon next to sp2 atoms stays C_1.
TEST(UffTypingTest, AlleneAndKeteneKeepSpCarbon)
{
  Molecule allene;
  Index c1 = addAt(allene, 6, -1.3, 0.0, 0.0);
  Index c2 = addAt(allene, 6, 0.0, 0.0, 0.0);
  Index c3 = addAt(allene, 6, 1.3, 0.0, 0.0);
  bond(allene, c1, c2, 2);
  bond(allene, c2, c3, 2);
  std::vector<std::string> types = uffTypes(allene);
  EXPECT_EQ(types[1], "C_1");
  EXPECT_EQ(types[0], "C_2");

  Molecule ketene;
  Index cc = addAt(ketene, 6, -1.3, 0.0, 0.0);
  Index cm = addAt(ketene, 6, 0.0, 0.0, 0.0);
  Index o = addAt(ketene, 8, 1.2, 0.0, 0.0);
  bond(ketene, cc, cm, 2);
  bond(ketene, cm, o, 2);
  types = uffTypes(ketene);
  EXPECT_EQ(types[1], "C_1");
  EXPECT_EQ(types[2], "O_2");
}

// XeF4 must use Xe4+4. Xe has atomic number 54; the table used to have it at
// 53 (and Cs at 54), so Xe was typed as I and Cs as Xe...
TEST(UffTypingTest, XenonTetrafluoride)
{
  Molecule molecule;
  Index xe = addAt(molecule, 54, 0.0, 0.0, 0.0);
  const double dirs[4][2] = { { 1, 0 }, { -1, 0 }, { 0, 1 }, { 0, -1 } };
  for (const auto& d : dirs) {
    Index f = addAt(molecule, 9, 1.95 * d[0], 1.95 * d[1], 0.0);
    bond(molecule, xe, f);
  }
  std::vector<std::string> types = uffTypes(molecule);
  EXPECT_EQ(types[0], "Xe4+4");
  EXPECT_EQ(types[1], "F_");

  Molecule cesiumChloride;
  Index cs = addAt(cesiumChloride, 55, 0.0, 0.0, 0.0);
  Index cl = addAt(cesiumChloride, 17, 3.0, 0.0, 0.0);
  bond(cesiumChloride, cs, cl);
  EXPECT_EQ(uffTypes(cesiumChloride)[0], "Cs");
}

// SF4 (four single bonds, bond order sum 4) is S(IV): S_3+4. SF6 has six
// neighbors: S_3+6 (UFF.prm: S+4 for SO2, S+6 for SO3 / H2SO4).
TEST(UffTypingTest, SulfurFluorides)
{
  Molecule sf4;
  Index s = addAt(sf4, 16, 0.0, 0.0, 0.0);
  const double dirs[6][3] = { { 1, 0, 0 },  { -1, 0, 0 }, { 0, 1, 0 },
                              { 0, -1, 0 }, { 0, 0, 1 },  { 0, 0, -1 } };
  for (int k = 0; k < 4; ++k)
    bond(sf4, s,
         addAt(sf4, 9, 1.6 * dirs[k][0], 1.6 * dirs[k][1], 1.6 * dirs[k][2]));
  EXPECT_EQ(uffTypes(sf4)[0], "S_3+4");

  Molecule sf6;
  Index s6 = addAt(sf6, 16, 0.0, 0.0, 0.0);
  for (int k = 0; k < 6; ++k)
    bond(sf6, s6,
         addAt(sf6, 9, 1.6 * dirs[k][0], 1.6 * dirs[k][1], 1.6 * dirs[k][2]));
  EXPECT_EQ(uffTypes(sf6)[0], "S_3+6");
}

// Rappe et al. (1992) / UFF.prm: B_2 is trigonal planar, B_3 tetrahedral.
TEST(UffTypingTest, BoronCoordination)
{
  Molecule bf3;
  Index b = addAt(bf3, 5, 0.0, 0.0, 0.0);
  for (int k = 0; k < 3; ++k) {
    double angle = 2.0 * PI_D * k / 3.0;
    bond(bf3, b,
         addAt(bf3, 9, 1.3 * std::cos(angle), 1.3 * std::sin(angle), 0.0));
  }
  EXPECT_EQ(uffTypes(bf3)[0], "B_2");

  Molecule bf4; // tetrafluoroborate
  Index b4 = addAt(bf4, 5, 0.0, 0.0, 0.0);
  const double tet[4][3] = {
    { 1, 1, 1 }, { 1, -1, -1 }, { -1, 1, -1 }, { -1, -1, 1 }
  };
  for (const auto& t : tet)
    bond(bf4, b4, addAt(bf4, 9, 0.8 * t[0], 0.8 * t[1], 0.8 * t[2]));
  EXPECT_EQ(uffTypes(bf4)[0], "B_3");
}

// H_ for an isolated or terminal hydrogen, H_b only for a bridging hydrogen
// (more than one bond), as in diborane.
TEST(UffTypingTest, HydrogenBridging)
{
  Molecule atom; // a lone H atom has no bonds (no force field is set up for
                 // one atom, so pair it with a non-bonded H)
  addAt(atom, 1, 0.0, 0.0, 0.0);
  addAt(atom, 1, 5.0, 0.0, 0.0);
  EXPECT_EQ(uffTypes(atom)[0], "H_");

  Molecule h2;
  Index h1 = addAt(h2, 1, 0.0, 0.0, 0.0);
  Index h1b = addAt(h2, 1, 0.74, 0.0, 0.0);
  bond(h2, h1, h1b);
  EXPECT_EQ(uffTypes(h2)[0], "H_");

  // B2H6: two bridging H (two bonds each), four terminal H
  Molecule b2h6;
  Index b1 = addAt(b2h6, 5, -0.88, 0.0, 0.0);
  Index b2 = addAt(b2h6, 5, 0.88, 0.0, 0.0);
  Index hb1 = addAt(b2h6, 1, 0.0, 0.0, 0.98);
  Index hb2 = addAt(b2h6, 1, 0.0, 0.0, -0.98);
  bond(b2h6, b1, hb1);
  bond(b2h6, b2, hb1);
  bond(b2h6, b1, hb2);
  bond(b2h6, b2, hb2);
  Index t1 = addAt(b2h6, 1, -1.5, 1.0, 0.0);
  Index t2 = addAt(b2h6, 1, -1.5, -1.0, 0.0);
  bond(b2h6, b1, t1);
  bond(b2h6, b1, t2);
  std::vector<std::string> types = uffTypes(b2h6);
  EXPECT_EQ(types[hb1], "H_b");
  EXPECT_EQ(types[hb2], "H_b");
  EXPECT_EQ(types[t1], "H_");
  EXPECT_EQ(types[t2], "H_");
  EXPECT_EQ(types[b1], "B_3"); // four neighbors
}

// ---- Angle and inversion terms against their own energies -----------------

namespace {
using TermEnergy = Real (UFF::*)(const Eigen::VectorXd&);
using TermGradient = void (UFF::*)(const Eigen::VectorXd&, Eigen::VectorXd&);

// Maximum |analytic - central finite difference| of one energy term, given as
// the UFF member functions for its energy and gradient. Both are in the units
// of that term's energy (they share the UFF scaling). The default positions
// are the molecule's own and the default step is 1e-5.
double maxTermGradientError(
  Molecule& molecule, TermEnergy energy, TermGradient gradient,
  const Eigen::VectorXd& positions = Eigen::VectorXd(), double h = 1.0e-5)
{
  UFF uff;
  uff.setMolecule(&molecule);
  const Eigen::VectorXd x =
    positions.size() > 0 ? positions : positionsOf(molecule);
  const Eigen::Index n = x.size();

  Eigen::VectorXd analytic = Eigen::VectorXd::Zero(n);
  (uff.*gradient)(x, analytic);

  double worst = 0.0;
  for (Eigen::Index c = 0; c < n; ++c) {
    Eigen::VectorXd xp = x;
    Eigen::VectorXd xm = x;
    xp[c] += h;
    xm[c] -= h;
    const double fd = ((uff.*energy)(xp) - (uff.*energy)(xm)) / (2.0 * h);
    worst = std::max(worst, std::fabs(fd - analytic[c]));
  }
  return worst;
}
} // namespace

// A seven-coordinate center has no UFF angle form (Rappe et al. only define
// up to octahedral), so the angle energy is harmonic, k * (theta - theta0)^2.
// The analytic gradient must be the derivative of exactly that. Si3 with
// seven ligands reaches the fallback branch ("Other").
TEST(UffAngleTest, SevenCoordinateFallbackGradientMatchesEnergy)
{
  Molecule molecule;
  Index center = addAt(molecule, 14, 0.0, 0.0, 0.0);
  // pentagonal bipyramid, with some distortion so no angle is 180 degrees
  for (int k = 0; k < 5; ++k) {
    double a = 2.0 * PI_D * k / 5.0 + 0.05 * k;
    bond(
      molecule, center,
      addAt(molecule, 1, 1.5 * std::cos(a), 1.5 * std::sin(a), 0.1 * (k - 2)));
  }
  bond(molecule, center, addAt(molecule, 1, 0.1, 0.2, 1.5));
  bond(molecule, center, addAt(molecule, 1, -0.2, 0.1, -1.5));
  EXPECT_EQ(uffTypes(molecule)[0], "Si3");

  const double error =
    maxTermGradientError(molecule, &UFF::angleEnergy, &UFF::angleGradient);
  EXPECT_LT(error, 1.0e-4);
}

// Inversion terms for P, As, Sb and Bi: E = K (C0 + C1 cos w + C2 cos 2w) with
// C1 = -4 C2 cos w0 so that the minimum is at w0 (Rappe et al. 1992), and
// C0 chosen so E(w0) = 0.
TEST(UffOopTest, BismuthGradientMatchesEnergy)
{
  Molecule molecule;
  Index bi = addAt(molecule, 83, 0.0, 0.0, 0.0);
  bond(molecule, bi, addAt(molecule, 1, 1.9, 0.1, 0.05));
  bond(molecule, bi, addAt(molecule, 1, 0.15, 1.8, -0.1));
  bond(molecule, bi, addAt(molecule, 1, -0.1, 0.2, 1.85));
  EXPECT_EQ(uffTypes(molecule)[0], "Bi3+3");

  const double error =
    maxTermGradientError(molecule, &UFF::oopEnergy, &UFF::oopGradient);
  EXPECT_LT(error, 1.0e-4);
}

// Bi has w0 = 90 degrees: three mutually perpendicular bonds. The inversion
// energy must be zero there (it was evaluated at 90 radians before).
TEST(UffOopTest, BismuthEnergyIsZeroAtEquilibrium)
{
  Molecule molecule;
  Index bi = addAt(molecule, 83, 0.0, 0.0, 0.0);
  bond(molecule, bi, addAt(molecule, 1, 1.9, 0.0, 0.0));
  bond(molecule, bi, addAt(molecule, 1, 0.0, 1.9, 0.0));
  bond(molecule, bi, addAt(molecule, 1, 0.0, 0.0, 1.9));
  UFF uff;
  uff.setMolecule(&molecule);
  const Eigen::VectorXd x = positionsOf(molecule);
  EXPECT_NEAR(uff.oopEnergy(x), 0.0, 1.0e-9);
}

// The same for P (w0 = 84.4339): scan the H-P-H angle for the minimum of the
// inversion energy, which must be zero.
TEST(UffOopTest, PhosphorusMinimumEnergyIsZero)
{
  double lowest = 1.0e9;
  for (double deg = 80.0; deg <= 100.0; deg += 0.005) {
    const double a = deg * DEG_TO_RAD_D;
    // three equivalent bonds of length 1.4 with mutual angle a
    const double cz = std::sqrt((1.0 + 2.0 * std::cos(a)) / 3.0);
    const double rho = std::sqrt(1.0 - cz * cz);
    Molecule molecule;
    Index p = addAt(molecule, 15, 0.0, 0.0, 0.0);
    for (int k = 0; k < 3; ++k) {
      const double phi = 2.0 * PI_D * k / 3.0;
      bond(molecule, p,
           addAt(molecule, 1, 1.4 * rho * std::cos(phi),
                 1.4 * rho * std::sin(phi), 1.4 * cz));
    }
    UFF uff;
    uff.setMolecule(&molecule);
    const Eigen::VectorXd x = positionsOf(molecule);
    lowest = std::min(lowest, uff.oopEnergy(x));
  }
  EXPECT_NEAR(lowest, 0.0, 1.0e-4);
}

// Exactly collinear F-Xe-F (a perfect square): the gradient must stay finite
// and the angle term (zero force at 180 degrees) must not disturb the bonds.
TEST(UffGradientDistortedTest, ExactlySquarePlanarXenonTetrafluoride)
{
  Molecule molecule;
  Index xe = addAt(molecule, 54, 0.0, 0.0, 0.0);
  const double dirs[4][2] = { { 1, 0 }, { -1, 0 }, { 0, 1 }, { 0, -1 } };
  for (const auto& d : dirs)
    bond(molecule, xe, addAt(molecule, 9, 2.0 * d[0], 2.0 * d[1], 0.0));
  UFF uff;
  uff.setMolecule(&molecule);
  const Eigen::VectorXd x = positionsOf(molecule);
  Eigen::VectorXd grad = Eigen::VectorXd::Zero(15);
  uff.angleGradient(x, grad);
  EXPECT_TRUE(grad.allFinite());
  EXPECT_LT(grad.cwiseAbs().maxCoeff(), 1.0e-6);
}

// ---- Torsion terms ---------------------------------------------------------

namespace {
// A molecule plus a rigid group of atoms that can be twisted about an axis.
struct Twistable
{
  Molecule molecule;
  std::vector<Index> moving;
  Vector3 origin = Vector3::Zero();
  Vector3 axis = Vector3::UnitX();

  // positions with the moving group rotated by `degrees` about the axis
  Eigen::VectorXd positions(double degrees) const
  {
    Eigen::VectorXd x = positionsOf(molecule);
    const Eigen::AngleAxisd rotation(degrees * DEG_TO_RAD_D, axis.normalized());
    for (Index a : moving) {
      const Vector3 p = x.segment<3>(3 * a);
      x.segment<3>(3 * a) = origin + rotation * (p - origin);
    }
    return x;
  }

  // the torsion energy (kcal/mol) at a twist angle
  double energy(double degrees)
  {
    UFF uff;
    uff.setMolecule(&molecule);
    return uff.torsionEnergy(positions(degrees));
  }

  double gradientError(double degrees)
  {
    return maxTermGradientError(molecule, &UFF::torsionEnergy,
                                &UFF::torsionGradient, positions(degrees));
  }
};

double paramU(const char* label)
{
  return uffparams[rowForLabel(label)].Uj;
}

// Three hydrogens exactly 120 degrees apart about the x axis, for a methyl
// carbon at the origin
std::vector<Vector3> methylHydrogens()
{
  std::vector<Vector3> hydrogens;
  for (int k = 0; k < 3; ++k) {
    const double a = 2.0 * PI_D * k / 3.0 + 0.5 * PI_D;
    hydrogens.push_back(Vector3(-0.36, 1.03 * std::sin(a), 1.03 * std::cos(a)));
  }
  return hydrogens;
}

// H2C=CH2, twisting one CH2 about the C=C bond
Twistable ethene()
{
  Twistable t;
  Molecule& m = t.molecule;
  Index c0 = addAt(m, 6, 0.0, 0.0, 0.0);
  Index c1 = addAt(m, 6, 1.34, 0.0, 0.0);
  bond(m, c0, c1, 2);
  bond(m, c0, addAt(m, 1, -0.55, 0.93, 0.0));
  bond(m, c0, addAt(m, 1, -0.55, -0.93, 0.0));
  Index h4 = addAt(m, 1, 1.89, 0.93, 0.0);
  Index h5 = addAt(m, 1, 1.89, -0.93, 0.0);
  bond(m, c1, h4);
  bond(m, c1, h5);
  t.moving = { h4, h5 };
  return t;
}

// s-trans 1,3-butadiene, twisting one vinyl group about the central bond
Twistable butadiene()
{
  Twistable t;
  Molecule& m = t.molecule;
  Index c0 = addAt(m, 6, -0.67, 1.16, 0.0);
  Index c1 = addAt(m, 6, 0.0, 0.0, 0.0);
  Index c2 = addAt(m, 6, 1.46, 0.0, 0.0);
  Index c3 = addAt(m, 6, 2.13, -1.16, 0.0);
  bond(m, c0, c1, 2);
  bond(m, c1, c2, 1);
  bond(m, c2, c3, 2);
  bond(m, c0, addAt(m, 1, -0.2, 2.1, 0.0));
  bond(m, c0, addAt(m, 1, -1.75, 1.1, 0.0));
  bond(m, c1, addAt(m, 1, -0.5, -0.95, 0.0));
  Index h2 = addAt(m, 1, 1.96, 0.95, 0.0);
  Index h3a = addAt(m, 1, 1.66, -2.1, 0.0);
  Index h3b = addAt(m, 1, 3.21, -1.1, 0.0);
  bond(m, c2, h2);
  bond(m, c3, h3a);
  bond(m, c3, h3b);
  t.moving = { c3, h2, h3a, h3b };
  t.origin = m.atomPosition3d(c1);
  return t;
}

// CH3-OH, twisting the hydroxyl hydrogen about the C-O bond
Twistable methanol()
{
  Twistable t;
  Molecule& m = t.molecule;
  Index c = addAt(m, 6, 0.0, 0.0, 0.0);
  Index o = addAt(m, 8, 1.43, 0.0, 0.0);
  bond(m, c, o);
  for (const Vector3& v : methylHydrogens())
    bond(m, c, addAt(m, 1, v.x(), v.y(), v.z()));
  Index h = addAt(m, 1, 1.75, 0.9, 0.0);
  bond(m, o, h);
  t.moving = { h };
  return t;
}

// HO-OH, twisting one hydroxyl hydrogen about the O-O bond
Twistable peroxide()
{
  Twistable t;
  Molecule& m = t.molecule;
  Index o0 = addAt(m, 8, 0.0, 0.0, 0.0);
  Index o1 = addAt(m, 8, 1.45, 0.0, 0.0);
  bond(m, o0, o1);
  bond(m, o0, addAt(m, 1, -0.3, 0.9, 0.0));
  Index h = addAt(m, 1, 1.75, 0.9, 0.0);
  bond(m, o1, h);
  t.moving = { h };
  return t;
}

// CH3-CHO, twisting the methyl group about the C-C bond
Twistable acetaldehyde()
{
  Twistable t;
  Molecule& m = t.molecule;
  Index cm = addAt(m, 6, 0.0, 0.0, 0.0);
  Index ca = addAt(m, 6, 1.5, 0.0, 0.0);
  bond(m, cm, ca);
  bond(m, ca, addAt(m, 8, 2.1, 1.05, 0.0), 2);
  bond(m, ca, addAt(m, 1, 2.1, -0.9, 0.0));
  for (const Vector3& v : methylHydrogens()) {
    Index h = addAt(m, 1, v.x(), v.y(), v.z());
    bond(m, cm, h);
    t.moving.push_back(h);
  }
  return t;
}

// H2C=CH-S(=O)-CH3, twisting the sulfoxide group about the (sp2)C-S bond.
// The S atom is sp3 and group 16; S_3+4 keeps it from being typed resonant.
// The oxygen and methyl carbon sit at +-60 degrees from the C=C plane.
Twistable vinylSulfoxide()
{
  Twistable t;
  Molecule& m = t.molecule;
  Index c2 = addAt(m, 6, 0.0, 0.0, 0.0);
  Index c1 = addAt(m, 6, -0.67, 1.16, 0.0);
  Index s = addAt(m, 16, 1.77, 0.0, 0.0);
  bond(m, c1, c2, 2);
  bond(m, c2, s);
  bond(m, c1, addAt(m, 1, -0.2, 2.1, 0.0));
  bond(m, c1, addAt(m, 1, -1.75, 1.1, 0.0));
  bond(m, c2, addAt(m, 1, -0.55, -0.93, 0.0));
  const double c = std::cos(1.0471975511966), sn = std::sin(1.0471975511966);
  Index o = addAt(m, 8, 2.1, 1.4 * c, 1.4 * sn);
  Index cm = addAt(m, 6, 2.4, 1.8 * c, -1.8 * sn);
  bond(m, s, o, 2);
  bond(m, s, cm);
  t.moving = { s, o, cm };
  // the methyl hydrogens move with the carbon
  for (const Vector3& v : { Vector3(3.4, 1.8 * c, -1.8 * sn + 0.9),
                            Vector3(3.0, 1.8 * c + 0.9, -1.8 * sn - 0.4),
                            Vector3(3.0, 1.8 * c - 0.9, -1.8 * sn - 0.4) }) {
    Index h = addAt(m, 1, v.x(), v.y(), v.z());
    bond(m, cm, h);
    t.moving.push_back(h);
  }
  return t;
}

// H2C=CH-BF2, twisting the BF2 group about the C-B bond. B_2 is not a
// resonant type, so this bond is C_R-B_2 and uses its own bond order.
Twistable vinylBorane()
{
  Twistable t;
  Molecule& m = t.molecule;
  Index c2 = addAt(m, 6, 0.0, 0.0, 0.0);
  Index c1 = addAt(m, 6, -0.67, 1.16, 0.0);
  Index b = addAt(m, 5, 1.55, 0.0, 0.0);
  bond(m, c1, c2, 2);
  bond(m, c2, b);
  bond(m, c1, addAt(m, 1, -0.2, 2.1, 0.0));
  bond(m, c1, addAt(m, 1, -1.75, 1.1, 0.0));
  bond(m, c2, addAt(m, 1, -0.55, -0.93, 0.0));
  Index f1 = addAt(m, 9, 2.2, 1.15, 0.0);
  Index f2 = addAt(m, 9, 2.2, -1.15, 0.0);
  bond(m, b, f1);
  bond(m, b, f2);
  t.moving = { b, f1, f2 };
  return t;
}

// H2N-CH=O, twisting the NH2 group about the amide C-N bond
Twistable formamide()
{
  Twistable t;
  Molecule& m = t.molecule;
  Index c = addAt(m, 6, 0.0, 0.0, 0.0);
  Index n = addAt(m, 7, 1.35, 0.0, 0.0);
  bond(m, c, n);
  bond(m, c, addAt(m, 8, -0.6, 1.05, 0.0), 2);
  bond(m, c, addAt(m, 1, -0.6, -0.9, 0.0));
  Index h1 = addAt(m, 1, 1.9, 0.85, 0.0);
  Index h2 = addAt(m, 1, 1.9, -0.85, 0.0);
  bond(m, n, h1);
  bond(m, n, h2);
  t.moving = { n, h1, h2 };
  return t;
}
} // namespace

// Rotation about a C=C bond. The typer makes both carbons C_R (each has an
// sp2 neighbor), so the sp2-sp2 term uses BO = 1.5: n = 2, phi0 = 180 and
// V = 5 sqrt(Uj Uk) (1 + 4.18 ln 1.5). The four H-C=C-H torsions cost 4 V at
// 90 degrees. Before this was fixed double bonds had no torsion at all.
TEST(UffTorsionTest, EtheneBarrier)
{
  Twistable t = ethene();
  EXPECT_EQ(uffTypes(t.molecule)[0], "C_R");
  const double v = 5.0 * paramU("C_R") * (1.0 + 4.18 * std::log(1.5));
  EXPECT_NEAR(t.energy(0.0), 0.0, 1.0e-9);
  EXPECT_NEAR(t.energy(90.0), 4.0 * v, 1.0e-6);
  EXPECT_NEAR(t.energy(45.0), 2.0 * v, 1.0e-6);
  // cis and trans (twist by 180 degrees) are the same by symmetry
  EXPECT_NEAR(t.energy(180.0), t.energy(0.0), 1.0e-9);
  EXPECT_NEAR(t.energy(37.0), t.energy(217.0), 1.0e-9);
}

// The single bond of s-trans butadiene joins two sp2 carbons. Both are C_R
// here, so BO = 1.5 as for any resonant pair.
TEST(UffTorsionTest, ButadieneCentralBond)
{
  Twistable t = butadiene();
  const auto types = uffTypes(t.molecule);
  EXPECT_EQ(types[1], "C_R");
  EXPECT_EQ(types[2], "C_R");
  const double v = 5.0 * paramU("C_R") * (1.0 + 4.18 * std::log(1.5));
  EXPECT_NEAR(t.energy(0.0), 0.0, 1.0e-9); // s-trans
  EXPECT_NEAR(t.energy(90.0), 4.0 * v, 1.0e-6);
  EXPECT_NEAR(t.energy(180.0), 0.0, 1.0e-9); // s-cis
}

// A resonant atom bonded to a non-resonant sp2 atom uses the bond's own
// order: BO = 1 gives V = 5 sqrt(Uj Uk).
TEST(UffTorsionTest, ResonantToPlainSp2UsesBondOrder)
{
  Twistable t = vinylBorane();
  const auto types = uffTypes(t.molecule);
  EXPECT_EQ(types[0], "C_R");
  EXPECT_EQ(types[2], "B_2");
  const double v = 5.0 * std::sqrt(paramU("C_R") * paramU("B_2"));
  EXPECT_GT(v, 0.0);
  EXPECT_NEAR(t.energy(0.0), 0.0, 1.0e-9);
  EXPECT_NEAR(t.energy(90.0), 4.0 * v, 1.0e-6);
}

// The amide C-N bond uses BO = 1.41
TEST(UffTorsionTest, AmideBondOrder)
{
  Twistable t = formamide();
  const auto types = uffTypes(t.molecule);
  EXPECT_EQ(types[0], "C_R");
  EXPECT_EQ(types[1], "N_R");
  const double v = 5.0 * std::sqrt(paramU("C_R") * paramU("N_R")) *
                   (1.0 + 4.18 * std::log(1.41));
  EXPECT_NEAR(t.energy(90.0), 4.0 * v, 1.0e-6);
}

// H-C-O-H is sp3-sp3 with only one group 16 atom: 3-fold, phi0 = 60. Only a
// pair of group 16 atoms (H-O-O-H) is 2-fold with phi0 = 90.
TEST(UffTorsionTest, MethanolIsThreefold)
{
  Twistable t = methanol();
  const auto types = uffTypes(t.molecule);
  EXPECT_EQ(types[0], "C_3");
  EXPECT_EQ(types[1], "O_3");
  const double v = std::sqrt(uffparams[rowForLabel("C_3")].Vi *
                             uffparams[rowForLabel("O_3")].Vi);
  EXPECT_GT(v, 0.0);
  for (double deg : { 0.0, 17.0, 50.0, 111.0 })
    EXPECT_NEAR(t.energy(deg), t.energy(deg + 120.0), 1.0e-9);
  // eclipsed (0) is the maximum, 3 torsions of V
  EXPECT_NEAR(t.energy(0.0), 3.0 * v, 1.0e-6);
  EXPECT_NEAR(t.energy(60.0), 0.0, 1.0e-9);
}

TEST(UffTorsionTest, HydrogenPeroxideKeepsTwofoldTerm)
{
  Twistable t = peroxide();
  EXPECT_EQ(uffTypes(t.molecule)[0], "O_3");
  double bestAngle = 0.0;
  double best = 1.0e9;
  for (double deg = 0.0; deg <= 180.0; deg += 1.0) {
    const double e = t.energy(deg);
    if (e < best) {
      best = e;
      bestAngle = deg;
    }
  }
  EXPECT_NEAR(bestAngle, 90.0, 1.0);
  EXPECT_NEAR(best, 0.0, 1.0e-9);
  EXPECT_NEAR(t.energy(0.0), 2.0, 1.0e-6); // V = sqrt(2 * 2)
  EXPECT_NEAR(t.energy(0.0), t.energy(180.0), 1.0e-9);
}

// sp2-sp3 (methyl on a carbonyl): n = 6, phi0 = 0, V = 1 kcal/mol, six
// torsions across the bond.
TEST(UffTorsionTest, AcetaldehydeMethylIsSixfold)
{
  Twistable t = acetaldehyde();
  const auto types = uffTypes(t.molecule);
  EXPECT_EQ(types[0], "C_3");
  EXPECT_EQ(types[1], "C_R");
  EXPECT_NEAR(t.energy(0.0), 0.0, 1.0e-9);
  EXPECT_NEAR(t.energy(30.0), 6.0, 1.0e-6);
  for (double deg : { 5.0, 23.0, 41.0 })
    EXPECT_NEAR(t.energy(deg), t.energy(deg + 60.0), 1.0e-9);
}

// sp2-sp3 with a group 16 sp3 atom (vinyl sulfoxide): n = 2, phi0 = 90, so
// E = V/2 (1 + cos 2 phi) per torsion, minimum perpendicular to the C=C plane.
// (Vinyl ethers don't reach this: the typer calls that oxygen O_R.)
TEST(UffTorsionTest, Sp2Sp3GroupSixteenIsTwofold)
{
  Twistable t = vinylSulfoxide();
  const auto types = uffTypes(t.molecule);
  EXPECT_EQ(types[0], "C_R");
  EXPECT_EQ(types[2], "S_3+4");
  // dihedrals of C1/H against O/CH3 at zero twist: +-60 and 180 -/+ 60
  // (the S-CH3 torsions add a constant that doesn't depend on the twist)
  const double phi[4] = { 60.0, -60.0, 120.0, -120.0 };
  auto twofold = [&phi](double deg) {
    double sum = 0.0;
    for (double p : phi)
      sum += 0.5 * (1.0 + std::cos(2.0 * (p + deg) * DEG_TO_RAD_D));
    return sum;
  };
  const double constant = t.energy(0.0) - twofold(0.0);
  for (double deg : { 0.0, 20.0, 45.0, 90.0, 133.0 }) {
    EXPECT_NEAR(t.energy(deg), twofold(deg) + constant, 1.0e-6);
    EXPECT_NEAR(t.energy(deg + 180.0), t.energy(deg), 1.0e-9);
  }
  // not the 6-fold form
  EXPECT_GT(std::fabs(t.energy(0.0) - t.energy(60.0)), 0.1);
}

TEST(UffTorsionTest, GradientsMatchEnergies)
{
  for (double deg : { 13.0, 37.0, 122.0 }) {
    Twistable cases[] = { ethene(),      butadiene(),    methanol(),
                          peroxide(),    acetaldehyde(), vinylSulfoxide(),
                          vinylBorane(), formamide() };
    for (Twistable& t : cases)
      EXPECT_LT(t.gradientError(deg), 1.0e-4);
  }
}

// ---- Torsions near linear bond angles --------------------------------------

namespace {
// A four carbon chain A-B-C-D with bond angles theta1 (A-B-C) and theta2
// (B-C-D), both given in degrees, and dihedral phi (degrees)
Molecule fourChain(double theta1, double theta2, double phi)
{
  const double r = DEG_TO_RAD_D;
  Molecule m;
  addAt(m, 6, 1.5 * std::cos(theta1 * r),
        1.5 * std::sin(theta1 * r) * std::cos(phi * r),
        1.5 * std::sin(theta1 * r) * std::sin(phi * r));
  addAt(m, 6, 0.0, 0.0, 0.0);
  addAt(m, 6, 1.5, 0.0, 0.0);
  addAt(m, 6, 1.5 - 1.5 * std::cos(theta2 * r), 1.5 * std::sin(theta2 * r),
        0.0);
  bond(m, 0, 1);
  bond(m, 1, 2);
  bond(m, 2, 3);
  return m;
}

// sp3-sp3 torsion energy of the chain before any switching: n = 3, phi0 = 60
double bareTorsion(double phi)
{
  const double v = uffparams[rowForLabel("C_3")].Vi;
  return 0.5 * v * (1.0 + std::cos(3.0 * phi * DEG_TO_RAD_D));
}

// the C2 smoothstep in cos(theta), from 170 to 180 degrees
double switchValue(double theta)
{
  const double onset = 1.0 + std::cos(170.0 * DEG_TO_RAD_D);
  double u = (std::cos(theta * DEG_TO_RAD_D) + 1.0) / onset;
  u = std::min(1.0, std::max(0.0, u));
  return u * u * u * (10.0 - 15.0 * u + 6.0 * u * u);
}

double chainEnergy(double theta1, double theta2, double phi)
{
  Molecule m = fourChain(theta1, theta2, phi);
  UFF uff;
  uff.setMolecule(&m);
  return uff.torsionEnergy(positionsOf(m));
}
} // namespace

TEST(UffTorsionSwitchTest, EnergyFollowsTheSwitch)
{
  const double phi = 20.0;
  for (double theta : { 100.0, 150.0, 165.0, 170.0 })
    EXPECT_DOUBLE_EQ(chainEnergy(theta, 110.0, phi), bareTorsion(phi));
  for (double theta : { 171.0, 175.0, 178.0, 179.9, 179.9999 }) {
    EXPECT_NEAR(chainEnergy(theta, 110.0, phi),
                switchValue(theta) * bareTorsion(phi), 1.0e-9);
    // the same when the other angle is the near-linear one
    EXPECT_NEAR(chainEnergy(110.0, theta, phi),
                switchValue(theta) * bareTorsion(phi), 1.0e-9);
  }
  EXPECT_NEAR(chainEnergy(180.0, 110.0, phi), 0.0, 1.0e-12);
  EXPECT_NEAR(chainEnergy(110.0, 180.0, phi), 0.0, 1.0e-12);
  // both angles switched
  EXPECT_NEAR(chainEnergy(175.0, 176.0, phi),
              switchValue(175.0) * switchValue(176.0) * bareTorsion(phi),
              1.0e-9);
}

// C1: no kink at the onset or at 180 degrees
TEST(UffTorsionSwitchTest, EnergyIsSmoothThroughTheScan)
{
  const double phi = 20.0;
  const double h = 1.0e-3;
  for (double theta : { 170.0, 179.998 }) {
    const double slope = (chainEnergy(theta + h, 110.0, phi) -
                          chainEnergy(theta - h, 110.0, phi)) /
                         (2.0 * h);
    EXPECT_LT(std::fabs(slope), 1.0e-3);
  }
  double previous = chainEnergy(165.0, 110.0, phi);
  for (double theta = 165.0; theta <= 180.0; theta += 0.05) {
    const double e = chainEnergy(theta, 110.0, phi);
    EXPECT_LE(e, previous + 1.0e-12);
    EXPECT_LT(previous - e, 0.05); // no jump
    previous = e;
  }
}

TEST(UffTorsionSwitchTest, GradientMatchesEnergyNearLinear)
{
  for (double phi : { 20.0, 75.0 }) {
    for (double theta :
         { 165.0, 170.5, 172.0, 176.0, 179.0, 179.9999, 180.0 }) {
      for (int which = 0; which < 2; ++which) {
        Molecule m = which == 0 ? fourChain(theta, 110.0, phi)
                                : fourChain(110.0, theta, phi);
        UFF uff;
        uff.setMolecule(&m);
        const Eigen::VectorXd x = positionsOf(m);
        Eigen::VectorXd analytic = Eigen::VectorXd::Zero(x.size());
        uff.torsionGradient(x, analytic);
        ASSERT_TRUE(analytic.allFinite());
        const double h = 1.0e-7;
        for (Eigen::Index c = 0; c < x.size(); ++c) {
          Eigen::VectorXd xp = x;
          Eigen::VectorXd xm = x;
          xp[c] += h;
          xm[c] -= h;
          const double fd =
            (uff.torsionEnergy(xp) - uff.torsionEnergy(xm)) / (2.0 * h);
          EXPECT_NEAR(fd, analytic[c], 1.0e-4 + 1.0e-4 * std::fabs(fd))
            << "theta " << theta << " phi " << phi << " component " << c;
        }
      }
    }
  }
}

// ---- Bonded terms across periodic boundaries ------------------------------

namespace {
using Avogadro::Core::UnitCell;

// n-butane (the heavy-atom backbone is gauche so no angle is 180 degrees)
Molecule butane()
{
  Molecule m;
  Index c0 = addAt(m, 6, 0.0, 0.0, 0.0);
  Index c1 = addAt(m, 6, 1.53, 0.1, 0.0);
  Index c2 = addAt(m, 6, 2.1, 1.5, 0.1);
  Index c3 = addAt(m, 6, 3.6, 1.6, 0.9);
  bond(m, c0, c1);
  bond(m, c1, c2);
  bond(m, c2, c3);
  // hydrogen offsets from each carbon (3 on the ends, 2 inside)
  const std::vector<std::vector<Vector3>> offsets = {
    { Vector3(-0.4, 0.9, 0.3), Vector3(-0.4, -0.6, 0.8),
      Vector3(-0.5, -0.4, -0.9) },
    { Vector3(0.0, -0.7, 0.8), Vector3(0.1, -0.6, -0.9) },
    { Vector3(0.2, 0.7, -0.9), Vector3(-0.8, 1.2, 0.5) },
    { Vector3(0.5, 0.8, -0.5), Vector3(0.7, -0.1, -0.2),
      Vector3(0.9, 1.0, 0.8) }
  };
  const Index carbons[4] = { c0, c1, c2, c3 };
  for (int c = 0; c < 4; ++c) {
    const Vector3 p = m.atomPosition3d(carbons[c]);
    for (const Vector3& o : offsets[c])
      bond(m, carbons[c],
           addAt(m, 1, p.x() + o.x(), p.y() + o.y(), p.z() + o.z()));
  }
  return m;
}

// A pyramidalized acetaldehyde, so the inversion term is not zero
Molecule pyramidalAcetaldehyde()
{
  Molecule m;
  Index cm = addAt(m, 6, 0.0, 0.0, 0.0);
  Index ca = addAt(m, 6, 1.5, 0.1, 0.0);
  bond(m, cm, ca);
  bond(m, ca, addAt(m, 8, 2.1, 1.1, 0.2), 2);
  bond(m, ca, addAt(m, 1, 2.0, -0.9, -0.3));
  bond(m, cm, addAt(m, 1, -0.4, 1.0, 0.1));
  bond(m, cm, addAt(m, 1, -0.4, -0.5, 0.9));
  bond(m, cm, addAt(m, 1, -0.4, -0.5, -0.9));
  return m;
}

// A copy of the molecule in a cell with every atom wrapped back into it,
// after moving the molecule by `shift`, so it straddles the cell boundary.
Molecule wrappedInCell(const Molecule& cluster, const UnitCell& cell,
                       const Vector3& shift)
{
  Molecule m(cluster);
  m.setUnitCell(new UnitCell(cell));
  Vector3 center = Vector3::Zero();
  for (Index i = 0; i < m.atomCount(); ++i)
    center += m.atomPosition3d(i);
  center /= static_cast<double>(m.atomCount());
  for (Index i = 0; i < m.atomCount(); ++i)
    m.setAtomPosition3d(
      i, cell.wrapCartesian(m.atomPosition3d(i) - center + shift));
  return m;
}

const double halfPi = 0.5 * PI_D;
// cubic and triclinic
const UnitCell cubicCell(12.0, 12.0, 12.0, halfPi, halfPi, halfPi);
const UnitCell triclinicCell(12.0, 13.0, 14.0, 1.40, 1.65, 1.75);

struct BondedEnergies
{
  double bond, angle, oop, torsion;
};

void expectBondedNear(const BondedEnergies& actual,
                      const BondedEnergies& expected, double tolerance = 1.0e-8)
{
  EXPECT_NEAR(actual.bond, expected.bond, tolerance);
  EXPECT_NEAR(actual.angle, expected.angle, tolerance);
  EXPECT_NEAR(actual.oop, expected.oop, tolerance);
  EXPECT_NEAR(actual.torsion, expected.torsion, tolerance);
}

// the gradient error of each bonded term (see maxTermGradientError)
BondedEnergies bondedGradientErrors(Molecule& molecule)
{
  return {
    maxTermGradientError(molecule, &UFF::bondEnergy, &UFF::bondGradient),
    maxTermGradientError(molecule, &UFF::angleEnergy, &UFF::angleGradient),
    maxTermGradientError(molecule, &UFF::oopEnergy, &UFF::oopGradient),
    maxTermGradientError(molecule, &UFF::torsionEnergy, &UFF::torsionGradient)
  };
}

BondedEnergies bondedEnergies(Molecule& molecule, const Eigen::VectorXd& x)
{
  UFF uff;
  uff.setMolecule(&molecule);
  return { uff.bondEnergy(x), uff.angleEnergy(x), uff.oopEnergy(x),
           uff.torsionEnergy(x) };
}

// the largest bond length between atoms in the raw coordinates
double longestRawBond(const Molecule& molecule)
{
  double longest = 0.0;
  for (Index b = 0; b < molecule.bondCount(); ++b) {
    const auto bnd = molecule.bond(b);
    longest = std::max(longest, (molecule.atomPosition3d(bnd.atom1().index()) -
                                 molecule.atomPosition3d(bnd.atom2().index()))
                                  .norm());
  }
  return longest;
}

// Test molecules with a wrapped copy in each cell
struct PeriodicCase
{
  Molecule cluster;
  Molecule periodic;
};

std::vector<PeriodicCase> periodicCases()
{
  std::vector<PeriodicCase> cases;
  for (const Molecule& cluster : { butane(), pyramidalAcetaldehyde() }) {
    for (const UnitCell* cell : { &cubicCell, &triclinicCell }) {
      for (const Vector3& shift :
           { Vector3(0.0, 0.0, 0.0), Vector3(0.3, -0.7, 0.45) }) {
        cases.push_back({ cluster, wrappedInCell(cluster, *cell, shift) });
      }
    }
  }
  return cases;
}
} // namespace

// Wrap a molecule into the cell and every bonded term is the same as for
// the contiguous cluster without a cell.
TEST(UffPeriodicTest, BondedTermsMatchTheUnwrappedCluster)
{
  int straddling = 0;
  for (PeriodicCase& c : periodicCases()) {
    // a long raw bond means the molecule crosses the cell boundary
    if (longestRawBond(c.periodic) > 4.0)
      ++straddling;
    const BondedEnergies expected =
      bondedEnergies(c.cluster, positionsOf(c.cluster));
    const BondedEnergies actual =
      bondedEnergies(c.periodic, positionsOf(c.periodic));
    expectBondedNear(actual, expected);
  }
  // make sure the test really has bonds across the boundary
  EXPECT_GE(straddling, 4);
}

// Analytic gradients are the derivatives of the minimum image energies.
TEST(UffPeriodicTest, GradientsMatchEnergiesAcrossTheBoundary)
{
  for (PeriodicCase& c : periodicCases()) {
    const BondedEnergies error = bondedGradientErrors(c.periodic);
    EXPECT_LT(error.bond, 1.0e-4);
    EXPECT_LT(error.angle, 1.0e-4);
    EXPECT_LT(error.oop, 1.0e-4);
    EXPECT_LT(error.torsion, 1.0e-4);
  }
}

// Moving the whole molecule and wrapping it back into the cell changes the
// raw coordinates, not the energy.
TEST(UffPeriodicTest, TranslatingAndWrappingKeepsTheEnergy)
{
  const Vector3 shifts[] = { Vector3(1.9, 0.7, -0.3), Vector3(-5.5, 3.2, 8.8),
                             Vector3(12.0, -13.0, 29.0) };
  for (PeriodicCase& c : periodicCases()) {
    const BondedEnergies reference =
      bondedEnergies(c.periodic, positionsOf(c.periodic));
    const UnitCell cell = *c.periodic.unitCell();
    for (const Vector3& shift : shifts) {
      Molecule moved(c.periodic);
      moved.setUnitCell(new UnitCell(cell));
      for (Index i = 0; i < moved.atomCount(); ++i)
        moved.setAtomPosition3d(
          i, cell.wrapCartesian(moved.atomPosition3d(i) + shift));
      const BondedEnergies after = bondedEnergies(moved, positionsOf(moved));
      expectBondedNear(after, reference);
    }
  }
}

// A chain that is bonded across the cell boundary on its own, with no end:
// four CH2 groups of zigzag polyethylene (a ring in the bond graph) along a.
// The total bonded energy must not depend on where the cell boundary falls.
TEST(UffPeriodicTest, InfiniteChainDoesNotDependOnTheBoundary)
{
  auto chain = [](double offset) {
    Molecule m;
    m.setUnitCell(new UnitCell(5.12, 14.0, 14.0, halfPi, halfPi, halfPi));
    const UnitCell& cell = *m.unitCell();
    Index carbons[4];
    for (int c = 0; c < 4; ++c) {
      const double y = (c % 2 == 0) ? 0.43 : -0.43;
      carbons[c] = addAt(m, 6, 1.28 * c + offset, y, 0.0);
    }
    for (int c = 0; c < 4; ++c) {
      bond(m, carbons[c], carbons[(c + 1) % 4]);
      const double s = (c % 2 == 0) ? 1.0 : -1.0;
      for (double z : { 0.89, -0.89 }) {
        Vector3 p = m.atomPosition3d(carbons[c]) + Vector3(0.0, s * 0.63, z);
        bond(m, carbons[c], addAt(m, 1, p.x(), p.y(), p.z()));
      }
    }
    for (Index i = 0; i < m.atomCount(); ++i)
      m.setAtomPosition3d(i, cell.wrapCartesian(m.atomPosition3d(i)));
    return m;
  };
  Molecule reference = chain(0.0);
  const BondedEnergies expected =
    bondedEnergies(reference, positionsOf(reference));
  // the periodic bond is about 1.5 A, not a cell length: finite and small
  EXPECT_LT(expected.bond, 5.0);
  EXPECT_LT(expected.angle, 30.0);
  for (double offset : { 0.4, 1.0, 2.7, 4.9 }) {
    Molecule m = chain(offset);
    const BondedEnergies actual = bondedEnergies(m, positionsOf(m));
    expectBondedNear(actual, expected);
  }
}

// ---- Van der Waals switching, pair list and soft core ---------------------

namespace {
// Two unbonded argon atoms, `r` apart along x. Argon has no bonded terms, so
// UFF::value() is the van der Waals energy alone (kJ/mol).
struct ArgonPair
{
  Molecule molecule;
  UFF uff;
  ArgonPair(double r = 5.0)
  {
    addAt(molecule, 18, 0.0, 0.0, 0.0);
    addAt(molecule, 18, r, 0.0, 0.0);
    uff.setMolecule(&molecule);
  }
  static Eigen::VectorXd positions(double r)
  {
    Eigen::VectorXd x = Eigen::VectorXd::Zero(6);
    x[3] = r;
    return x;
  }
  double energy(double r) { return uff.value(positions(r)); }
  // dE/dr, the force on the second atom along x
  double slope(double r)
  {
    Eigen::VectorXd g = Eigen::VectorXd::Zero(6);
    uff.gradient(positions(r), g);
    return g[3];
  }
  double finiteSlope(double r, double h)
  {
    return (energy(r + h) - energy(r - h)) / (2.0 * h);
  }
};

// Argon-argon UFF parameters, in kcal/mol and Angstrom
double argonX()
{
  return uffparams[rowForLabel("Ar4+4")].x1;
}

double argonDepth()
{
  return uffparams[rowForLabel("Ar4+4")].D1;
}

// Deterministic scatter of argon atoms in a box (a simple LCG)
Molecule argonCluster(int count, double box)
{
  Molecule molecule;
  unsigned int state = 12345u;
  auto next = [&state]() {
    state = state * 1664525u + 1013904223u;
    return static_cast<double>(state >> 8) / static_cast<double>(1u << 24);
  };
  for (int i = 0; i < count; ++i)
    addAt(molecule, 18, box * next(), box * next(), box * next());
  return molecule;
}
} // namespace

// The energy used to jump at the 10 A cutoff. It must now be continuous
// across the whole switching region (8-10 A) and vanish beyond it, and the
// analytic gradient must be the derivative of the switched energy.
TEST(UffVdwSwitchTest, EnergyIsContinuousAcrossSwitchRegion)
{
  ArgonPair pair;
  const double step = 1.0e-4;
  const double regions[2][2] = { { 7.9, 8.1 }, { 9.9, 10.1 } };
  for (const auto& region : regions) {
    double previous = pair.energy(region[0]);
    for (double r = region[0] + step; r <= region[1]; r += step) {
      const double current = pair.energy(r);
      // the slope is at most ~0.02 kJ/mol/A here, so a step changes the
      // energy by ~2e-6; the old jump at 10 A was 2.6e-3
      EXPECT_LT(std::fabs(current - previous), 1.0e-5) << "r = " << r;
      previous = current;
    }
  }
  EXPECT_EQ(pair.energy(10.0), 0.0);
  EXPECT_EQ(pair.energy(10.5), 0.0);
  EXPECT_EQ(pair.energy(13.0), 0.0);
  EXPECT_NE(pair.energy(9.9), 0.0);
}

TEST(UffVdwSwitchTest, GradientMatchesFiniteDifferencesAcrossSwitchRegion)
{
  ArgonPair pair;
  // includes both ends of the switch exactly
  const double radii[] = { 3.0, 4.5,  7.0,  7.99, 8.0,  8.01, 8.5,
                           9.0, 9.25, 9.75, 9.99, 10.0, 10.01 };
  for (double r : radii) {
    const double analytic = pair.slope(r);
    // the second derivative of the switch jumps at its ends, so use a short
    // step there
    const double numeric = pair.finiteSlope(r, 1.0e-7);
    EXPECT_NEAR(analytic, numeric, 1.0e-8 + 1.0e-6 * std::fabs(analytic))
      << "r = " << r;
  }
}

// With a switch that reaches zero at the cutoff and a pair list that holds
// every pair inside it, the energy cannot depend on earlier evaluations.
TEST(UffVdwSwitchTest, EnergyAndGradientDoNotDependOnPairListHistory)
{
  Molecule molecule = argonCluster(40, 22.0);
  const Eigen::VectorXd x = positionsOf(molecule);

  UFF uff;
  uff.setMolecule(&molecule);

  Eigen::VectorXd g0;
  const double e0 = uff.evaluate(x, &g0);

  // trial points: a small step, a far one (every atom moves well past the
  // rebuild threshold), and a long run of evaluations in between
  Eigen::VectorXd far = x;
  for (Eigen::Index i = 0; i < far.size(); ++i)
    far[i] += 3.0 * std::sin(1.7 * static_cast<double>(i) + 0.3);
  for (int pass = 0; pass < 25; ++pass) {
    Eigen::VectorXd trial = (pass % 3 == 0) ? far : x;
    if (pass % 3 == 1)
      trial[0] += 0.01 * pass;
    Eigen::VectorXd g;
    const double e = uff.evaluate(trial, &g);

    // a UFF built at exactly these coordinates is the reference
    Molecule fresh = molecule;
    for (Index i = 0; i < fresh.atomCount(); ++i)
      fresh.setAtomPosition3d(i, trial.segment<3>(3 * i));
    UFF reference;
    reference.setMolecule(&fresh);
    Eigen::VectorXd gr;
    const double er = reference.evaluate(trial, &gr);
    EXPECT_EQ(e, er) << "pass " << pass;
    EXPECT_EQ((g - gr).cwiseAbs().maxCoeff(), 0.0) << "pass " << pass;
  }

  Eigen::VectorXd g1;
  const double e1 = uff.evaluate(x, &g1);
  EXPECT_EQ(e1, e0);
  EXPECT_EQ((g1 - g0).cwiseAbs().maxCoeff(), 0.0);
  EXPECT_NE(e0, 0.0);
}

// A pair that drifts into range must be seen right away: the list reaches
// beyond the switching distance and is rebuilt before any atom has moved far
// enough to matter.
TEST(UffVdwPairListTest, DriftingPairIsNotMissed)
{
  const double starts[2][2] = { { 10.5, 9.5 }, { 13.0, 9.0 } };
  for (const auto& drift : starts) {
    ArgonPair pair(drift[0]);
    const double step =
      0.01 * (drift[1] - drift[0]) / std::fabs(drift[1] - drift[0]);
    for (double r = drift[0]; (r - drift[1]) * step <= 0.0; r += step) {
      ArgonPair fresh(r);
      EXPECT_EQ(pair.energy(r), fresh.energy(r)) << "r = " << r;
      EXPECT_EQ(pair.slope(r), fresh.slope(r)) << "r = " << r;
    }
  }
}

// Below r_c = x / 2 the energy continues linearly with the slope it has at
// r_c, so the energy and the gradient describe the same function there.
TEST(UffVdwSoftCoreTest, EnergyAndGradientAgreeInsideTheCore)
{
  ArgonPair pair;
  const double rc = 0.5 * argonX();
  const double radii[] = { 0.002,     0.02,     0.05,          0.09,
                           0.3,       0.8,      1.5,           rc - 0.01,
                           rc + 0.01, rc + 0.1, 0.8 * argonX() };
  for (double r : radii) {
    const double analytic = pair.slope(r);
    const double numeric = pair.finiteSlope(r, 1.0e-6);
    EXPECT_NEAR(analytic, numeric, 1.0e-8 + 1.0e-6 * std::fabs(analytic))
      << "r = " << r;
    EXPECT_LT(analytic, 0.0) << "r = " << r; // always repulsive
  }
}

TEST(UffVdwSoftCoreTest, EnergyIsContinuousAndSmoothAtCoreRadius)
{
  ArgonPair pair;
  const double rc = 0.5 * argonX();
  const double eps = 1.0e-9;
  const double below = pair.energy(rc - eps);
  const double above = pair.energy(rc + eps);
  EXPECT_NEAR(below, above, 1.0e-5 * std::fabs(above));
  const double slopeBelow = pair.slope(rc - eps);
  const double slopeAbove = pair.slope(rc + eps);
  EXPECT_NEAR(slopeBelow, slopeAbove, 1.0e-6 * std::fabs(slopeAbove));

  // E(r_c) is the 12-6 energy there; kcal/mol -> kJ/mol
  const double x6 = std::pow(argonX(), 6);
  const double r6 = std::pow(rc, 6);
  const double expected =
    argonDepth() * (x6 * x6 / (r6 * r6) - 2.0 * x6 / r6) * 4.184;
  EXPECT_NEAR(pair.energy(rc), expected, 1.0e-3 * expected);
}

TEST(UffVdwSoftCoreTest, CoincidentAtomsGiveFiniteEnergyAndGradient)
{
  ArgonPair pair;
  const Eigen::VectorXd x = Eigen::VectorXd::Zero(6);
  Eigen::VectorXd g;
  const double e = pair.uff.evaluate(x, &g);
  EXPECT_TRUE(std::isfinite(e));
  EXPECT_TRUE(g.allFinite());
  // finite and larger than anywhere outside the core
  EXPECT_GT(e, pair.energy(0.5 * argonX()));
  // the force still pushes the atoms apart rather than vanishing
  EXPECT_GT(g.cwiseAbs().maxCoeff(), 0.0);
  EXPECT_NEAR((g.segment<3>(0) + g.segment<3>(3)).norm(), 0.0, 1.0e-9);
}

// A pair is seen through its nearest periodic image, and the switch, the soft
// core and the list behave as they do without a cell. (Only the nearest image
// is used, so a cell narrower than 2 * 10 A leaves out the farther ones; see
// the note in uff.cpp.)
TEST(UffVdwPeriodicTest, NearestImageDriftMatchesFreshEvaluation)
{
  Molecule molecule;
  addAt(molecule, 18, 0.0, 0.0, 0.0);
  addAt(molecule, 18, 3.0, 0.0, 0.0);
  molecule.setUnitCell(new UnitCell(30.0, 30.0, 30.0, halfPi, halfPi, halfPi));
  UFF uff;
  uff.setMolecule(&molecule);

  ArgonPair open;
  // the second atom starts 27 A away along -x through the boundary and drifts
  // from an image 13 A away to one 9 A away
  for (double r = 13.0; r >= 9.0; r -= 0.05) {
    Eigen::VectorXd x = Eigen::VectorXd::Zero(6);
    x[3] = 30.0 - r;
    Eigen::VectorXd g;
    const double e = uff.evaluate(x, &g);
    EXPECT_NEAR(e, open.energy(r), 1.0e-12) << "r = " << r;
    EXPECT_NEAR(g[3], -open.slope(r), 1.0e-12) << "r = " << r;
  }
}
