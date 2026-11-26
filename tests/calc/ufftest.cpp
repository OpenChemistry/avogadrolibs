/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/uff.h>
#include <avogadro/calc/uffdata.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
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
                    "hooh.xyz", "PF5.xyz", "SF4.xyz", "SF6.xyz"
                    // Add more molecule files here as needed
                    ));

// XeF4 is exactly square planar (Xe4+4), so its F-Xe-F angles are 180 degrees
// and the analytical angle gradient is dropped for such degenerate (collinear)
// angles. Check the gradient on a distorted copy instead.
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

  // the same molecule with only single bonds (e.g., perceived from XYZ)
  // or sulfate with charge-separated S+ / O- bonds is still four-coordinate
  Molecule single;
  Index s2 = addAt(single, 16, 0.0, 0.0, 0.0);
  for (int k = 0; k < 4; ++k) {
    Index o = addAt(single, 8, k < 2 ? (k ? 1.5 : -1.5) : 0.0,
                    k >= 2 ? (k == 2 ? 1.5 : -1.5) : 0.0, 0.0);
    bond(single, s2, o);
  }
  EXPECT_EQ(uffTypes(single)[0], "S_3+6");
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
    double angle = 2.0 * 3.14159265358979 * k / 3.0;
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
    double angle = 2.0 * 3.14159265358979 * k / 3.0;
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
    double angle = 2.0 * 3.14159265358979 * k / 6.0;
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
