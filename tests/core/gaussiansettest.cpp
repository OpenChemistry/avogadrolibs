/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <cmath>
#include <vector>

using Avogadro::Vector3;
using Avogadro::Core::BasisSet;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::GaussianSetTools;
using Avogadro::Core::Molecule;
using Avogadro::Core::Rhf;
using Avogadro::Core::Rohf;
using Avogadro::Core::Uhf;
using Avogadro::Core::Unknown;

TEST(GaussianSetTest, defaultConstruction)
{
  GaussianSet gs;
  EXPECT_EQ(gs.molecularOrbitalCount(), static_cast<unsigned int>(0));
  EXPECT_EQ(gs.scfType(), Rhf);
}

TEST(GaussianSetTest, addSBasis)
{
  GaussianSet gs;
  unsigned int idx = gs.addBasis(0, GaussianSet::S);
  EXPECT_EQ(idx, static_cast<unsigned int>(0));
  // addBasis returns the shell index; add a second shell to verify
  unsigned int idx2 = gs.addBasis(0, GaussianSet::S);
  EXPECT_EQ(idx2, static_cast<unsigned int>(1));
}

TEST(GaussianSetTest, addPBasis)
{
  GaussianSet gs;
  unsigned int idx = gs.addBasis(0, GaussianSet::P);
  EXPECT_EQ(idx, static_cast<unsigned int>(0));
}

TEST(GaussianSetTest, orbitalTypeMOCounts)
{
  // molecularOrbitalCount() is driven by the MO coefficient matrix,
  // not by addBasis(). Verify that after setting a coefficient matrix
  // with the right number of rows, the count is correct.
  GaussianSet gs;
  gs.addBasis(0, GaussianSet::S);
  gs.addBasis(0, GaussianSet::P);
  // S(1) + P(3) = 4 basis functions

  // Set a 4x4 coefficient matrix -> 4 MOs
  std::vector<double> moCoeffs(4 * 4, 0.0);
  gs.setMolecularOrbitals(moCoeffs, BasisSet::Paired);
  EXPECT_EQ(gs.molecularOrbitalCount(BasisSet::Paired),
            static_cast<unsigned int>(4));
}

TEST(GaussianSetTest, addGto)
{
  GaussianSet gs;
  unsigned int basis0 = gs.addBasis(0, GaussianSet::S);

  // STO-3G hydrogen: 3 primitives
  unsigned int gto0 = gs.addGto(basis0, 0.1543, 3.4253);
  unsigned int gto1 = gs.addGto(basis0, 0.5353, 0.6239);
  unsigned int gto2 = gs.addGto(basis0, 0.4446, 0.1689);

  EXPECT_EQ(gto0, static_cast<unsigned int>(0));
  EXPECT_EQ(gto1, static_cast<unsigned int>(1));
  EXPECT_EQ(gto2, static_cast<unsigned int>(2));

  // Check internal data
  EXPECT_EQ(gs.gtoA().size(), static_cast<size_t>(3));
  EXPECT_EQ(gs.gtoC().size(), static_cast<size_t>(3));
}

TEST(GaussianSetTest, setMolecularOrbitals)
{
  GaussianSet gs;
  gs.addBasis(0, GaussianSet::S);
  gs.addBasis(0, GaussianSet::S);
  // 2 s-type basis functions -> 2 MOs

  std::vector<double> moCoeffs = { 1.0, 0.0, 0.0, 1.0 };
  gs.setMolecularOrbitals(moCoeffs, BasisSet::Paired);

  EXPECT_EQ(gs.molecularOrbitalCount(BasisSet::Paired),
            static_cast<unsigned int>(2));
}

TEST(GaussianSetTest, uhfOrbitals)
{
  GaussianSet gs;
  gs.setScfType(Uhf);
  gs.addBasis(0, GaussianSet::S);
  // 1 MO

  std::vector<double> alpha = { 1.0 };
  std::vector<double> beta = { 0.5 };
  gs.setMolecularOrbitals(alpha, BasisSet::Alpha);
  gs.setMolecularOrbitals(beta, BasisSet::Beta);

  EXPECT_EQ(gs.molecularOrbitalCount(BasisSet::Alpha),
            static_cast<unsigned int>(1));
  EXPECT_EQ(gs.molecularOrbitalCount(BasisSet::Beta),
            static_cast<unsigned int>(1));
}

TEST(GaussianSetTest, scfType)
{
  GaussianSet gs;
  EXPECT_EQ(gs.scfType(), Rhf);

  gs.setScfType(Uhf);
  EXPECT_EQ(gs.scfType(), Uhf);

  gs.setScfType(Rohf);
  EXPECT_EQ(gs.scfType(), Rohf);

  gs.setScfType(Unknown);
  EXPECT_EQ(gs.scfType(), Unknown);
}

TEST(GaussianSetTest, functionalName)
{
  GaussianSet gs;
  EXPECT_TRUE(gs.functionalName().empty());

  gs.setFunctionalName("B3LYP");
  EXPECT_EQ(gs.functionalName(), "B3LYP");
}

TEST(GaussianSetTest, electronCount)
{
  GaussianSet gs;
  gs.setElectronCount(2, BasisSet::Paired);
  EXPECT_EQ(gs.electronCount(BasisSet::Paired), static_cast<unsigned int>(2));

  gs.setElectronCount(1, BasisSet::Alpha);
  gs.setElectronCount(1, BasisSet::Beta);
  EXPECT_EQ(gs.electronCount(BasisSet::Alpha), static_cast<unsigned int>(1));
  EXPECT_EQ(gs.electronCount(BasisSet::Beta), static_cast<unsigned int>(1));
}

TEST(GaussianSetTest, clone)
{
  GaussianSet gs;
  gs.addBasis(0, GaussianSet::S);
  gs.addBasis(0, GaussianSet::P);
  gs.setScfType(Uhf);
  gs.setFunctionalName("PBE");

  GaussianSet* cloned = gs.clone();
  EXPECT_EQ(cloned->molecularOrbitalCount(), gs.molecularOrbitalCount());
  EXPECT_EQ(cloned->scfType(), Uhf);
  EXPECT_EQ(cloned->functionalName(), "PBE");

  delete cloned;
}

// ---------------------------------------------------------------------------
// initCalculation() must be safe to run more than once. It runs again
// whenever shells or MOs are added after a first evaluation, and it used to
// append to cIndices and push another end-of-shells entry onto gtoIndices
// each time.
// ---------------------------------------------------------------------------

namespace {

struct PrimitiveSpec
{
  double c;
  double a;
};

struct ShellSpec
{
  unsigned int atom;
  GaussianSet::orbital type;
  std::vector<PrimitiveSpec> primitives;
};

// Two atoms 0.74 Angstrom apart: an s and p shell on the first, two s shells
// on the second. Five basis functions in all.
std::vector<ShellSpec> baseShells()
{
  return { { 0, GaussianSet::S, { { 0.4, 5.0 }, { 0.7, 1.2 } } },
           { 0, GaussianSet::P, { { 1.0, 0.9 } } },
           { 1, GaussianSet::S, { { 0.5, 3.0 }, { 0.6, 0.5 } } } };
}

// One more shell (a p shell, three functions) on the second atom.
ShellSpec extraShell()
{
  return { 1, GaussianSet::P, { { 0.8, 1.1 }, { 0.3, 0.4 } } };
}

unsigned int functionCount(const std::vector<ShellSpec>& shells)
{
  unsigned int count = 0;
  for (const auto& shell : shells)
    count += shell.type == GaussianSet::S ? 1 : 3;
  return count;
}

void addShell(GaussianSet& basis, const ShellSpec& shell)
{
  unsigned int index = basis.addBasis(shell.atom, shell.type);
  for (const auto& primitive : shell.primitives)
    basis.addGto(index, primitive.c, primitive.a);
}

// A deterministic, non-trivial MO matrix: nBasis rows, nBasis columns, with
// no symmetry that could hide an indexing slip.
std::vector<double> moCoefficients(unsigned int nBasis, double seed)
{
  std::vector<double> mos(static_cast<size_t>(nBasis) * nBasis);
  for (size_t i = 0; i < mos.size(); ++i)
    mos[i] = std::sin(seed + 0.37 * static_cast<double>(i)) /
             (1.0 + 0.1 * static_cast<double>(i % nBasis));
  return mos;
}

void setUpMolecule(Molecule& molecule)
{
  molecule.addAtom(8, Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(1, Vector3(0.0, 0.0, 0.74));
}

// Sets the MOs and rebuilds the density matrix from them. The point-wise
// GaussianSetTools::calculateElectronDensity() reads the stored density
// matrix, which setMolecularOrbitals() does not refresh.
void setOrbitals(GaussianSet& basis, unsigned int nBasis, double seed)
{
  basis.setMolecularOrbitals(moCoefficients(nBasis, seed), BasisSet::Paired);
  ASSERT_TRUE(basis.generateDensityMatrix());
}

// The molecule owns the basis set (setBasisSet takes ownership); the
// returned pointer stays valid for the molecule's lifetime and is the very
// object GaussianSetTools evaluates, since nothing else shares it.
GaussianSet* attachBasis(Molecule& molecule,
                         const std::vector<ShellSpec>& shells, double seed,
                         unsigned int electrons = 4)
{
  auto* basis = new GaussianSet;
  basis->setMolecule(&molecule);
  for (const auto& shell : shells)
    addShell(*basis, shell);
  basis->setElectronCount(electrons);
  setOrbitals(*basis, functionCount(shells), seed);
  molecule.setBasisSet(basis);
  return basis;
}

const Vector3 POINTS[] = { Vector3(0.0, 0.0, 0.0),  Vector3(0.1, -0.2, 0.3),
                           Vector3(0.0, 0.0, 0.74), Vector3(-0.4, 0.3, 0.5),
                           Vector3(0.5, 0.5, 1.2),  Vector3(-0.8, 0.1, -0.3) };

// Tools take a snapshot of the normalized coefficients when they are
// constructed, so a fresh GaussianSetTools is built for every comparison.
void expectSameValues(Molecule& actual, Molecule& expected)
{
  GaussianSetTools actualTools(&actual);
  GaussianSetTools expectedTools(&expected);
  const int nMOs = static_cast<int>(actual.basisSet()->molecularOrbitalCount());
  ASSERT_EQ(nMOs,
            static_cast<int>(expected.basisSet()->molecularOrbitalCount()));
  for (const Vector3& point : POINTS) {
    EXPECT_DOUBLE_EQ(actualTools.calculateElectronDensity(point),
                     expectedTools.calculateElectronDensity(point));
    for (int mo = 0; mo < nMOs; ++mo)
      EXPECT_DOUBLE_EQ(actualTools.calculateMolecularOrbital(point, mo),
                       expectedTools.calculateMolecularOrbital(point, mo));
  }
}

// After initialization the index arrays must describe every shell exactly
// once, and gtoIndices must end with the total number of primitives.
void expectConsistentIndices(const GaussianSet& basis, size_t nShells,
                             size_t nPrimitives)
{
  EXPECT_EQ(basis.moIndices().size(), nShells);
  EXPECT_EQ(basis.cIndices().size(), nShells);
  ASSERT_EQ(basis.gtoIndices().size(), nShells + 1);
  EXPECT_EQ(basis.gtoIndices().back(), nPrimitives);
}

size_t primitiveCount(const std::vector<ShellSpec>& shells)
{
  size_t count = 0;
  for (const auto& shell : shells)
    count += shell.primitives.size();
  return count;
}

} // namespace

TEST(GaussianSetTest, initCalculationIsIdempotent)
{
  Molecule molecule;
  setUpMolecule(molecule);
  const auto shells = baseShells();
  GaussianSet* basis = attachBasis(molecule, shells, 0.3);

  basis->initCalculation();
  const auto cIndices = basis->cIndices();
  const auto moIndices = basis->moIndices();
  const auto gtoIndices = basis->gtoIndices();
  const auto gtoCN = basis->gtoCN();
  expectConsistentIndices(*basis, shells.size(), primitiveCount(shells));

  // Re-setting the MOs clears the initialized flag, so this runs a second
  // and third initialization over the same shells.
  for (int pass = 0; pass < 2; ++pass) {
    setOrbitals(*basis, functionCount(shells), 0.3);
    basis->initCalculation();
    EXPECT_EQ(basis->cIndices(), cIndices);
    EXPECT_EQ(basis->moIndices(), moIndices);
    EXPECT_EQ(basis->gtoIndices(), gtoIndices);
    EXPECT_EQ(basis->gtoCN(), gtoCN);
  }
}

TEST(GaussianSetTest, settingMOsAfterEvaluationMatchesFreshBasis)
{
  Molecule molecule;
  setUpMolecule(molecule);
  const auto shells = baseShells();
  GaussianSet* basis = attachBasis(molecule, shells, 0.3);

  {
    // Evaluating initializes the basis.
    GaussianSetTools tools(&molecule);
    ASSERT_NE(tools.calculateElectronDensity(POINTS[1]), 0.0);
  }

  setOrbitals(*basis, functionCount(shells), 1.7);

  Molecule fresh;
  setUpMolecule(fresh);
  attachBasis(fresh, shells, 1.7);
  expectSameValues(molecule, fresh);
  expectConsistentIndices(*basis, shells.size(), primitiveCount(shells));
}

TEST(GaussianSetTest, addingAShellAfterEvaluationMatchesFreshBasis)
{
  Molecule molecule;
  setUpMolecule(molecule);
  auto shells = baseShells();
  GaussianSet* basis = attachBasis(molecule, shells, 0.3);

  {
    GaussianSetTools tools(&molecule);
    ASSERT_NE(tools.calculateElectronDensity(POINTS[1]), 0.0);
  }

  shells.push_back(extraShell());
  addShell(*basis, shells.back());
  setOrbitals(*basis, functionCount(shells), 2.9);

  Molecule fresh;
  setUpMolecule(fresh);
  attachBasis(fresh, shells, 2.9);
  expectSameValues(molecule, fresh);
  expectConsistentIndices(*basis, shells.size(), primitiveCount(shells));
}

TEST(GaussianSetTest, addingAPrimitiveAfterEvaluationMatchesFreshBasis)
{
  Molecule molecule;
  setUpMolecule(molecule);
  auto shells = baseShells();
  GaussianSet* basis = attachBasis(molecule, shells, 0.3);

  {
    GaussianSetTools tools(&molecule);
    ASSERT_NE(tools.calculateElectronDensity(POINTS[1]), 0.0);
  }

  // A primitive appended to the last shell, with no addBasis() or MO change
  // to reset the initialized flag for it.
  shells.back().primitives.push_back({ 0.2, 0.15 });
  basis->addGto(static_cast<unsigned int>(shells.size() - 1), 0.2, 0.15);

  Molecule fresh;
  setUpMolecule(fresh);
  attachBasis(fresh, shells, 0.3);
  expectSameValues(molecule, fresh);
  expectConsistentIndices(*basis, shells.size(), primitiveCount(shells));
}

TEST(GaussianSetTest, addingShellsOneByOneAfterEvaluation)
{
  // Grow a basis shell by shell, evaluating between each addition.
  Molecule molecule;
  setUpMolecule(molecule);
  auto* basis = new GaussianSet;
  basis->setMolecule(&molecule);
  molecule.setBasisSet(basis);
  // One occupied MO, so the density is defined from the first shell on.
  basis->setElectronCount(2);

  std::vector<ShellSpec> shells;
  auto all = baseShells();
  all.push_back(extraShell());
  for (const auto& shell : all) {
    shells.push_back(shell);
    addShell(*basis, shell);
    setOrbitals(*basis, functionCount(shells), 0.8);

    Molecule fresh;
    setUpMolecule(fresh);
    attachBasis(fresh, shells, 0.8, 2);
    expectSameValues(molecule, fresh);
    expectConsistentIndices(*basis, shells.size(), primitiveCount(shells));
  }
}

// A primitive for a shell other than the last (or a new) one would land in
// the wrong shell; it is refused and the basis is left as it was.
TEST(GaussianSetTest, addGtoToAnEarlierShellIsRefused)
{
  GaussianSet basis;
  unsigned int s = basis.addBasis(0, GaussianSet::S);
  basis.addGto(s, 0.5, 2.0);
  unsigned int p = basis.addBasis(0, GaussianSet::P);
  basis.addGto(p, 0.7, 1.0);
  basis.initCalculation();
  const std::vector<double> gtoA = basis.gtoA();
  const std::vector<unsigned int> gtoIndices = basis.gtoIndices();

  EXPECT_EQ(basis.addGto(s, 0.3, 0.5), 69696969u);
  EXPECT_EQ(basis.gtoA(), gtoA);
  EXPECT_EQ(basis.gtoIndices(), gtoIndices);

  // The last shell and a new one still take primitives.
  EXPECT_EQ(basis.addGto(p, 0.2, 0.3), 2u);
  unsigned int d = basis.addBasis(0, GaussianSet::D);
  EXPECT_EQ(basis.addGto(d, 1.0, 0.8), 3u);
}

// Trailing shells without primitives still get a start index, so every shell
// has a [start, end) range of primitives.
TEST(GaussianSetTest, trailingShellsWithoutPrimitives)
{
  GaussianSet basis;
  unsigned int s = basis.addBasis(0, GaussianSet::S);
  basis.addGto(s, 0.5, 2.0);
  basis.addBasis(0, GaussianSet::P);
  basis.addBasis(0, GaussianSet::D);
  basis.initCalculation();

  const std::vector<unsigned int> gtoIndices = basis.gtoIndices();
  ASSERT_EQ(gtoIndices.size(), 4u);
  EXPECT_EQ(gtoIndices[0], 0u);
  EXPECT_EQ(gtoIndices[1], 1u);
  EXPECT_EQ(gtoIndices[2], 1u);
  EXPECT_EQ(gtoIndices[3], 1u);
  EXPECT_EQ(basis.cIndices().size(), 3u);
}
