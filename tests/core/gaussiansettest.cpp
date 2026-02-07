/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/gaussianset.h>

#include <vector>

using Avogadro::Core::BasisSet;
using Avogadro::Core::GaussianSet;
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
