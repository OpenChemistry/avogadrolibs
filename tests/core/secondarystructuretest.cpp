/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/secondarystructure.h>

#include <cmath>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Core::Residue;
using Avogadro::Core::SecondaryStructureAssigner;

TEST(SecondaryStructureTest, constructorWithNull)
{
  SecondaryStructureAssigner ssa(nullptr);
  // Should not crash when given null
}

TEST(SecondaryStructureTest, emptyMolecule)
{
  Molecule mol;
  SecondaryStructureAssigner ssa;
  ssa.assign(&mol);
  // Should not crash with no residues
}

TEST(SecondaryStructureTest, singleResidue)
{
  Molecule mol;
  std::string name = "ALA";
  Index num = 1;
  char chain = 'A';
  Residue& res = mol.addResidue(name, num, chain);

  Atom n = mol.addAtom(7);
  n.setPosition3d(Vector3(0.0, 0.0, 0.0));
  res.addResidueAtom("N", n);

  Atom o = mol.addAtom(8);
  o.setPosition3d(Vector3(1.2, 0.0, 0.0));
  res.addResidueAtom("O", o);

  SecondaryStructureAssigner ssa;
  ssa.assign(&mol);
  // Single residue cannot form any secondary structure
  EXPECT_EQ(res.secondaryStructure(), Residue::undefined);
}

TEST(SecondaryStructureTest, noBackboneAtoms)
{
  Molecule mol;
  // Create residues without N or O atoms (no backbone)
  for (int i = 0; i < 5; ++i) {
    std::string name = "UNK";
    Index num = static_cast<Index>(i);
    char chain = 'A';
    Residue& res = mol.addResidue(name, num, chain);

    Atom ca = mol.addAtom(6); // only a CA, no N or O
    ca.setPosition3d(Vector3(i * 1.5, 0.0, 0.0));
    res.addResidueAtom("CA", ca);
  }

  SecondaryStructureAssigner ssa;
  ssa.assign(&mol);
  // All residues should stay undefined
  for (size_t i = 0; i < mol.residues().size(); ++i)
    EXPECT_EQ(mol.residue(i).secondaryStructure(), Residue::undefined);
}

TEST(SecondaryStructureTest, alphaHelixMinimal)
{
  // Build ~10 residues with backbone N and O atoms positioned
  // to mimic an alpha helix. Alpha helix: ~3.6 residues/turn,
  // rise ~1.5 A/residue, radius ~2.3 A.
  // Place O_i close to N_{i+4} to create i,i+4 hydrogen bonds.
  Molecule mol;
  const int numResidues = 10;
  const double radius = 2.3;
  const double rise = 1.5;
  const double degreesPerResidue = 100.0;
  const double degToRad = M_PI / 180.0;

  for (int i = 0; i < numResidues; ++i) {
    std::string resName = "ALA";
    Index resNum = static_cast<Index>(i);
    char chain = 'A';
    Residue& res = mol.addResidue(resName, resNum, chain);

    // N atom at helix position
    double angle = i * degreesPerResidue * degToRad;
    Atom n = mol.addAtom(7);
    n.setPosition3d(
      Vector3(radius * cos(angle), radius * sin(angle), rise * i));
    res.addResidueAtom("N", n);

    // O atom placed near where N_{i+4} will be
    // This creates the characteristic i,i+4 hydrogen bond pattern
    double oAngle = (i + 4) * degreesPerResidue * degToRad;
    double oZ = rise * (i + 4);
    Atom o = mol.addAtom(8);
    o.setPosition3d(Vector3(radius * cos(oAngle) + 0.2,
                            radius * sin(oAngle) + 0.2, oZ + 0.2));
    res.addResidueAtom("O", o);
  }

  SecondaryStructureAssigner ssa;
  ssa.assign(&mol);

  // Check that at least some middle residues are assigned alphaHelix
  // (edge residues may not be, and singleton removal may clear some)
  int helixCount = 0;
  for (int i = 0; i < numResidues; ++i) {
    if (mol.residue(i).secondaryStructure() == Residue::alphaHelix)
      ++helixCount;
  }
  // With 10 residues and proper geometry, we expect several to be alpha helix
  EXPECT_GT(helixCount, 0)
    << "Expected at least some residues to be assigned alpha helix";
}
