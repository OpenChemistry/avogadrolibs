/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::Vector3ub;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Core::Residue;

// The tests of the deprecated accessors call them on purpose.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

TEST(ResidueTest, defaultConstructor)
{
  Residue r;
  EXPECT_EQ(r.residueName(), "");
  EXPECT_EQ(r.chainId(), 'A');
  EXPECT_FALSE(r.isHeterogen());
  EXPECT_EQ(r.secondaryStructure(), Residue::undefined);
}

TEST(ResidueTest, constructorWithName)
{
  std::string name = "ALA";
  Residue r(name);
  EXPECT_EQ(r.residueName(), "ALA");
}

TEST(ResidueTest, constructorWithNameAndNumber)
{
  std::string name = "GLY";
  Index number = 42;
  Residue r(name, number);
  EXPECT_EQ(r.residueName(), "GLY");
  EXPECT_EQ(r.residueId(), static_cast<Index>(42));
}

TEST(ResidueTest, constructorFull)
{
  std::string name = "VAL";
  Index number = 7;
  char id = 'B';
  Residue r(name, number, id);
  EXPECT_EQ(r.residueName(), "VAL");
  EXPECT_EQ(r.residueId(), static_cast<Index>(7));
  EXPECT_EQ(r.chainId(), 'B');
}

TEST(ResidueTest, copyAndAssignment)
{
  std::string name = "LEU";
  Index number = 3;
  char id = 'A';
  Residue r1(name, number, id);
  r1.setSecondaryStructure(Residue::alphaHelix);
  r1.setHeterogen(true);

  // Copy constructor
  Residue r2(r1);
  EXPECT_EQ(r2.residueName(), "LEU");
  EXPECT_EQ(r2.residueId(), static_cast<Index>(3));
  EXPECT_EQ(r2.chainId(), 'A');
  EXPECT_EQ(r2.secondaryStructure(), Residue::alphaHelix);
  EXPECT_TRUE(r2.isHeterogen());

  // Assignment operator
  Residue r3;
  r3 = r1;
  EXPECT_EQ(r3.residueName(), "LEU");
  EXPECT_EQ(r3.residueId(), static_cast<Index>(3));
}

TEST(ResidueTest, settersGetters)
{
  Residue r;
  std::string name = "PHE";
  r.setResidueName(name);
  EXPECT_EQ(r.residueName(), "PHE");

  Index id = 10;
  r.setResidueId(id);
  EXPECT_EQ(r.residueId(), static_cast<Index>(10));

  r.setChainId('C');
  EXPECT_EQ(r.chainId(), 'C');

  r.setSecondaryStructure(Residue::betaSheet);
  EXPECT_EQ(r.secondaryStructure(), Residue::betaSheet);
}

TEST(ResidueTest, addAndLookupAtom)
{
  Molecule mol;
  Atom ca = mol.addAtom(6);
  ca.setPosition3d(Vector3(1.0, 2.0, 3.0));

  Residue r;
  r.addResidueAtom("CA", ca);

  Atom found = r.atomByName("CA");
  EXPECT_TRUE(found.isValid());
  EXPECT_EQ(found.index(), ca.index());
}

TEST(ResidueTest, atomByNameNotFound)
{
  Residue r;
  Atom notFound = r.atomByName("NONEXISTENT");
  EXPECT_FALSE(notFound.isValid());
}

TEST(ResidueTest, residueAtoms)
{
  Molecule mol;
  Atom n = mol.addAtom(7);
  Atom ca = mol.addAtom(6);
  Atom c = mol.addAtom(6);

  Residue r;
  r.addResidueAtom("N", n);
  r.addResidueAtom("CA", ca);
  r.addResidueAtom("C", c);

  std::vector<Atom> atoms = r.residueAtoms();
  EXPECT_EQ(atoms.size(), static_cast<size_t>(3));
}

TEST(ResidueTest, hasAtomByIndex)
{
  Molecule mol;
  Atom a0 = mol.addAtom(6);
  mol.addAtom(7); // index 1, not added to residue
  Atom a2 = mol.addAtom(8);

  Residue r;
  r.addResidueAtom("C", a0);
  r.addResidueAtom("O", a2);

  EXPECT_TRUE(r.hasAtomByIndex(0));
  EXPECT_FALSE(r.hasAtomByIndex(1));
  EXPECT_TRUE(r.hasAtomByIndex(2));
  EXPECT_FALSE(r.hasAtomByIndex(99));
}

TEST(ResidueTest, atomName)
{
  Molecule mol;
  Atom n = mol.addAtom(7);
  Atom ca = mol.addAtom(6);

  Residue r;
  r.addResidueAtom("N", n);
  r.addResidueAtom("CA", ca);

  EXPECT_EQ(r.atomName(n), "N");
  EXPECT_EQ(r.atomName(ca), "CA");
  EXPECT_EQ(r.atomName(static_cast<Index>(0)), "N");
  EXPECT_EQ(r.atomName(static_cast<Index>(1)), "CA");
}

#if defined(_MSC_VER)
#pragma warning(pop)
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

TEST(ResidueTest, atomIndicesAreSortedByIndexNotName)
{
  Molecule mol;
  Atom a0 = mol.addAtom(6);
  Atom a1 = mol.addAtom(7);
  Atom a2 = mol.addAtom(8);

  // The map orders by name ("A" < "B" < "Z"), the indices run 2, 0, 1.
  Residue r;
  r.addResidueAtom("A", a2);
  r.addResidueAtom("B", a0);
  r.addResidueAtom("Z", a1);

  const std::vector<Index> indices = r.atomIndices();
  ASSERT_EQ(indices.size(), static_cast<size_t>(3));
  EXPECT_EQ(indices[0], static_cast<Index>(0));
  EXPECT_EQ(indices[1], static_cast<Index>(1));
  EXPECT_EQ(indices[2], static_cast<Index>(2));
  EXPECT_TRUE(Residue().atomIndices().empty());
}

TEST(ResidueTest, atomIndexByName)
{
  Molecule mol;
  mol.addAtom(6);
  Atom ca = mol.addAtom(6);

  Residue r;
  r.addResidueAtom("CA", ca);

  EXPECT_EQ(r.atomIndexByName("CA"), static_cast<Index>(1));
  EXPECT_EQ(r.atomIndexByName("NONEXISTENT"), Avogadro::MaxIndex);
  EXPECT_EQ(r.atomIndexByName(""), Avogadro::MaxIndex);
}

TEST(ResidueTest, atomIndexMap)
{
  Molecule mol;
  Atom n = mol.addAtom(7);
  mol.addAtom(6);
  Atom c = mol.addAtom(6);

  Residue r;
  r.addResidueAtom("N", n);
  r.addResidueAtom("C", c);

  const std::map<std::string, Index> map = r.atomIndexMap();
  ASSERT_EQ(map.size(), static_cast<size_t>(2));
  EXPECT_EQ(map.at("N"), static_cast<Index>(0));
  EXPECT_EQ(map.at("C"), static_cast<Index>(2));
  EXPECT_TRUE(Residue().atomIndexMap().empty());

  // A copy, not a view: later changes to the residue do not show in it.
  r.addResidueAtom("CA", mol.atom(1));
  EXPECT_EQ(map.size(), static_cast<size_t>(2));
}

TEST(ResidueTest, indexAccessorsAgreeWithTheDeprecatedOnes)
{
  Molecule mol;
  Atom n = mol.addAtom(7);
  Atom ca = mol.addAtom(6);

  Residue r;
  r.addResidueAtom("N", n);
  r.addResidueAtom("CA", ca);

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
  EXPECT_EQ(r.atomByName("CA").index(), r.atomIndexByName("CA"));
  EXPECT_EQ(r.residueAtoms().size(), r.atomIndices().size());
  EXPECT_EQ(r.atomNameMap().size(), r.atomIndexMap().size());
#if defined(_MSC_VER)
#pragma warning(pop)
#elif defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
}

TEST(ResidueTest, heterogen)
{
  Residue r;
  EXPECT_FALSE(r.isHeterogen());
  r.setHeterogen(true);
  EXPECT_TRUE(r.isHeterogen());
  r.setHeterogen(false);
  EXPECT_FALSE(r.isHeterogen());
}

TEST(ResidueTest, customColor)
{
  Residue r;
  Vector3ub red(255, 0, 0);
  r.setColor(red);
  EXPECT_EQ(r.color(), red);
}

TEST(ResidueTest, secondaryStructureEnum)
{
  Residue r;

  r.setSecondaryStructure(Residue::alphaHelix);
  EXPECT_EQ(r.secondaryStructure(), Residue::alphaHelix);

  r.setSecondaryStructure(Residue::betaSheet);
  EXPECT_EQ(r.secondaryStructure(), Residue::betaSheet);

  r.setSecondaryStructure(Residue::helix310);
  EXPECT_EQ(r.secondaryStructure(), Residue::helix310);

  r.setSecondaryStructure(Residue::coil);
  EXPECT_EQ(r.secondaryStructure(), Residue::coil);

  r.setSecondaryStructure(Residue::turn);
  EXPECT_EQ(r.secondaryStructure(), Residue::turn);

  r.setSecondaryStructure(Residue::piHelix);
  EXPECT_EQ(r.secondaryStructure(), Residue::piHelix);

  r.setSecondaryStructure(Residue::undefined);
  EXPECT_EQ(r.secondaryStructure(), Residue::undefined);
}
