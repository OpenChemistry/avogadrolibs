/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>

#include <avogadro/io/mdlformat.h>
#include <avogadro/io/smilesformat.h>
#include <avogadro/io/smileswriter.h>

#include <map>
#include <set>
#include <string>

using Avogadro::Index;
using Avogadro::Core::Molecule;
using Avogadro::Io::MdlFormat;
using Avogadro::Io::SmilesFormat;
using Avogadro::Io::SmilesWriter;

namespace {

/** A writer in the only mode implemented so far. */
SmilesWriter mappedWriter()
{
  SmilesWriter writer;
  writer.setAtomMaps(true);
  return writer;
}

std::string writeMapped(const Molecule& mol)
{
  SmilesWriter writer = mappedWriter();
  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles)) << writer.error();
  return smiles;
}

/** Attach @a count hydrogens to @a heavy with single bonds. */
void addHydrogens(Molecule& mol, Index heavy, int count)
{
  for (int i = 0; i < count; ++i)
    mol.addBond(heavy, mol.addAtom(1).index(), 1);
}

/** Parentheses balance, and never close more than were opened. */
bool parenthesesBalanced(const std::string& smiles)
{
  int depth = 0;
  for (char c : smiles) {
    if (c == '(') {
      ++depth;
    } else if (c == ')') {
      if (--depth < 0)
        return false;
    }
  }
  return depth == 0;
}

/** Every ring bond number in the string occurs an even number of times. */
bool ringNumbersPaired(const std::string& smiles)
{
  std::map<int, int> counts;
  for (size_t i = 0; i < smiles.size(); ++i) {
    // Skip bracket contents, where digits are isotopes, charges and maps.
    if (smiles[i] == '[') {
      while (i < smiles.size() && smiles[i] != ']')
        ++i;
      continue;
    }
    if (smiles[i] == '%' && i + 2 < smiles.size()) {
      counts[(smiles[i + 1] - '0') * 10 + (smiles[i + 2] - '0')] += 1;
      i += 2;
    } else if (smiles[i] >= '0' && smiles[i] <= '9') {
      counts[smiles[i] - '0'] += 1;
    }
  }
  for (const auto& entry : counts) {
    if (entry.second % 2 != 0)
      return false;
  }
  return true;
}

/** Each atom map class 1..atomCount appears exactly once. */
bool everyAtomMapped(const std::string& smiles, Index atomCount)
{
  std::set<int> seen;
  for (size_t i = 0; i < smiles.size(); ++i) {
    if (smiles[i] != ':')
      continue;
    int value = 0;
    size_t j = i + 1;
    for (; j < smiles.size() && smiles[j] >= '0' && smiles[j] <= '9'; ++j)
      value = value * 10 + (smiles[j] - '0');
    if (j == i + 1)
      return false; // A colon with no digits after it.
    seen.insert(value);
    i = j - 1;
  }
  if (seen.size() != atomCount)
    return false;
  return *seen.begin() == 1 && *seen.rbegin() == static_cast<int>(atomCount);
}

} // namespace

TEST(SmilesTest, methane)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);

  EXPECT_EQ(writeMapped(mol), "[C:1]([H:2])([H:3])([H:4])[H:5]");
}

TEST(SmilesTest, methaneWithoutMaps)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);

  SmilesWriter writer;
  writer.setHydrogenMode(SmilesWriter::HydrogenMode::Explicit);
  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles)) << writer.error();
  EXPECT_EQ(smiles, "[C]([H])([H])([H])[H]");
}

TEST(SmilesTest, water)
{
  Molecule mol;
  Index oxygen = mol.addAtom(8).index();
  addHydrogens(mol, oxygen, 2);

  EXPECT_EQ(writeMapped(mol), "[O:1]([H:2])[H:3]");
}

TEST(SmilesTest, formalCharge)
{
  Molecule mol;
  Index nitrogen = mol.addAtom(7).index();
  mol.setFormalCharge(nitrogen, 1);
  addHydrogens(mol, nitrogen, 4);

  EXPECT_EQ(writeMapped(mol), "[N+:1]([H:2])([H:3])([H:4])[H:5]");
}

TEST(SmilesTest, multipleCharge)
{
  Molecule mol;
  Index magnesium = mol.addAtom(12).index();
  mol.setFormalCharge(magnesium, 2);

  EXPECT_EQ(writeMapped(mol), "[Mg+2:1]");

  Molecule anion;
  Index sulfur = anion.addAtom(16).index();
  anion.setFormalCharge(sulfur, -2);

  EXPECT_EQ(writeMapped(anion), "[S-2:1]");
}

TEST(SmilesTest, isotope)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);
  mol.setIsotope(carbon, 13);
  mol.setIsotope(1, 2);

  EXPECT_EQ(writeMapped(mol), "[13C:1]([2H:2])([H:3])([H:4])[H:5]");
}

TEST(SmilesTest, bondOrders)
{
  Molecule mol;
  Index first = mol.addAtom(6).index();
  Index second = mol.addAtom(6).index();
  mol.addBond(first, second, 2);
  addHydrogens(mol, first, 2);
  addHydrogens(mol, second, 2);

  EXPECT_EQ(writeMapped(mol), "[C:1](=[C:2]([H:5])[H:6])([H:3])[H:4]");

  Molecule triple;
  Index a = triple.addAtom(6).index();
  Index b = triple.addAtom(6).index();
  triple.addBond(a, b, 3);

  EXPECT_EQ(writeMapped(triple), "[C:1]#[C:2]");
}

TEST(SmilesTest, ringClosure)
{
  Molecule mol;
  Index a = mol.addAtom(6).index();
  Index b = mol.addAtom(6).index();
  Index c = mol.addAtom(6).index();
  mol.addBond(a, b, 1);
  mol.addBond(b, c, 1);
  mol.addBond(c, a, 1);

  EXPECT_EQ(writeMapped(mol), "[C:1]1[C:2][C:3]1");
}

TEST(SmilesTest, ringClosureBondOrder)
{
  // The closing bond carries the double bond, so the symbol has to travel to
  // the ring number rather than sitting between two atoms.
  Molecule mol;
  Index a = mol.addAtom(6).index();
  Index b = mol.addAtom(6).index();
  Index c = mol.addAtom(6).index();
  Index d = mol.addAtom(6).index();
  mol.addBond(a, b, 1);
  mol.addBond(b, c, 1);
  mol.addBond(c, d, 1);
  mol.addBond(d, a, 2);

  EXPECT_EQ(writeMapped(mol), "[C:1]=1[C:2][C:3][C:4]1");
}

TEST(SmilesTest, ringNumbersAreReused)
{
  // Two rings that do not overlap in the traversal should both use number 1.
  Molecule mol;
  for (int ring = 0; ring < 2; ++ring) {
    Index base = mol.atomCount();
    mol.addAtom(6);
    mol.addAtom(6);
    mol.addAtom(6);
    mol.addBond(base, base + 1, 1);
    mol.addBond(base + 1, base + 2, 1);
    mol.addBond(base + 2, base, 1);
  }

  EXPECT_EQ(writeMapped(mol), "[C:1]1[C:2][C:3]1.[C:4]1[C:5][C:6]1");
}

TEST(SmilesTest, disconnectedComponents)
{
  Molecule mol;
  mol.addAtom(11);
  mol.addAtom(17);

  EXPECT_EQ(writeMapped(mol), "[Na:1].[Cl:2]");
}

TEST(SmilesTest, atomsWithoutAnElementSymbol)
{
  // Dummy atoms, custom elements and InvalidElement all have to become the
  // wildcard: Elements::symbol() answers "Xx" for them, which is not valid
  // SMILES, and dropping them would leave a gap in the atom mapping.
  Molecule mol;
  mol.addAtom(0);
  mol.addAtom(Avogadro::InvalidElement);
  mol.addAtom(Avogadro::CustomElementMin);

  EXPECT_EQ(writeMapped(mol), "[*:1].[*:2].[*:3]");
}

TEST(SmilesTest, emptyMolecule)
{
  Molecule mol;
  SmilesWriter writer = mappedWriter();
  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles));
  EXPECT_EQ(smiles, "");
}

TEST(SmilesTest, atomMapsImplyExplicitHydrogens)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);

  SmilesWriter writer;
  writer.setHydrogenMode(SmilesWriter::HydrogenMode::Bracket);
  writer.setAtomMaps(true);

  EXPECT_EQ(writer.effectiveHydrogenMode(),
            SmilesWriter::HydrogenMode::Explicit);

  std::string smiles;
  EXPECT_TRUE(writer.write(mol, smiles)) << writer.error();
  EXPECT_EQ(smiles, "[C:1]([H:2])([H:3])([H:4])[H:5]");
}

TEST(SmilesTest, unimplementedModesFailCleanly)
{
  Molecule mol;
  mol.addAtom(6);

  for (SmilesWriter::HydrogenMode mode :
       { SmilesWriter::HydrogenMode::Implicit,
         SmilesWriter::HydrogenMode::Bracket }) {
    SmilesWriter writer;
    writer.setHydrogenMode(mode);
    std::string smiles;
    EXPECT_FALSE(writer.write(mol, smiles));
    EXPECT_FALSE(writer.error().empty());
    EXPECT_EQ(smiles, "");
  }
}

TEST(SmilesTest, formatIsWriteOnly)
{
  SmilesFormat format;
  EXPECT_EQ(format.supportedOperations() & Avogadro::Io::FileFormat::Read, 0);
  EXPECT_NE(format.supportedOperations() & Avogadro::Io::FileFormat::Write, 0);
}

TEST(SmilesTest, formatOptions)
{
  Molecule mol;
  Index carbon = mol.addAtom(6).index();
  addHydrogens(mol, carbon, 4);

  SmilesFormat format;
  format.setOptions("{\"atomMaps\": true}");
  std::string smiles;
  EXPECT_TRUE(format.writeString(smiles, mol)) << format.error();
  EXPECT_EQ(smiles, "[C:1]([H:2])([H:3])([H:4])[H:5]\n");

  SmilesFormat defaults;
  std::string unimplemented;
  EXPECT_FALSE(defaults.writeString(unimplemented, mol));
}

TEST(SmilesTest, structuralInvariantsOnRealMolecule)
{
  MdlFormat mdl;
  Molecule mol;
  ASSERT_TRUE(
    mdl.readFile(std::string(AVOGADRO_DATA) + "/data/sdf/ethane.mol", mol));

  const std::string smiles = writeMapped(mol);
  EXPECT_TRUE(parenthesesBalanced(smiles)) << smiles;
  EXPECT_TRUE(ringNumbersPaired(smiles)) << smiles;
  EXPECT_TRUE(everyAtomMapped(smiles, mol.atomCount())) << smiles;
}
