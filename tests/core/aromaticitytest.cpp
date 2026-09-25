/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/aromaticity.h>
#include <avogadro/core/molecule.h>

#include <numeric>
#include <string>
#include <vector>

using Avogadro::Index;
using Avogadro::Core::AromaticityPerceiver;
using Avogadro::Core::Molecule;
using Avogadro::Core::NotAromaticCandidate;

namespace {

/**
 * Build a single ring from a compact description: one entry per ring atom
 * giving its atomic number, formal charge, and the order of the bond to the
 * next atom round the ring.
 */
struct RingAtom
{
  unsigned char atomicNumber;
  signed char charge;
  unsigned char bondToNext;
};

Molecule ring(const std::vector<RingAtom>& atoms)
{
  Molecule mol;
  for (const RingAtom& atom : atoms) {
    Index index = mol.addAtom(atom.atomicNumber).index();
    mol.setFormalCharge(index, atom.charge);
  }
  for (Index i = 0; i < atoms.size(); ++i)
    mol.addBond(i, (i + 1) % atoms.size(), atoms[i].bondToNext);
  return mol;
}

/**
 * True when the first @a ringSize atoms all came out aromatic. Ring atoms are
 * always added first, so any hydrogens or substituents added afterwards -- and
 * which are not in the ring -- are correctly ignored.
 */
bool allAromatic(const Molecule& mol, Index ringSize)
{
  AromaticityPerceiver perceiver(&mol);
  const std::vector<bool>& atoms = perceiver.aromaticAtoms();
  if (atoms.size() < ringSize || ringSize == 0)
    return false;
  for (Index i = 0; i < ringSize; ++i) {
    if (!atoms[i])
      return false;
  }
  return true;
}

bool noneAromatic(const Molecule& mol)
{
  AromaticityPerceiver perceiver(&mol);
  for (bool aromatic : perceiver.aromaticAtoms()) {
    if (aromatic)
      return false;
  }
  return true;
}

constexpr unsigned char C = 6;
constexpr unsigned char N = 7;
constexpr unsigned char O = 8;
constexpr unsigned char S = 16;
constexpr unsigned char B = 5;

} // namespace

TEST(AromaticityTest, benzene)
{
  EXPECT_TRUE(allAromatic(ring({ { C, 0, 2 },
                                 { C, 0, 1 },
                                 { C, 0, 2 },
                                 { C, 0, 1 },
                                 { C, 0, 2 },
                                 { C, 0, 1 } }),
                          6));
}

TEST(AromaticityTest, sixMemberedHeterocycles)
{
  // Pyridine: the nitrogen carries a ring double bond and gives one electron.
  EXPECT_TRUE(allAromatic(ring({ { N, 0, 2 },
                                 { C, 0, 1 },
                                 { C, 0, 2 },
                                 { C, 0, 1 },
                                 { C, 0, 2 },
                                 { C, 0, 1 } }),
                          6));
}

TEST(AromaticityTest, fiveMemberedHeterocycles)
{
  // Pyrrole, furan and thiophene all work the same way: the heteroatom has no
  // ring double bond and donates its lone pair.
  for (unsigned char heteroatom : { N, O, S }) {
    Molecule mol = ring({ { heteroatom, 0, 1 },
                          { C, 0, 2 },
                          { C, 0, 1 },
                          { C, 0, 2 },
                          { C, 0, 1 } });
    // Pyrrole's nitrogen needs its hydrogen to reach three connections.
    if (heteroatom == N)
      mol.addBond(0, mol.addAtom(1).index(), 1);
    EXPECT_TRUE(allAromatic(mol, 5)) << "atomic number " << int(heteroatom);
  }
}

TEST(AromaticityTest, imidazole)
{
  Molecule mol = ring({ { N, 0, 1 }, // pyrrole-type, donates two
                        { C, 0, 2 }, //
                        { N, 0, 1 }, // pyridine-type, donates one
                        { C, 0, 2 }, //
                        { C, 0, 1 } });
  mol.addBond(0, mol.addAtom(1).index(), 1);
  EXPECT_TRUE(allAromatic(mol, 5));
}

TEST(AromaticityTest, chargedRings)
{
  // Cyclopentadienyl anion: the carbanion donates its pair, giving six.
  EXPECT_TRUE(allAromatic(
    ring({ { C, -1, 1 }, { C, 0, 2 }, { C, 0, 1 }, { C, 0, 2 }, { C, 0, 1 } }),
    5));

  // Tropylium: the carbocation donates nothing, leaving six from the rest.
  EXPECT_TRUE(allAromatic(ring({ { C, 1, 1 },
                                 { C, 0, 2 },
                                 { C, 0, 1 },
                                 { C, 0, 2 },
                                 { C, 0, 1 },
                                 { C, 0, 2 },
                                 { C, 0, 1 } }),
                          7));
}

TEST(AromaticityTest, antiaromaticAndSaturatedRingsAreNot)
{
  // Cyclobutadiene: four electrons is not 4n+2.
  EXPECT_TRUE(
    noneAromatic(ring({ { C, 0, 2 }, { C, 0, 1 }, { C, 0, 2 }, { C, 0, 1 } })));

  // Cyclohexane: no atom has a p orbital to lend.
  Molecule cyclohexane = ring({ { C, 0, 1 },
                                { C, 0, 1 },
                                { C, 0, 1 },
                                { C, 0, 1 },
                                { C, 0, 1 },
                                { C, 0, 1 } });
  for (Index i = 0; i < 6; ++i) {
    cyclohexane.addBond(i, cyclohexane.addAtom(1).index(), 1);
    cyclohexane.addBond(i, cyclohexane.addAtom(1).index(), 1);
  }
  EXPECT_TRUE(noneAromatic(cyclohexane));

  // Cyclooctatetraene: eight electrons.
  EXPECT_TRUE(noneAromatic(ring({ { C, 0, 2 },
                                  { C, 0, 1 },
                                  { C, 0, 2 },
                                  { C, 0, 1 },
                                  { C, 0, 2 },
                                  { C, 0, 1 },
                                  { C, 0, 2 },
                                  { C, 0, 1 } })));

  // Borazine. Boron is not treated as a candidate, so the answer does not
  // depend on how the B-N bonds were drawn.
  EXPECT_TRUE(noneAromatic(ring({ { B, 0, 1 },
                                  { N, 0, 1 },
                                  { B, 0, 1 },
                                  { N, 0, 1 },
                                  { B, 0, 1 },
                                  { N, 0, 1 } })));
}

TEST(AromaticityTest, exocyclicDoubleBond)
{
  // 2-pyridone: the carbonyl carbon donates nothing, and the amide nitrogen
  // donates its pair, which still totals six.
  Molecule mol = ring({ { N, 0, 1 },
                        { C, 0, 1 },
                        { C, 0, 2 },
                        { C, 0, 1 },
                        { C, 0, 2 },
                        { C, 0, 1 } });
  mol.addBond(0, mol.addAtom(1).index(), 1); // N-H
  mol.addBond(1, mol.addAtom(O).index(), 2); // C=O, leaving the ring

  AromaticityPerceiver perceiver(&mol);
  EXPECT_EQ(perceiver.piContributions()[1], 0) << "carbonyl carbon";
  EXPECT_EQ(perceiver.piContributions()[0], 2) << "amide nitrogen";
  EXPECT_TRUE(perceiver.aromaticAtoms()[0]);
  EXPECT_TRUE(perceiver.aromaticAtoms()[1]);
  EXPECT_FALSE(perceiver.aromaticAtoms()[7]) << "the oxygen is not in a ring";
}

TEST(AromaticityTest, fusedRings)
{
  // Naphthalene, built as two six-membered rings sharing a bond.
  Molecule mol;
  for (int i = 0; i < 10; ++i)
    mol.addAtom(C);
  const int bonds[11][3] = { { 0, 1, 2 }, { 1, 2, 1 }, { 2, 3, 2 }, { 3, 4, 1 },
                             { 4, 5, 2 }, { 5, 0, 1 }, { 4, 6, 1 }, { 6, 7, 2 },
                             { 7, 8, 1 }, { 8, 9, 2 }, { 9, 3, 1 } };
  for (const auto& bond : bonds)
    mol.addBond(bond[0], bond[1], static_cast<unsigned char>(bond[2]));

  EXPECT_TRUE(allAromatic(mol, 10));

  AromaticityPerceiver perceiver(&mol);
  ASSERT_EQ(perceiver.ringSystems().size(), 1u)
    << "the two rings are fused, so they form one system";
  EXPECT_EQ(perceiver.ringSystems()[0].size(), 10u);
}

TEST(AromaticityTest, azuleneNeedsTheWholeSystem)
{
  // Neither ring satisfies Huckel alone -- five and seven atoms -- but the
  // fused system has ten pi electrons.
  Molecule mol;
  for (int i = 0; i < 10; ++i)
    mol.addAtom(C);
  const int bonds[11][3] = { { 0, 1, 2 }, { 1, 2, 1 }, { 2, 3, 2 }, { 3, 4, 1 },
                             { 4, 0, 1 }, { 0, 5, 1 }, { 5, 6, 2 }, { 6, 7, 1 },
                             { 7, 8, 2 }, { 8, 9, 1 }, { 9, 4, 2 } };
  for (const auto& bond : bonds)
    mol.addBond(bond[0], bond[1], static_cast<unsigned char>(bond[2]));

  EXPECT_TRUE(allAromatic(mol, 10));
}

TEST(AromaticityTest, acyclicMoleculesHaveNoAromaticity)
{
  Molecule mol;
  Index a = mol.addAtom(C).index();
  Index b = mol.addAtom(C).index();
  mol.addBond(a, b, 2);

  AromaticityPerceiver perceiver(&mol);
  EXPECT_TRUE(noneAromatic(mol));
  EXPECT_EQ(perceiver.piContributions()[0], NotAromaticCandidate);
  EXPECT_TRUE(perceiver.ringSystems().empty());
}

TEST(AromaticityTest, emptyMolecule)
{
  Molecule mol;
  AromaticityPerceiver perceiver(&mol);
  EXPECT_TRUE(perceiver.aromaticAtoms().empty());
  EXPECT_TRUE(perceiver.ringSystems().empty());

  AromaticityPerceiver detached;
  EXPECT_TRUE(detached.aromaticAtoms().empty());
}
