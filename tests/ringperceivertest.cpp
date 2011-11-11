#include <gtest/gtest.h>

#include <molecule.h>
#include <ringperceiver.h>

TEST(RingPerceiverTest, benzene)
{
  MolCore::Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 2);
  molecule.addBond(molecule.atom(2), molecule.atom(3), 1);
  molecule.addBond(molecule.atom(3), molecule.atom(4), 2);
  molecule.addBond(molecule.atom(4), molecule.atom(5), 1);
  molecule.addBond(molecule.atom(5), molecule.atom(0), 2);

  MolCore::RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t> > rings = perceiver.rings();
  EXPECT_EQ(rings.size(), 1);
  EXPECT_EQ(rings[0].size(), 6);
}

TEST(RingPerceiverTest, ethanol)
{
  MolCore::Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(8);
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 1);

  MolCore::RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t> > rings = perceiver.rings();
  EXPECT_EQ(rings.size(), 0);
}
