/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>

TEST(MoleculeTest, size)
{
  Avogadro::Core::Molecule molecule;
  EXPECT_EQ(molecule.size(), 0);
}

TEST(MoleculeTest, isEmpty)
{
  Avogadro::Core::Molecule molecule;
  EXPECT_EQ(molecule.isEmpty(), true);
}

TEST(MoleculeTest, addAtom)
{
  Avogadro::Core::Molecule molecule;
  EXPECT_EQ(molecule.atomCount(), 0);

  Avogadro::Core::Atom atom = molecule.addAtom(6);
  EXPECT_EQ(atom.isValid(), true);
  EXPECT_EQ(molecule.atomCount(), 1);
  EXPECT_EQ(atom.index(), 0);
  EXPECT_EQ(atom.atomicNumber(), 6);

  Avogadro::Core::Atom atom2 = molecule.addAtom(1);
  EXPECT_EQ(atom2.isValid(), true);
  EXPECT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(atom2.index(), 1);
  EXPECT_EQ(atom2.atomicNumber(), 1);
}

TEST(MoleculeTest, addBond)
{
  Avogadro::Core::Molecule molecule;
  EXPECT_EQ(molecule.bondCount(), 0);

  Avogadro::Core::Atom a = molecule.addAtom(1);
  Avogadro::Core::Atom b = molecule.addAtom(1);
  Avogadro::Core::Bond bondAB = molecule.addBond(a, b);
  EXPECT_TRUE(bondAB.isValid());
  EXPECT_EQ(bondAB.molecule(), &molecule);
  EXPECT_EQ(molecule.bondCount(), 1);
  EXPECT_EQ(bondAB.index(), 0);
  EXPECT_EQ(bondAB.atom1().index(), a.index());
  EXPECT_EQ(bondAB.atom2().index(), b.index());
  EXPECT_EQ(bondAB.order(), 1);

  Avogadro::Core::Atom c = molecule.addAtom(1);
  Avogadro::Core::Bond bondBC = molecule.addBond(b, c, 2);
  EXPECT_TRUE(bondBC.isValid());
  EXPECT_EQ(molecule.bondCount(), 2);
  EXPECT_EQ(bondBC.index(), 1);
  EXPECT_EQ(bondBC.order(), 2);

  // try to lookup nonexistant bond
  Avogadro::Core::Bond bond = molecule.bond(a, c);
  EXPECT_FALSE(bond.isValid());

  // try to lookup bond between a and b
  bond = molecule.bond(a, b);
  EXPECT_TRUE(bond.isValid());
  EXPECT_EQ(bond.molecule(), &molecule);
  EXPECT_EQ(bond.atom1().index(), a.index());
  EXPECT_EQ(bond.atom2().index(), b.index());

  // try to lookup bond between b and c by index
  bond = molecule.bond(1);
  EXPECT_TRUE(bond.isValid());
  EXPECT_EQ(bond.molecule(), &molecule);
  EXPECT_EQ(bond.atom1().index(), b.index());
  EXPECT_EQ(bond.atom2().index(), c.index());
}

TEST(MoleculeTest, setData)
{
  Avogadro::Core::Molecule molecule;
  molecule.setData("name", "ethanol");
  EXPECT_EQ(molecule.data("name").toString(), "ethanol");
}
