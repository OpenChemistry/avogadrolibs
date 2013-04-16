/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/hydrogentools.h>
#include <avogadro/core/molecule.h>

using namespace Avogadro::Core;

TEST(HydrogenToolsTest, removeAllHydrogens)
{
  Molecule mol;
  mol.addAtom(1);
  HydrogenTools::removeAllHydrogens(mol);
  EXPECT_EQ(mol.atomCount(), 0);

  Atom C1 = mol.addAtom(6);
  Atom C2 = mol.addAtom(6);
  Atom C3 = mol.addAtom(6);

  mol.addBond(C1, C2, 1);
  mol.addBond(C2, C3, 1);

  Atom H = mol.addAtom(1);
  mol.addBond(C1, H);
  H = mol.addAtom(1);
  mol.addBond(C1, H);
  H = mol.addAtom(1);
  mol.addBond(C1, H);

  H = mol.addAtom(1);
  mol.addBond(C2, H);
  H = mol.addAtom(1);
  mol.addBond(C2, H);

  H = mol.addAtom(1);
  mol.addBond(C3, H);
  H = mol.addAtom(1);
  mol.addBond(C3, H);
  H = mol.addAtom(1);
  mol.addBond(C3, H);

  HydrogenTools::removeAllHydrogens(mol);
  EXPECT_EQ(std::string("C3"), mol.formula());
}

TEST(HydrogenToolsTest, fixupHydrogens_C3H8)
{
  Molecule mol;
  Atom C1 = mol.addAtom(6);
  Atom C2 = mol.addAtom(6);
  Atom C3 = mol.addAtom(6);
  mol.addBond(C1, C2, 1);
  mol.addBond(C2, C3, 1);

  HydrogenTools::fixupHydrogens(mol);
  EXPECT_EQ(11, mol.atomCount());
  EXPECT_EQ(10, mol.bondCount());
  EXPECT_EQ(std::string("C3H8"), mol.formula());
}

TEST(HydrogenToolsTest, fixupHydrogens_C2H7NO)
{
  Molecule mol;
  Atom C1 = mol.addAtom(6);
  Atom C2 = mol.addAtom(6);
  Atom O1 = mol.addAtom(8);
  Atom N1 = mol.addAtom(7);
  mol.addBond(C1, C2, 1);
  mol.addBond(C2, O1, 1);
  mol.addBond(O1, N1, 1);

  HydrogenTools::fixupHydrogens(mol);
  EXPECT_EQ(11, mol.atomCount());
  EXPECT_EQ(10, mol.bondCount());
  EXPECT_EQ(std::string("C2H7NO"), mol.formula());
}

TEST(HydrogenToolsTest, fixupHydrogens_C2H4O)
{
  Molecule mol;
  Atom C1 = mol.addAtom(6);
  Atom C2 = mol.addAtom(6);
  Atom O1 = mol.addAtom(8);
  mol.addBond(C1, C2, 1);
  mol.addBond(C2, O1, 2);

  HydrogenTools::fixupHydrogens(mol);
  EXPECT_EQ(7, mol.atomCount());
  EXPECT_EQ(6, mol.bondCount());
  EXPECT_EQ(std::string("C2H4O"), mol.formula());
}

TEST(HydrogenToolsTest, valencyAdjustment_C)
{
  Molecule mol;
  Atom C = mol.addAtom(6);
  int expectedAdjustment = 4;
  for (int i = 0; i < 8; ++i, --expectedAdjustment) {
    EXPECT_EQ(expectedAdjustment, HydrogenTools::valencyAdjustment(C));
    mol.addBond(mol.addAtom(1), C, 1);
  }
}

TEST(HydrogenToolsTest, valencyAdjustment_N)
{
  Molecule mol;
  Atom N = mol.addAtom(7);
  int expectedAdjustment = 3;
  for (int i = 0; i < 8; ++i, --expectedAdjustment) {
    if (i == 4) // neutral N can have 3 or 5 bonds in our valence model.
      expectedAdjustment += 2;
    EXPECT_EQ(expectedAdjustment, HydrogenTools::valencyAdjustment(N));
    mol.addBond(mol.addAtom(1), N, 1);
  }
}

TEST(HydrogenToolsTest, valencyAdjustment_O)
{
  Molecule mol;
  Atom O = mol.addAtom(8);
  int expectedAdjustment = 2;
  for (int i = 0; i < 8; ++i, --expectedAdjustment) {
    EXPECT_EQ(expectedAdjustment, HydrogenTools::valencyAdjustment(O));
    mol.addBond(mol.addAtom(1), O, 1);
  }
}
