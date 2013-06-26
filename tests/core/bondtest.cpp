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

using Avogadro::Core::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;

TEST(BondTest, setOrder)
{
  Molecule molecule;
  Atom a = molecule.addAtom(1);
  Atom b = molecule.addAtom(1);
  Bond bond = molecule.addBond(a, b);
  EXPECT_EQ(bond.order(), 1);

  // change the bonds's order
  bond.setOrder(2);
  EXPECT_EQ(bond.order(), 2);
}

TEST(BondTest, operators)
{
  Molecule molecule;
  Atom atom1 = molecule.addAtom(1);
  Atom atom2 = molecule.addAtom(2);
  Atom atom3 = molecule.addAtom(3);
  Bond bond1 = molecule.addBond(atom1, atom2, 1);
  Bond bond2 = molecule.addBond(atom2, atom3, 2);

  EXPECT_TRUE(bond1 == molecule.bond(0));
  EXPECT_FALSE(bond1 != molecule.bond(0));
  EXPECT_TRUE(bond1 != molecule.bond(1));
  EXPECT_FALSE(bond1 == molecule.bond(1));
  EXPECT_TRUE(bond1 != bond2);
}
