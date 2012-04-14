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

#include <atom.h>
#include <bond.h>
#include <molecule.h>

TEST(BondTest, setOrder)
{
  Avogadro::Core::Molecule molecule;
  Avogadro::Core::Atom a = molecule.addAtom(1);
  Avogadro::Core::Atom b = molecule.addAtom(1);
  Avogadro::Core::Bond bond = molecule.addBond(a, b);
  EXPECT_EQ(bond.order(), 1);

  // change the bonds's order
  bond.setOrder(2);
  EXPECT_EQ(bond.order(), 2);
}
