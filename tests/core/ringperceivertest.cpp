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
#include <avogadro/core/ringperceiver.h>

using Avogadro::Core::Molecule;
using Avogadro::Core::RingPerceiver;

TEST(RingPerceiverTest, benzene)
{
  Molecule molecule;
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

  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  EXPECT_EQ(rings.size(), static_cast<size_t>(1));
  EXPECT_EQ(rings[0].size(), static_cast<size_t>(6));
}

TEST(RingPerceiverTest, ethanol)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(8);
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 1);

  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  EXPECT_EQ(rings.size(), static_cast<size_t>(0));
}
