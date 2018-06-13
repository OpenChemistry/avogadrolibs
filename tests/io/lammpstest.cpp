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

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/lammpsformat.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Core::UnitCell;
using Avogadro::Io::FileFormat;
using Avogadro::Io::LammpsFormat;

TEST(LammpsTest, read)
{
  LammpsFormat multi;
  multi.open(AVOGADRO_DATA "/data/silicon_bulk.dump",
             FileFormat::Read | FileFormat::MultiMolecule);
  Molecule molecule, molecule2;

  // Read in the structure.
  EXPECT_TRUE(multi.readMolecule(molecule));
  ASSERT_EQ(multi.error(), "");

  // First, let's check the unit cell
  UnitCell* uc = molecule.unitCell();

  EXPECT_EQ(uc->aVector(),
            Vector3(2.7155000000000001e+01, 0.00000000, 0.00000000));
  EXPECT_EQ(uc->bVector(),
            Vector3(0.00000000, 2.7155000000000001e+01, 0.00000000));
  EXPECT_EQ(uc->cVector(),
            Vector3(0.00000000, 0.00000000, 2.7155000000000001e+01));

  // Check that the number of atoms per step and number of steps in the
  // trajectory were read correctly
  EXPECT_EQ(molecule.atomCount(), 1000);
  EXPECT_EQ(molecule.coordinate3dCount(), 11);

  // Check a couple of positions to make sure they were read correctly
  EXPECT_EQ(molecule.atom(1).position3d().x(), 1.35775);
  EXPECT_EQ(molecule.atom(1).position3d().y(), 1.35775);
  EXPECT_EQ(molecule.atom(1).position3d().z(), 1.35775);
  EXPECT_EQ(molecule.atom(4).position3d().x(), 10.862);
  EXPECT_EQ(molecule.atom(4).position3d().y(), 0);
  EXPECT_EQ(molecule.atom(4).position3d().z(), 0);
}
