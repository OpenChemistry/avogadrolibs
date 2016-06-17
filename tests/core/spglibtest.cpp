/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/avospglib.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

using Avogadro::Matrix3;
using Avogadro::Vector3;
using Avogadro::Core::AvoSpglib;
using Avogadro::Core::Molecule;
using Avogadro::Core::SpaceGroups;
using Avogadro::Core::UnitCell;

TEST(SpglibTest, getSpaceGroup)
{
  Molecule mol;

  // First, let's build rutile
  mol.setData("name", "TiO2 rutile");

  Matrix3 mat;
  mat.col(0) = Vector3(2.95812, 0.00000, 0.00000); // A
  mat.col(1) = Vector3(0.00000, 4.59373, 0.00000); // B
  mat.col(2) = Vector3(0.00000, 0.00000, 4.59373); // C

  UnitCell *uc = new UnitCell(mat);

  mol.setUnitCell(uc);

  mol.addAtom(8).setPosition3d(uc->toCartesian(Vector3(0.0, 0.3053, 0.3053)));
  mol.addAtom(8).setPosition3d(uc->toCartesian(Vector3(0.0, 0.6947, 0.6947)));
  mol.addAtom(8).setPosition3d(uc->toCartesian(Vector3(0.5, 0.1947, 0.8053)));
  mol.addAtom(8).setPosition3d(uc->toCartesian(Vector3(0.5, 0.8053, 0.1947)));
  mol.addAtom(22).setPosition3d(uc->toCartesian(Vector3(0.0, 0.0, 0.0)));
  mol.addAtom(22).setPosition3d(uc->toCartesian(Vector3(0.5, 0.5, 0.5)));

  // Now let's find the space group of this crystal!
  double cartTol = 0.05;
  unsigned short hallNumber = AvoSpglib::getHallNumber(mol, cartTol);

  EXPECT_EQ(hallNumber, 419);

  unsigned short intNumber = SpaceGroups::internationalNumber(hallNumber);
  std::string schoenflies = SpaceGroups::schoenflies(hallNumber);
  std::string hallSymbol = SpaceGroups::hallSymbol(hallNumber);
  std::string intSymbol = SpaceGroups::internationalFull(hallNumber);

  EXPECT_EQ(intNumber, 136);
  EXPECT_EQ(schoenflies, std::string("D4h^14"));
  EXPECT_EQ(hallSymbol, std::string("-P 4n 2n"));
  EXPECT_EQ(intSymbol, std::string("P 4_2/m 2_1/n 2/m"));
}
