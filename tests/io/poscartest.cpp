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

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/poscarformat.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Core::UnitCell;
using Avogadro::Io::FileFormat;
using Avogadro::Io::PoscarFormat;
using Avogadro::Matrix3;
using Avogadro::Vector3;

TEST(PoscarTest, read)
{
  PoscarFormat poscar;
  Molecule molecule;
  EXPECT_TRUE(poscar.readFile(AVOGADRO_DATA "/data/rutile.POSCAR", molecule));
  ASSERT_EQ(poscar.error(), std::string());

  // First, let's check the unit cell
  UnitCell* uc = molecule.unitCell();

  EXPECT_EQ(uc->aVector(), Vector3(2.95812000, 0.00000000, 0.00000000));
  EXPECT_EQ(uc->bVector(), Vector3(0.00000000, 4.59373000, 0.00000000));
  EXPECT_EQ(uc->cVector(), Vector3(0.00000000, 0.00000000, 4.59373000));

  // Check that the number of atoms and number of bonds were read correctly
  EXPECT_EQ(molecule.atomCount(), 6);
  EXPECT_EQ(molecule.bondCount(), 0);

  // Check that the symbols were read correctly
  EXPECT_EQ(molecule.atom(0).atomicNumber(), 8);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 8);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 8);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 8);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 22);
  EXPECT_EQ(molecule.atom(5).atomicNumber(), 22);

  // Check a couple of positions to make sure they were read correctly
  // Need to convert to Fractional
  Vector3 pos1 = uc->toFractional(molecule.atom(1).position3d());
  Vector3 pos5 = uc->toFractional(molecule.atom(5).position3d());
  EXPECT_DOUBLE_EQ(pos1.x(), 0.0);
  EXPECT_DOUBLE_EQ(pos1.y(), 0.6947);
  EXPECT_DOUBLE_EQ(pos1.z(), 0.6947);
  EXPECT_DOUBLE_EQ(pos5.x(), 0.5);
  EXPECT_DOUBLE_EQ(pos5.y(), 0.5);
  EXPECT_DOUBLE_EQ(pos5.z(), 0.5);
}

TEST(PoscarTest, write)
{
  PoscarFormat poscar;
  Molecule molecule;

  molecule.setData("name", "TiO2 rutile");

  Matrix3 mat;
  mat.col(0) = Vector3(2.95812, 0.00000, 0.00000); // A
  mat.col(1) = Vector3(0.00000, 4.59373, 0.00000); // B
  mat.col(2) = Vector3(0.00000, 0.00000, 4.59373); // C

  UnitCell* uc = new UnitCell(mat);

  molecule.setUnitCell(uc);

  molecule.addAtom(8).setPosition3d(
    uc->toCartesian(Vector3(0.0, 0.3053, 0.3053)));
  molecule.addAtom(8).setPosition3d(
    uc->toCartesian(Vector3(0.0, 0.6947, 0.6947)));
  molecule.addAtom(8).setPosition3d(
    uc->toCartesian(Vector3(0.5, 0.1947, 0.8053)));
  molecule.addAtom(8).setPosition3d(
    uc->toCartesian(Vector3(0.5, 0.8053, 0.1947)));
  molecule.addAtom(22).setPosition3d(uc->toCartesian(Vector3(0.0, 0.0, 0.0)));
  molecule.addAtom(22).setPosition3d(uc->toCartesian(Vector3(0.5, 0.5, 0.5)));

  std::string output;
  EXPECT_TRUE(poscar.writeString(output, molecule));

  // The output should be an exact match with the sample file.
  std::istringstream outputStream(output);
  std::ifstream refStream(AVOGADRO_DATA "/data/rutile.POSCAR");
  char outputChar = '\0';
  char refChar = '\0';
  outputStream >> std::noskipws;
  refStream >> std::noskipws;
  bool checkedSomething = false;
  while ((outputStream >> outputChar) && (refStream >> refChar)) {
    ASSERT_EQ(refChar, outputChar);
    checkedSomething = true;
  }
  EXPECT_TRUE(checkedSomething);
}

TEST(PoscarTest, modes)
{
  // This tests some of the mode setting/checking code, not explicitly Poscar
  // but
  // a concrete implementation is required in order to test.
  PoscarFormat format;
  format.open(AVOGADRO_DATA "/data/rutile.POSCAR", FileFormat::Read);
  EXPECT_TRUE(format.isMode(FileFormat::Read));
  EXPECT_TRUE(format.mode() & FileFormat::Read);
  EXPECT_FALSE(format.isMode(FileFormat::Write));
}
