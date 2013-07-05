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
#include <avogadro/core/vector.h>

#include <avogadro/io/xyzformat.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::Io::XyzFormat;
using Avogadro::Vector3;

// methane.xyz uses atomic symbols to identify atoms
TEST(XyzTest, readAtomicSymbols)
{
  XyzFormat xyz;
  Molecule molecule;
  EXPECT_TRUE(xyz.readFile(AVOGADRO_DATA "/data/methane.xyz", molecule));
  ASSERT_EQ(xyz.error(), std::string());

  EXPECT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.bondCount(), 0);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 1);

  EXPECT_EQ(molecule.atom(4).position3d().x(), -0.51336);
  EXPECT_EQ(molecule.atom(4).position3d().y(),  0.88916);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.36300);
}

// methane-num.xyz uses atomic numbers to identify atoms
TEST(XyzTest, readAtomicNumbers)
{
  XyzFormat xyz;
  Molecule molecule;
  xyz.readFile(AVOGADRO_DATA "/data/methane-num.xyz", molecule);

  EXPECT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.bondCount(), 0);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 1);

  EXPECT_EQ(molecule.atom(4).position3d().x(), -0.51336);
  EXPECT_EQ(molecule.atom(4).position3d().y(),  0.88916);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.36300);
}

TEST(XyzTest, write)
{
  XyzFormat xyz;
  Molecule molecule;

  molecule.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(1).setPosition3d(Vector3(0.0, 0.0, 1.089));
  molecule.addAtom(1).setPosition3d(Vector3(1.026719, 0.0, -0.363));
  molecule.addAtom(1).setPosition3d(Vector3(-0.51336, -0.889165, -0.363));
  molecule.addAtom(1).setPosition3d(Vector3(-0.51336, 0.889165, -0.363));
  std::string output;
  EXPECT_EQ(xyz.writeString(output, molecule), true);

  // The output should be an exact match with the sample file.
  std::istringstream outputStream(output);
  std::ifstream refStream(AVOGADRO_DATA "/data/methane.xyz");
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

TEST(XyzTest, readMulti)
{
  XyzFormat xyz(AVOGADRO_DATA "/data/multi.xyz", FileFormat::Read);
  Molecule molecule;

  // Read in the first structure.
  EXPECT_TRUE(xyz.readMolecule(molecule));
  ASSERT_EQ(xyz.error(), "");

  EXPECT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.bondCount(), 0);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 1);

  EXPECT_EQ(molecule.atom(4).position3d().x(), -0.51336);
  EXPECT_EQ(molecule.atom(4).position3d().y(),  0.88916);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.36300);

  // Now read in the second structure.
  Molecule molecule2;
  EXPECT_TRUE(xyz.readMolecule(molecule2));
  ASSERT_EQ(xyz.error(), "");
  EXPECT_EQ(molecule2.atomCount(), 24);
  EXPECT_EQ(molecule2.bondCount(), 0);
}
