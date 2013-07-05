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

#include <avogadro/core/molecule.h>

#include <avogadro/io/mdlformat.h>

using Avogadro::Core::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Io::FileFormat;
using Avogadro::Io::MdlFormat;

TEST(MdlTest, readFile)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success = mdl.readFile(std::string(AVOGADRO_DATA) +
                                "/data/ethane.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
}

TEST(MdlTest, atoms)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success = mdl.readFile(std::string(AVOGADRO_DATA) +
                                "/data/ethane.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  Atom atom = molecule.atom(0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  atom = molecule.atom(1);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_DOUBLE_EQ(atom.position3d().x(),  0.7516);
  EXPECT_DOUBLE_EQ(atom.position3d().y(), -0.0224);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.0208);

  atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_DOUBLE_EQ(atom.position3d().x(), -1.1850);
  EXPECT_DOUBLE_EQ(atom.position3d().y(),  0.0044);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.9875);
}

TEST(MdlTest, bonds)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success = mdl.readFile(std::string(AVOGADRO_DATA) +
                                "/data/ethane.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(7));

  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
  bond = molecule.bond(6);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(4));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(7));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(MdlTest, saveFile)
{
  MdlFormat mdl;
  Molecule savedMolecule, molecule;
  bool success = mdl.readFile(std::string(AVOGADRO_DATA) +
                                "/data/ethane.mol",
                                savedMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");

  success = mdl.writeFile("ethanetmp.mol", savedMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");

  // Now read the file back in and check a few key values are still present.
  success = mdl.readFile("ethanetmp.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(7));
  Atom atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_DOUBLE_EQ(atom.position3d().x(), -1.1850);
  EXPECT_DOUBLE_EQ(atom.position3d().y(),  0.0044);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.9875);
  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(MdlTest, readMulti)
{
  MdlFormat multi;
  multi.open(AVOGADRO_DATA "/data/multi.sdf", FileFormat::Read);
  Molecule molecule;

  // Read in the first structure.
  EXPECT_TRUE(multi.readMolecule(molecule));
  ASSERT_EQ(multi.error(), "");

  EXPECT_EQ(molecule.data("name").toString(), "Methane");
  EXPECT_EQ(molecule.atomCount(), 5);
  EXPECT_EQ(molecule.bondCount(), 4);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 1);

  EXPECT_EQ(molecule.atom(4).position3d().x(), -0.5134);
  EXPECT_EQ(molecule.atom(4).position3d().y(),  0.8892);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.3630);

  // Now read in the second structure.
  Molecule molecule2;
  EXPECT_TRUE(multi.readMolecule(molecule2));
  ASSERT_EQ(multi.error(), "");
  EXPECT_EQ(molecule2.data("name").toString(), "Caffeine");
  EXPECT_EQ(molecule2.atomCount(), 24);
  EXPECT_EQ(molecule2.bondCount(), 25);
}
