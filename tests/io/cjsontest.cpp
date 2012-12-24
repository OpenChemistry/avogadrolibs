/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>

#include <avogadro/io/cjsonformat.h>

using Avogadro::Core::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Io::CjsonFormat;
using Avogadro::MatrixX;

TEST(CjsonTest, readFile)
{
  CjsonFormat cjson;
  Molecule molecule;
  cjson.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cjson", molecule);

  EXPECT_EQ(molecule.data("name").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");

  EXPECT_EQ(molecule.data("inchi").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(CjsonTest, atoms)
{
  CjsonFormat cjson;
  Molecule molecule;
  cjson.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cjson", molecule);

  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  Atom atom = molecule.atom(0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  atom = molecule.atom(1);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(atom.position3d().x(),  0.751621);
  EXPECT_EQ(atom.position3d().y(), -0.022441);
  EXPECT_EQ(atom.position3d().z(), -0.020839);

  atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.184988);
  EXPECT_EQ(atom.position3d().y(),  0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
}

TEST(CjsonTest, bonds)
{
  CjsonFormat cjson;
  Molecule molecule;
  cjson.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cjson", molecule);

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

TEST(CjsonTest, saveFile)
{
  CjsonFormat cjson;
  Molecule savedMolecule, molecule;
  cjson.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cjson",
                 savedMolecule);
  cjson.writeFile("ethane.cjson", savedMolecule);

  // Now read the file back in and check a few key values are still present.
  cjson.readFile("ethane.cjson", molecule);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(7));
  Atom atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.184988);
  EXPECT_EQ(atom.position3d().y(),  0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}
