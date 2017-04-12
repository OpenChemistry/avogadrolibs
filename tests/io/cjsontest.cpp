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
#include <avogadro/core/unitcell.h>

#include <avogadro/io/cjsonformat.h>

using Avogadro::PI_F;
using Avogadro::Real;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Molecule;
using Avogadro::Core::UnitCell;
using Avogadro::Core::Variant;
using Avogadro::Io::CjsonFormat;
using Avogadro::MatrixX;

TEST(CjsonTest, readFile)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success =
    cjson.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");

  EXPECT_EQ(molecule.data("inchi").type(), Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(CjsonTest, atoms)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success =
    cjson.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  Atom atom = molecule.atom(0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  atom = molecule.atom(1);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(atom.position3d().x(), 0.751621);
  EXPECT_EQ(atom.position3d().y(), -0.022441);
  EXPECT_EQ(atom.position3d().z(), -0.020839);

  atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.184988);
  EXPECT_EQ(atom.position3d().y(), 0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
}

TEST(CjsonTest, bonds)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success =
    cjson.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
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

TEST(CjsonTest, crystal)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success =
    cjson.readFile(std::string(AVOGADRO_DATA) + "/data/rutile.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "TiO2 rutile");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(6));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(0));

  const UnitCell* unitCell = molecule.unitCell();
  ASSERT_NE(unitCell, (UnitCell*)nullptr);
  EXPECT_TRUE(std::fabs((float)unitCell->a() - 2.95812f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->b() - 4.59373f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->c() - 4.59373f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->alpha() - (.5f * PI_F)) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->beta() - (.5f * PI_F)) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->gamma() - (.5f * PI_F)) < 1e-5f);

  Atom atom = molecule.atom(5);
  EXPECT_EQ(atom.atomicNumber(), 8);
  EXPECT_TRUE(std::fabs((float)atom.position3d().x() - 1.479060f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)atom.position3d().y() - 3.699331f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)atom.position3d().z() - 0.894399f) < 1e-5f);

  std::string cjsonStr;
  cjson.writeString(cjsonStr, molecule);
  Molecule otherMolecule;
  cjson.readString(cjsonStr, otherMolecule);

  const UnitCell* otherUnitCell = otherMolecule.unitCell();
  ASSERT_NE(otherUnitCell, (UnitCell*)nullptr);
  EXPECT_FLOAT_EQ((float)otherUnitCell->a(), (float)unitCell->a());
  EXPECT_FLOAT_EQ((float)otherUnitCell->b(), (float)unitCell->b());
  EXPECT_FLOAT_EQ((float)otherUnitCell->c(), (float)unitCell->c());
  EXPECT_FLOAT_EQ((float)otherUnitCell->alpha(), (float)unitCell->alpha());
  EXPECT_FLOAT_EQ((float)otherUnitCell->beta(), (float)unitCell->beta());
  EXPECT_FLOAT_EQ((float)otherUnitCell->gamma(), (float)unitCell->gamma());

  Atom otherAtom = otherMolecule.atom(5);
  EXPECT_EQ(otherAtom.atomicNumber(), atom.atomicNumber());
  EXPECT_FLOAT_EQ((float)otherAtom.position3d().x(),
                  (float)atom.position3d().x());
  EXPECT_FLOAT_EQ((float)otherAtom.position3d().y(),
                  (float)atom.position3d().y());
  EXPECT_FLOAT_EQ((float)otherAtom.position3d().z(),
                  (float)atom.position3d().z());
}

TEST(CjsonTest, saveFile)
{
  CjsonFormat cjson;
  Molecule savedMolecule, molecule;
  bool success = cjson.readFile(
    std::string(AVOGADRO_DATA) + "/data/ethane.cjson", savedMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");

  success = cjson.writeFile("ethanetmp.cjson", savedMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");

  // Now read the file back in and check a few key values are still present.
  success = cjson.readFile("ethanetmp.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(7));
  Atom atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.184988);
  EXPECT_EQ(atom.position3d().y(), 0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}
