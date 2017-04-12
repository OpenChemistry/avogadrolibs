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
using Avogadro::Core::Variant;
using Avogadro::Io::FileFormat;
using Avogadro::Io::MdlFormat;

TEST(MdlTest, readFile)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success =
    mdl.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
}

TEST(MdlTest, atoms)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success =
    mdl.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.mol", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(mdl.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  Atom atom = molecule.atom(0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  atom = molecule.atom(1);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_DOUBLE_EQ(atom.position3d().x(), 0.7516);
  EXPECT_DOUBLE_EQ(atom.position3d().y(), -0.0224);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.0208);

  atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_DOUBLE_EQ(atom.position3d().x(), -1.1850);
  EXPECT_DOUBLE_EQ(atom.position3d().y(), 0.0044);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.9875);
}

TEST(MdlTest, bonds)
{
  MdlFormat mdl;
  Molecule molecule;
  bool success =
    mdl.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.mol", molecule);
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
  bool success = mdl.readFile(std::string(AVOGADRO_DATA) + "/data/ethane.mol",
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
  EXPECT_DOUBLE_EQ(atom.position3d().y(), 0.0044);
  EXPECT_DOUBLE_EQ(atom.position3d().z(), -0.9875);
  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(MdlTest, readMulti)
{
  MdlFormat multi;
  multi.open(AVOGADRO_DATA "/data/multi.sdf",
             FileFormat::Read | FileFormat::MultiMolecule);
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

  EXPECT_DOUBLE_EQ(molecule.atom(4).position3d().x(), -0.5134);
  EXPECT_DOUBLE_EQ(molecule.atom(4).position3d().y(), 0.8892);
  EXPECT_DOUBLE_EQ(molecule.atom(4).position3d().z(), -0.3630);

  // Now read in the second structure.
  Molecule molecule2;
  EXPECT_TRUE(multi.readMolecule(molecule2));
  ASSERT_EQ(multi.error(), "");
  EXPECT_EQ(molecule2.data("name").toString(), "Caffeine");
  EXPECT_EQ(molecule2.atomCount(), 24);
  EXPECT_EQ(molecule2.bondCount(), 25);

  // Should return false when there are no more molecules to be read in.
  EXPECT_FALSE(multi.readMolecule(molecule));
}

TEST(MdlTest, writeMulti)
{
  MdlFormat multi;
  multi.open(AVOGADRO_DATA "/data/multi.sdf",
             FileFormat::Read | FileFormat::MultiMolecule);
  Molecule mol[2];

  // Read in the two structures in the file.
  EXPECT_TRUE(multi.readMolecule(mol[0]));
  ASSERT_EQ(multi.error(), "");
  EXPECT_TRUE(multi.readMolecule(mol[1]));
  ASSERT_EQ(multi.error(), "");
  multi.close();

  // Now attempt to write out a multi-molecule file.
  multi.open("multitmp.sdf", FileFormat::Write | FileFormat::MultiMolecule);
  multi.writeMolecule(mol[0]);
  multi.writeMolecule(mol[1]);
  multi.close();

  // Finally, let's read them back in and check the basic properties match.
  multi.open("multitmp.sdf", FileFormat::Read | FileFormat::MultiMolecule);
  Molecule ref[2];
  EXPECT_TRUE(multi.readMolecule(ref[0]));
  EXPECT_TRUE(multi.readMolecule(ref[1]));
  // Compare some properties and see if they made it all the way back to us.
  for (int i = 0; i < 2; ++i) {
    EXPECT_EQ(mol[i].data("name").toString(), ref[i].data("name").toString());
    EXPECT_EQ(mol[i].atomCount(), ref[i].atomCount());
    EXPECT_EQ(mol[i].bondCount(), ref[i].bondCount());
  }
}

TEST(MdlTest, readSdfData)
{
  MdlFormat multi;
  multi.open(AVOGADRO_DATA "/data/pubchem3.sdf",
             FileFormat::Read | FileFormat::MultiMolecule);
  Molecule mol[2];
  EXPECT_TRUE(multi.readMolecule(mol[0]));
  EXPECT_TRUE(multi.readMolecule(mol[1]));

  // Check a few of the data parameters in the first few molecules.
  EXPECT_EQ(
    mol[0].data("PUBCHEM_IUPAC_INCHI").toString(),
    "InChI=1S/C9H17NO4/c1-7(11)14-8(5-9(12)13)6-10(2,3)4/h8H,5-6H2,1-4H3");
  EXPECT_EQ(mol[0].data("PUBCHEM_OPENEYE_CAN_SMILES").toString(),
            "CC(=O)OC(CC(=O)[O-])C[N+](C)(C)C");
  EXPECT_EQ(
    mol[1].data("PUBCHEM_IUPAC_INCHI").toString(),
    "InChI=1S/C9H17NO4/c1-7(11)14-8(5-9(12)13)6-10(2,3)4/h8H,5-6H2,1-4H3/p+1");
  EXPECT_EQ(mol[1].data("PUBCHEM_OPENEYE_CAN_SMILES").toString(),
            "CC(=O)OC(CC(=O)O)C[N+](C)(C)C");
}
