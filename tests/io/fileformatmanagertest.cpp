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

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/core/molecule.h>

using Avogadro::Core::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;

TEST(FileFormatManagerTest, readFile)
{
  FileFormat *format = FileFormatManager::instance().formatFromIdentifier("CML");
  EXPECT_TRUE(format != NULL);
  if (!format)
    return;
  Molecule molecule;
  format->readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cml", molecule);

  EXPECT_EQ(molecule.data("name").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");

  EXPECT_EQ(molecule.data("inchi").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(FileFormatManagerTest, identifiers)
{
  std::vector<std::string> ids = FileFormatManager::instance().identifiers();
  std::cout << "FileFormatManager has loaded " << ids.size() << " formats.\n";
  for (size_t i = 0; i < ids.size(); ++i)
    std::cout << i << ": " << ids[i] << std::endl;
  std::vector<std::string> mimes = FileFormatManager::instance().mimeTypes();
  std::cout << "\nMIME types supported:\n";
  for (size_t i = 0; i < mimes.size(); ++i)
    std::cout << "\t" << mimes[i] << std::endl;
  std::vector<std::string> extensions =
    FileFormatManager::instance().fileExtensions();
  std::cout << "\nFile extensions supported:\n";
  for (size_t i = 0; i < extensions.size(); ++i)
    std::cout << "\t" << extensions[i] << std::endl;
}

TEST(FileFormatManagerTest, readFileGuessCml)
{
  Molecule molecule;
  FileFormatManager::instance().readFile(molecule,
                                         std::string(AVOGADRO_DATA)
                                         + "/data/ethane.cml");
  EXPECT_EQ(molecule.data("name").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.data("inchi").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(FileFormatManagerTest, readFileGuessCjson)
{
  Molecule molecule;
  FileFormatManager::instance().readFile(molecule,
                                         std::string(AVOGADRO_DATA)
                                         + "/data/ethane.cjson");
  EXPECT_EQ(molecule.data("name").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.data("inchi").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(FileFormatManagerTest, writeFileGuessCml)
{
  Molecule readMol, writeMol;
  FileFormatManager::instance().readFile(readMol,
                                         std::string(AVOGADRO_DATA)
                                         + "/data/ethane.cml");
  FileFormatManager::instance().writeFile(readMol, "ethanemanagertmp.cml");

  // Now read the file back in and check a few key values are still present.
  FileFormatManager::instance().readFile(writeMol, "ethanemanagertmp.cml");
  EXPECT_EQ(writeMol.data("name").toString(), "Ethane");
  EXPECT_EQ(writeMol.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(writeMol.bondCount(), static_cast<size_t>(7));
  Atom atom = writeMol.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.18499);
  EXPECT_EQ(atom.position3d().y(),  0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
  Bond bond = writeMol.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(FileFormatManagerTest, writeStringCjson)
{
  Molecule molecule;
  FileFormatManager::instance().readFile(molecule,
                                         std::string(AVOGADRO_DATA)
                                         + "/data/ethane.cjson");
  std::string cjson;
  FileFormatManager::instance().writeString(molecule, cjson, "cjson");
  std::string cml;
  FileFormatManager::instance().writeString(molecule, cml, "cml");

  std::cout << cjson << std::endl;
  std::cout << cml << std::endl;

  // See if they still have data in them now they have gone back and forth...
  Molecule cmlMol, cjsonMol;
  FileFormatManager::instance().readString(cjsonMol, cjson, "cjson");
  FileFormatManager::instance().readString(cmlMol, cml, "cml");

  EXPECT_EQ(cjsonMol.data("name").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(cjsonMol.data("name").toString(), "Ethane");
  EXPECT_EQ(cjsonMol.data("inchi").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(cjsonMol.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");

  EXPECT_EQ(cmlMol.data("name").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(cmlMol.data("name").toString(), "Ethane");
  EXPECT_EQ(cmlMol.data("inchi").type(), Avogadro::Core::Variant::String);
  EXPECT_EQ(cmlMol.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}
