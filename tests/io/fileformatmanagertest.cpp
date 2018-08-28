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
#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

using Avogadro::Core::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Variant;
using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;

TEST(FileFormatManagerTest, readFile)
{
  FileFormat* format =
    FileFormatManager::instance().newFormatFromIdentifier("Avogadro: CML");
  EXPECT_TRUE(format != nullptr);
  if (!format)
    return;
  Molecule molecule;
  format->readFile(std::string(AVOGADRO_DATA) + "/data/ethane.cml", molecule);
  delete format;
  format = nullptr;

  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");

  EXPECT_EQ(molecule.data("inchi").type(), Variant::String);
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
  FileFormatManager::instance().readFile(molecule, std::string(AVOGADRO_DATA) +
                                                     "/data/ethane.cml");
  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.data("inchi").type(), Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(FileFormatManagerTest, readFileGuessCjson)
{
  Molecule molecule;
  FileFormatManager::instance().readFile(molecule, std::string(AVOGADRO_DATA) +
                                                     "/data/ethane.cjson");
  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.data("inchi").type(), Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(FileFormatManagerTest, writeFileGuessCml)
{
  Molecule readMol, writeMol;
  FileFormatManager::instance().readFile(readMol, std::string(AVOGADRO_DATA) +
                                                    "/data/ethane.cml");
  FileFormatManager::instance().writeFile(readMol, "ethanemanagertmp.cml");

  // Now read the file back in and check a few key values are still present.
  FileFormatManager::instance().readFile(writeMol, "ethanemanagertmp.cml");
  EXPECT_EQ(writeMol.data("name").toString(), "Ethane");
  EXPECT_EQ(writeMol.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(writeMol.bondCount(), static_cast<size_t>(7));
  Atom atom = writeMol.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.18499);
  EXPECT_EQ(atom.position3d().y(), 0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
  Bond bond = writeMol.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(FileFormatManagerTest, writeStringCjson)
{
  Molecule molecule;
  FileFormatManager::instance().readFile(molecule, std::string(AVOGADRO_DATA) +
                                                     "/data/ethane.cjson");
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

  EXPECT_EQ(cjsonMol.data("name").type(), Variant::String);
  EXPECT_EQ(cjsonMol.data("name").toString(), "Ethane");
  EXPECT_EQ(cjsonMol.data("inchi").type(), Variant::String);
  EXPECT_EQ(cjsonMol.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");

  EXPECT_EQ(cmlMol.data("name").type(), Variant::String);
  EXPECT_EQ(cmlMol.data("name").toString(), "Ethane");
  EXPECT_EQ(cmlMol.data("inchi").type(), Variant::String);
  EXPECT_EQ(cmlMol.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(FileFormatManagerTest, writeStringCjsonOptions)
{
  Molecule molecule;
  std::string options = "{ \"properties\": false }";
  FileFormatManager::instance().readFile(molecule, std::string(AVOGADRO_DATA) +
                                                     "/data/ethane.cjson");
  std::string cjson;
  FileFormatManager::instance().writeString(molecule, cjson, "cjson", options);

  std::cout << cjson << std::endl;

  // See if they still have data in them now they have gone back and forth...
  Molecule cjsonMol;
  FileFormatManager::instance().readString(cjsonMol, cjson, "cjson");

  // If the option was respected these should now be empty.
  EXPECT_EQ(cjsonMol.data("name").type(), Variant::Null);
  EXPECT_EQ(cjsonMol.data("name").toString(), "");
  EXPECT_EQ(cjsonMol.data("inchi").type(), Variant::Null);
  EXPECT_EQ(cjsonMol.data("inchi").toString(), "");
}

class Format : public FileFormat
{
private:
  Operations m_ops;
  std::string m_ident;

public:
  Format(const std::string& ident, Operations ops)
    : FileFormat(), m_ops(ops), m_ident(ident)
  {
  }
  Operations supportedOperations() const override { return m_ops; }
  bool read(std::istream&, Molecule&) override { return false; }
  bool write(std::ostream&, const Molecule&) override { return false; }
  FileFormat* newInstance() const override
  {
    return new Format(m_ident, m_ops);
  }
  std::string identifier() const override { return m_ident; }
  std::string name() const override { return m_ident; }
  std::string description() const override { return m_ident; }
  std::string specificationUrl() const override { return ""; }
  std::vector<std::string> fileExtensions() const override
  {
    std::vector<std::string> result;
    result.push_back("asdfjkl;");
    return result;
  }
  std::vector<std::string> mimeTypes() const override
  {
    std::vector<std::string> result;
    result.push_back("chemical/x-doodie");
    return result;
  }
};

TEST(FileFormatManagerTest, filtering)
{
  // Add formats with various supported operations
  Format readOnly("readOnly", Format::All ^ Format::Write);
  Format writeOnly("writeOnly", Format::All ^ Format::Read);
  FileFormatManager::registerFormat(readOnly.newInstance());
  FileFormatManager::registerFormat(writeOnly.newInstance());

  FileFormatManager& manager = FileFormatManager::instance();
  FileFormat* format = nullptr;

  format = manager.newFormatFromFileExtension("asdfjkl;", Format::Read);
  ASSERT_TRUE(format != nullptr);
  EXPECT_EQ(format->identifier(), std::string("readOnly"));
  delete format;

  format = manager.newFormatFromFileExtension("asdfjkl;", Format::Write);
  ASSERT_TRUE(format != nullptr);
  EXPECT_EQ(format->identifier(), std::string("writeOnly"));
  delete format;

  format = manager.newFormatFromMimeType("chemical/x-doodie", Format::Write);
  ASSERT_TRUE(format != nullptr);
  EXPECT_EQ(format->identifier(), std::string("writeOnly"));
  delete format;

  format = manager.newFormatFromMimeType("chemical/x-doodie", Format::Read);
  ASSERT_TRUE(format != nullptr);
  EXPECT_EQ(format->identifier(), std::string("readOnly"));
  delete format;
}

TEST(FileFormatManagerTest, unregister)
{
  Format testFormat("testingFormat", FileFormat::All);
  FileFormatManager::registerFormat(testFormat.newInstance());

  FileFormatManager& manager = FileFormatManager::instance();
  FileFormat* format = manager.newFormatFromIdentifier("testingFormat");
  ASSERT_TRUE(format != nullptr);
  EXPECT_EQ(format->identifier(), std::string("testingFormat"));
  delete format;

  EXPECT_TRUE(FileFormatManager::unregisterFormat("testingFormat"));
  format = manager.newFormatFromIdentifier("testingFormat");
  ASSERT_TRUE(format == nullptr);
}
