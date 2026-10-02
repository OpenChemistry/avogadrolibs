/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/fileformatdialog.h>

#include <QtCore/QString>

#include <string>
#include <utility>
#include <vector>

using Avogadro::Io::FileFormat;
using Avogadro::QtGui::FileFormatDialog;

namespace {

// findFileFormat() only puts a dialog on screen when several formats claim the
// same extension. Every name used here resolves to exactly one built-in
// format, so these run without any user interaction.
const FileFormat* readerFor(const QString& fileName)
{
  return FileFormatDialog::findFileFormat(nullptr, QString(), fileName,
                                          FileFormat::File | FileFormat::Read);
}

// A do-nothing format with a chosen identifier and name, for exercising
// selectFileFormat() without linking QuantumIO or Open Babel.
class FakeFormat : public FileFormat
{
public:
  FakeFormat(std::string ident, std::string displayName, std::string ext)
    : m_ident(std::move(ident)), m_name(std::move(displayName)),
      m_ext(std::move(ext))
  {
  }
  Operations supportedOperations() const override { return Read | File; }
  FileFormat* newInstance() const override
  {
    return new FakeFormat(m_ident, m_name, m_ext);
  }
  std::string identifier() const override { return m_ident; }
  std::string name() const override { return m_name; }
  std::string description() const override { return std::string(); }
  std::string specificationUrl() const override { return std::string(); }
  std::vector<std::string> fileExtensions() const override { return { m_ext }; }
  std::vector<std::string> mimeTypes() const override { return {}; }
  bool read(std::istream&, Avogadro::Core::Molecule&) override { return false; }
  bool write(std::ostream&, const Avogadro::Core::Molecule&) override
  {
    return false;
  }

private:
  std::string m_ident;
  std::string m_name;
  std::string m_ext;
};

// Registers fake readers claiming a private extension, in the order given, and
// asks findFileFormat() (which calls selectFileFormat()) to pick one. Each
// caller needs its own extension: the manager is a process-wide singleton.
// Returns the identifier of the pick.
std::string pick(const std::string& ext,
                 const std::vector<std::pair<std::string, std::string>>& fmts)
{
  std::vector<std::string> registered;
  for (const auto& f : fmts) {
    auto* ff = new FakeFormat(f.first, f.second, ext);
    if (Avogadro::Io::FileFormatManager::registerFormat(ff))
      registered.push_back(f.first);
    else
      delete ff;
  }
  const FileFormat* chosen = FileFormatDialog::findFileFormat(
    nullptr, QString(), QString::fromStdString("sample." + ext),
    FileFormat::File | FileFormat::Read);
  std::string ident = chosen ? chosen->identifier() : std::string();
  for (const auto& id : registered)
    Avogadro::Io::FileFormatManager::unregisterFormat(id);
  return ident;
}

} // namespace

// A compression suffix does not name a chemical format. Before this was
// handled, opening "1crn.pdb.gz" looked for a reader claiming "gz", found
// none, and told the user no suitable file reader existed.
TEST(FileFormatDialogTest, findsFormatBeneathCompressionSuffix)
{
  const FileFormat* plain = readerFor("1crn.pdb");
  ASSERT_NE(plain, nullptr);
  EXPECT_EQ(plain->identifier(), "Avogadro: PDB");

  for (const char* name : { "1crn.pdb.gz", "1crn.pdb.bz2", "1crn.pdb.xz",
                            "1crn.pdb.zst", "1crn.pdb.zstd", "1CRN.PDB.GZ" }) {
    const FileFormat* format = readerFor(name);
    ASSERT_NE(format, nullptr) << name;
    EXPECT_EQ(format->identifier(), plain->identifier()) << name;
  }
}

// Other formats reach the same path, and a doubled extension must not confuse
// it.
TEST(FileFormatDialogTest, findsOtherFormatsBeneathCompression)
{
  struct Case
  {
    const char* fileName;
    const char* identifier;
  };
  const Case cases[] = {
    { "water.xyz.gz", "Avogadro: XYZ" },
    { "ethane.cml.bz2", "Avogadro: CML" },
    { "caffeine.cjson.zst", "Avogadro: CJSON" },
  };
  for (const Case& c : cases) {
    const FileFormat* format = readerFor(c.fileName);
    ASSERT_NE(format, nullptr) << c.fileName;
    EXPECT_EQ(format->identifier(), c.identifier) << c.fileName;
  }
}

// A file that is only a compression suffix names no chemical format, and a
// plain file must keep working.
TEST(FileFormatDialogTest, bareCompressionSuffixFindsNothing)
{
  EXPECT_EQ(readerFor("archive.gz"), nullptr);
  EXPECT_EQ(readerFor(""), nullptr);
  ASSERT_NE(readerFor("water.xyz"), nullptr);
}

// Note: the compressed-file entry added to the open dialog's filter is not
// covered here. readFileFilter() is private, and widening the class's
// interface just to assert on a filter string is not a good trade.

// .out/.log files go straight to Generic Output, which sniffs the content,
// instead of whichever format registered first.
TEST(FileFormatDialogTest, genericOutputPreferredWhenPresent)
{
  EXPECT_EQ(
    pick("fftesta", { { "User Script: x", "x" },
                      { "OpenBabel: y", "y" },
                      { "Avogadro: Generic Output", "Generic Output" } }),
    "Avogadro: Generic Output");
  EXPECT_EQ(pick("fftestb", { { "Avogadro: Generic Output", "Generic Output" },
                              { "User Script: x", "x" },
                              { "OpenBabel: y", "y" } }),
            "Avogadro: Generic Output");
}

// Look-alikes must not trigger the rule; the old first-match behavior holds.
TEST(FileFormatDialogTest, genericOutputLookalikesIgnored)
{
  EXPECT_EQ(
    pick("fftestc", { { "User Script: cclib", "Generic Output" },
                      { "OpenBabel: out", "Generic Output file format" } }),
    "User Script: cclib");
  EXPECT_EQ(
    pick("fftestd", { { "OpenBabel: out", "Generic Output file format" },
                      { "User Script: cclib", "Generic Output" } }),
    "OpenBabel: out");
  EXPECT_EQ(pick("fftestf", { { "OpenBabel: log", "Generic Output" },
                              { "User Script: cclib", "Generic Output" } }),
            "OpenBabel: log");
}

TEST(FileFormatDialogTest, noGenericOutputKeepsFirstMatch)
{
  EXPECT_EQ(pick("fftestg", { { "OpenBabel: y", "y" },
                              { "Avogadro: Foo", "Foo" },
                              { "User Script: x", "x" } }),
            "OpenBabel: y");
  EXPECT_EQ(
    pick("fftesth", { { "User Script: x", "x" }, { "OpenBabel: y", "y" } }),
    "User Script: x");
}
