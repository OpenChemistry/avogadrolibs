/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/qtgui/fileformatdialog.h>

#include <QtCore/QString>

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
