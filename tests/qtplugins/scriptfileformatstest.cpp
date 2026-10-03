/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include "fileformatscript.h"

#include <memory>

#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

using Avogadro::QtPlugins::FileFormatScript;

namespace {

QVariantMap baseMetadata()
{
  QVariantMap metadata;
  metadata["identifier"] = "test";
  metadata["format-name"] = "Test";
  QVariantMap support;
  support["read"] = true;
  metadata["support"] = support;
  metadata["output-format"] = "cjson";
  return metadata;
}

} // namespace

TEST(ScriptFileFormatsCommandTest, patternsAbsentByDefault)
{
  FileFormatScript format;
  format.readMetaData(baseMetadata());
  EXPECT_TRUE(format.isValid());
  EXPECT_TRUE(format.contentPatterns().empty());
}

TEST(ScriptFileFormatsCommandTest, patternsListForm)
{
  QVariantMap metadata = baseMetadata();
  metadata["patterns"] = QStringList{ "CP2K| version string", "Other" };
  FileFormatScript format;
  format.readMetaData(metadata);
  const std::vector<std::string> expected = { "CP2K| version string", "Other" };
  EXPECT_EQ(format.contentPatterns(), expected);
}

TEST(ScriptFileFormatsCommandTest, patternsVariantListForm)
{
  // This is the shape the TOML parser produces.
  QVariantMap metadata = baseMetadata();
  metadata["patterns"] = QVariantList{ "A", "B" };
  FileFormatScript format;
  format.readMetaData(metadata);
  const std::vector<std::string> expected = { "A", "B" };
  EXPECT_EQ(format.contentPatterns(), expected);
}

TEST(ScriptFileFormatsCommandTest, patternsStringForm)
{
  QVariantMap metadata = baseMetadata();
  metadata["patterns"] = "Only one";
  FileFormatScript format;
  format.readMetaData(metadata);
  const std::vector<std::string> expected = { "Only one" };
  EXPECT_EQ(format.contentPatterns(), expected);
}

TEST(ScriptFileFormatsCommandTest, patternsDropBlankEntries)
{
  QVariantMap metadata = baseMetadata();
  metadata["patterns"] = QStringList{ "", "  ", "keep", "\t" };
  FileFormatScript format;
  format.readMetaData(metadata);
  const std::vector<std::string> expected = { "keep" };
  EXPECT_EQ(format.contentPatterns(), expected);

  metadata["patterns"] = "   ";
  format.readMetaData(metadata);
  EXPECT_TRUE(format.contentPatterns().empty());
}

TEST(ScriptFileFormatsCommandTest, patternsSurviveNewInstanceAndReset)
{
  QVariantMap metadata = baseMetadata();
  metadata["patterns"] = QStringList{ "banner" };
  FileFormatScript format;
  format.readMetaData(metadata);

  std::unique_ptr<Avogadro::Io::FileFormat> copy(format.newInstance());
  const std::vector<std::string> expected = { "banner" };
  EXPECT_EQ(copy->contentPatterns(), expected);

  // Reading metadata again without the key clears the old value.
  format.readMetaData(baseMetadata());
  EXPECT_TRUE(format.contentPatterns().empty());
}
