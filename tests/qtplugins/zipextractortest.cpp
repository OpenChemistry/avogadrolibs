/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Regression tests for the package installer's archive extraction: entries
// must never be written outside the extraction directory (Zip Slip), and the
// package directory name derived from an archive must be a plain child name.

#include <gtest/gtest.h>

#include "zipextractor.h"

#include <archive.h>
#include <archive_entry.h>

#include <QtCore/QDir>
#include <QtCore/QDirIterator>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QTemporaryDir>

#include <string>
#include <vector>

using Avogadro::QtPlugins::ZipExtractor;

namespace {

struct Entry
{
  enum class Kind
  {
    File,
    Symlink,
    Hardlink
  };
  Kind kind;
  std::string path;
  std::string content; // file data, or the link target
};

// Write @p entries to @p archivePath with libarchive (zip, or pax for hard
// links, which zip cannot hold).
bool writeArchive(const QString& archivePath, const std::vector<Entry>& entries,
                  bool tar = false)
{
  struct archive* w = archive_write_new();
  if (tar)
    archive_write_set_format_pax_restricted(w);
  else
    archive_write_set_format_zip(w);
  if (archive_write_open_filename(w, archivePath.toStdString().c_str()) !=
      ARCHIVE_OK) {
    archive_write_free(w);
    return false;
  }
  bool ok = true;
  for (const Entry& e : entries) {
    struct archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, e.path.c_str());
    switch (e.kind) {
      case Entry::Kind::File:
        archive_entry_set_filetype(entry, AE_IFREG);
        archive_entry_set_perm(entry, 0644);
        archive_entry_set_size(entry,
                               static_cast<la_int64_t>(e.content.size()));
        break;
      case Entry::Kind::Symlink:
        archive_entry_set_filetype(entry, AE_IFLNK);
        archive_entry_set_perm(entry, 0755);
        archive_entry_set_symlink(entry, e.content.c_str());
        archive_entry_set_size(entry, 0);
        break;
      case Entry::Kind::Hardlink:
        archive_entry_set_filetype(entry, AE_IFREG);
        archive_entry_set_perm(entry, 0644);
        archive_entry_set_hardlink(entry, e.content.c_str());
        archive_entry_set_size(entry, 0);
        break;
    }
    if (archive_write_header(w, entry) < ARCHIVE_WARN)
      ok = false;
    else if (e.kind == Entry::Kind::File && !e.content.empty())
      archive_write_data(w, e.content.data(), e.content.size());
    archive_entry_free(entry);
  }
  if (archive_write_close(w) != ARCHIVE_OK)
    ok = false;
  archive_write_free(w);
  return ok;
}

class ZipExtractorTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    ASSERT_TRUE(m_root.isValid());
    // Everything outside m_extract (but inside m_root) is "outside".
    m_extract = m_root.path() + QStringLiteral("/plugins");
    m_outside = m_root.path() + QStringLiteral("/outside");
    m_archive = m_root.path() + QStringLiteral("/package.zip");
    ASSERT_TRUE(QDir().mkpath(m_extract));
    ASSERT_TRUE(QDir().mkpath(m_outside));
  }

  QList<QString> extract()
  {
    ZipExtractor unzip;
    return unzip.extract(m_extract.toStdString() + '/',
                         m_archive.toStdString());
  }

  // Every file or link in m_root that is not under m_extract, other than the
  // archive itself and the (empty) outside directory.
  QStringList filesOutside() const
  {
    QStringList found;
    QDirIterator it(m_root.path(),
                    QDir::AllEntries | QDir::Hidden | QDir::System |
                      QDir::NoDotAndDotDot,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
      const QString path = it.next();
      if (path == m_archive || path == m_outside || path == m_extract ||
          path.startsWith(m_extract + '/'))
        continue;
      found << path;
    }
    return found;
  }

  QTemporaryDir m_root;
  QString m_extract;
  QString m_outside;
  QString m_archive;
};

} // namespace

TEST_F(ZipExtractorTest, extractsBenignArchive)
{
  ASSERT_TRUE(writeArchive(
    m_archive, { { Entry::Kind::File, "org-repo-abcdef1/plugin.toml",
                   "name = \"repo\"\n" } }));

  const QList<QString> errors = extract();
  EXPECT_TRUE(errors.isEmpty()) << errors.value(0).toStdString();
  QFile file(m_extract + QStringLiteral("/org-repo-abcdef1/plugin.toml"));
  ASSERT_TRUE(file.open(QIODevice::ReadOnly));
  EXPECT_EQ(file.readAll(), QByteArray("name = \"repo\"\n"));
  EXPECT_TRUE(filesOutside().isEmpty())
    << filesOutside().join(' ').toStdString();
}

TEST_F(ZipExtractorTest, refusesDotDotEntry)
{
  ASSERT_TRUE(writeArchive(
    m_archive,
    { { Entry::Kind::File, "org-repo-abcdef1/plugin.toml", "benign\n" },
      { Entry::Kind::File, "../evil.txt", "evil\n" },
      { Entry::Kind::File, "org-repo-abcdef1/../../evil2.txt", "evil\n" } }));

  EXPECT_FALSE(extract().isEmpty());
  EXPECT_TRUE(filesOutside().isEmpty())
    << filesOutside().join(' ').toStdString();
  // Entries before the malicious one are still extracted.
  EXPECT_TRUE(QFileInfo::exists(
    m_extract + QStringLiteral("/org-repo-abcdef1/plugin.toml")));
}

TEST_F(ZipExtractorTest, refusesAbsoluteEntry)
{
  const std::string absolute =
    (m_outside + QStringLiteral("/abs.txt")).toStdString();
  ASSERT_TRUE(
    writeArchive(m_archive, { { Entry::Kind::File, absolute, "evil\n" } }));

  EXPECT_FALSE(extract().isEmpty());
  EXPECT_TRUE(filesOutside().isEmpty())
    << filesOutside().join(' ').toStdString();
  // Nothing is written at all, not even rebased under the extraction dir.
  EXPECT_TRUE(QDir(m_extract).isEmpty());
}

TEST_F(ZipExtractorTest, refusesWritingThroughSymlink)
{
  ASSERT_TRUE(writeArchive(
    m_archive,
    { { Entry::Kind::Symlink, "org-repo-abcdef1/link",
        m_outside.toStdString() },
      { Entry::Kind::File, "org-repo-abcdef1/link/pwned.txt", "evil\n" } }));

  EXPECT_FALSE(extract().isEmpty());
  EXPECT_FALSE(QFileInfo::exists(m_outside + QStringLiteral("/pwned.txt")));
  EXPECT_TRUE(filesOutside().isEmpty())
    << filesOutside().join(' ').toStdString();
}

TEST_F(ZipExtractorTest, refusesHardlinkOutside)
{
  const QString target = m_outside + QStringLiteral("/victim.txt");
  {
    QFile victim(target);
    ASSERT_TRUE(victim.open(QIODevice::WriteOnly));
    victim.write("original\n");
  }
  // Zip cannot hold hard links, but extract() reads any archive format.
  m_archive = m_root.path() + QStringLiteral("/package.tar");
  for (const std::string& link :
       { target.toStdString(), std::string("../outside/victim.txt") }) {
    QFile::remove(m_archive);
    ASSERT_TRUE(writeArchive(
      m_archive, { { Entry::Kind::Hardlink, "org-repo-abcdef1/link", link } },
      true));

    EXPECT_FALSE(extract().isEmpty()) << link;
    EXPECT_FALSE(
      QFileInfo::exists(m_extract + QStringLiteral("/org-repo-abcdef1/link")))
      << link;
  }
}

TEST(PackageDirectoryNameTest, stripsOrgAndSha)
{
  EXPECT_EQ(ZipExtractor::packageDirectoryName("org-repo-abcdef1/"),
            QStringLiteral("repo"));
  EXPECT_EQ(
    ZipExtractor::packageDirectoryName("ghutchis-avogadro-rdkit-2e9abcd/"),
    QStringLiteral("avogadro-rdkit"));
  EXPECT_EQ(
    ZipExtractor::packageDirectoryName("OpenChemistry-crystals-a7c672d"),
    QStringLiteral("crystals"));
  // Only the top-level directory counts, even if the first entry is a file.
  EXPECT_EQ(ZipExtractor::packageDirectoryName("org-repo-abcdef1/plugin.toml"),
            QStringLiteral("repo"));
}

TEST(PackageDirectoryNameTest, refusesUnsafeNames)
{
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("org-../").isEmpty());
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("org-..").isEmpty());
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("org-./").isEmpty());
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("org-/").isEmpty());
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("../").isEmpty());
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("/etc/passwd").isEmpty());
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("").isEmpty());
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("org-..\\..\\x/").isEmpty());
  EXPECT_TRUE(ZipExtractor::packageDirectoryName("org-C:x/").isEmpty());
}
