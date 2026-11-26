/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "zipextractor.h"

#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QString>
#include <QtCore/QStringView>

namespace Avogadro::QtPlugins {

namespace {
// True for a non-empty entry name that is not absolute on any platform:
// no leading separator and no drive letter ("C:").
bool isRelativeEntry(const char* name)
{
  if (name == nullptr || name[0] == '\0' || name[0] == '/' || name[0] == '\\')
    return false;
  const auto c = static_cast<unsigned char>(name[0]);
  const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  return !(letter && name[1] == ':');
}
} // namespace

ZipExtractor::ZipExtractor() {}

ZipExtractor::~ZipExtractor() {}

/**
 * Copies data from one archive to another.
 *
 * This is a convenience function to copy data from one archive to another.
 * It will copy the data block by block until it reaches the end of the
 * input archive. If there is an error reading or writing the data, it
 * will return the error code directly.
 */
int ZipExtractor::copyData(struct archive* ar, struct archive* aw)
{
  int r;
  const void* buff;
  size_t size;
  la_int64_t offset;

  for (;;) {
    r = archive_read_data_block(ar, &buff, &size, &offset);
    if (r == ARCHIVE_EOF)
      return (ARCHIVE_OK);
    if (r < ARCHIVE_OK)
      return (r);
    r = archive_write_data_block(aw, buff, size, offset);
    if (r < ARCHIVE_OK) {
      qWarning() << archive_error_string(aw);
      return (r);
    }
  }
}

QList<QString> ZipExtractor::listFiles(const std::string& absolutepath)
{
  struct archive* a;
  struct archive_entry* entry;
  int r;

  a = archive_read_new();
  archive_read_support_format_zip(a);
  archive_read_support_filter_all(a);

  QList<QString> toReturn;

  if ((r = archive_read_open_filename(a, absolutepath.c_str(), 512))) {
    toReturn.append(
      QString(tr("ERROR: could not open zip file to list contents.\n(%1)",
                 "%1 is the error message from libarchive"))
        .arg(archive_error_string(a)));
    archive_read_free(a);
    return toReturn;
  }

  for (;;) {
    r = archive_read_next_header(a, &entry);
    if (r < ARCHIVE_OK)
      break;

    toReturn.append(archive_entry_pathname(entry));
    archive_read_data_skip(a); // Note 2
  }
  archive_read_free(a);

  return toReturn;
}

// Extract method from libarchive docs, changed to return QList of errors
QList<QString> ZipExtractor::extract(const std::string& extractdir,
                                     const std::string& absolutepath)
{
  struct archive* a;
  struct archive* ext;
  struct archive_entry* entry;
  int flags;
  int r;
  QList<QString> toReturn;

  // Entries are rebased onto the symlink-resolved extraction directory, so
  // that SECURE_SYMLINKS below objects only to links inside it (e.g., not to
  // macOS's /var -> /private/var).
  const QString dir = QString::fromStdString(extractdir);
  QDir().mkpath(dir);
  QString canonicalDir = QFileInfo(dir).canonicalFilePath();
  if (canonicalDir.isEmpty())
    canonicalDir = QDir::cleanPath(QFileInfo(dir).absoluteFilePath());
  std::string extractPrefix = canonicalDir.toStdString();
  if (!extractPrefix.empty() && extractPrefix.back() != '/')
    extractPrefix += '/';

  /* Select which attributes we want to restore. */
  flags = ARCHIVE_EXTRACT_TIME;
  flags |= ARCHIVE_EXTRACT_PERM;
  flags |= ARCHIVE_EXTRACT_ACL;
  flags |= ARCHIVE_EXTRACT_FFLAGS;
  // Refuse '..' and writing through symlinks (Zip Slip). Absolute entry
  // names are refused by isRelativeEntry() instead: NOABSOLUTEPATHS would
  // also refuse our own absolute extraction prefix.
  flags |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;
  flags |= ARCHIVE_EXTRACT_SECURE_SYMLINKS;

  a = archive_read_new();
  archive_read_support_format_all(a);
  archive_read_support_filter_all(a);

  ext = archive_write_disk_new();
  archive_write_disk_set_options(ext, flags);
  archive_write_disk_set_standard_lookup(ext);

  auto cleanup = [&]() {
    archive_read_free(a);
    archive_write_free(ext);
  };

  if ((r = archive_read_open_filename(a, absolutepath.c_str(), 10240))) {
    toReturn.append(
      QString(tr("ERROR: could not open zip file to extract files.\n(%1)",
                 "%1 is the error message from libarchive"))
        .arg(archive_error_string(a)));
    cleanup();
    return toReturn;
  }

  for (;;) {
    r = archive_read_next_header(a, &entry);

    if (r == ARCHIVE_EOF) {
      break;
    }
    if (r < ARCHIVE_OK)
      qWarning() << archive_error_string(a);
    if (r < ARCHIVE_WARN) {
      toReturn.append(
        QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
          .arg(archive_error_string(a)));
      cleanup();
      return toReturn;
    }

    // Rebase the entry (and any hard link target, which would otherwise be
    // resolved against the working directory) under the extraction prefix.
    const char* pathname = archive_entry_pathname(entry);
    const char* hardlink = archive_entry_hardlink(entry);
    if (!isRelativeEntry(pathname) ||
        (hardlink != nullptr && !isRelativeEntry(hardlink))) {
      toReturn.append(
        QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
          .arg(QStringLiteral("Path is absolute or empty: %1")
                 .arg(QString::fromUtf8(pathname ? pathname : ""))));
      cleanup();
      return toReturn;
    }
    std::string newFilename = extractPrefix + pathname;
    archive_entry_set_pathname(entry, newFilename.c_str());
    if (hardlink != nullptr) {
      std::string newHardlink = extractPrefix + hardlink;
      archive_entry_set_hardlink(entry, newHardlink.c_str());
    }
    r = archive_write_header(ext, entry);
    if (r < ARCHIVE_OK)
      qWarning() << archive_error_string(ext);
    if (r < ARCHIVE_WARN) {
      // Includes entries refused by the SECURE_* flags.
      toReturn.append(
        QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
          .arg(archive_error_string(ext)));
      cleanup();
      return toReturn;
    }
    // ARCHIVE_WARN still wrote the header, so the data must follow.
    if (archive_entry_size(entry) > 0) {
      r = copyData(a, ext);
      if (r < ARCHIVE_OK)
        qWarning() << archive_error_string(ext);
      if (r < ARCHIVE_WARN) {
        // copyData() fails on either the read or the write side.
        const char* error = archive_error_string(ext);
        if (error == nullptr)
          error = archive_error_string(a);
        toReturn.append(
          QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
            .arg(error));
        cleanup();
        return toReturn;
      }
    }
    r = archive_write_finish_entry(ext);
    if (r < ARCHIVE_OK)
      qWarning() << archive_error_string(ext);
    if (r < ARCHIVE_WARN) {
      toReturn.append(
        QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
          .arg(archive_error_string(ext)));
      cleanup();
      return toReturn;
    }
  }
  cleanup();
  return toReturn;
}

QString ZipExtractor::packageDirectoryName(const QString& firstEntry)
{
  // Only the archive's top-level directory names the package.
  const QString topLevel = firstEntry.section('/', 0, 0);
  if (!isUsableName(topLevel))
    return QString();

  // Derive the name from GitHub archive directory names like:
  //   "OpenChemistry-crystals-a7c672d" -> "crystals"
  //   "ghutchis-avogadro-rdkit-2e9abcd" -> "avogadro-rdkit"
  // Pattern is always {org}-{repo}-{sha}, strip org prefix and SHA suffix.
  QString component = topLevel;
  // Strip trailing SHA: last segment if it looks like a hex hash (7+ chars)
  int lastDash = component.lastIndexOf('-');
  if (lastDash != -1) {
    QStringView tail = QStringView(component).mid(lastDash + 1);
    bool isHex = tail.size() >= 7;
    for (qsizetype i = 0; isHex && i < tail.size(); ++i) {
      QChar c = tail[i];
      isHex = c.isDigit() || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    if (isHex)
      component = component.left(lastDash);
  }
  // Strip leading org/owner prefix (everything before the first dash)
  int firstDash = component.indexOf('-');
  if (firstDash != -1)
    component = component.mid(firstDash + 1);

  if (!isUsableName(component))
    return QString();
  return component;
}

bool ZipExtractor::isUsableName(const QString& name)
{
  return !name.isEmpty() && name != QLatin1String(".") &&
         name != QLatin1String("..") && !name.contains('/') &&
         !name.contains('\\') && !name.contains(':');
}

} // namespace Avogadro::QtPlugins
