/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "zipextracter.h"

#include <QtCore/QDebug>
#include <QtCore/QString>

namespace Avogadro::QtPlugins {

ZipExtracter::ZipExtracter() {}

ZipExtracter::~ZipExtracter() {}

/**
 * Copies data from one archive to another.
 *
 * This is a convenience function to copy data from one archive to another.
 * It will copy the data block by block until it reaches the end of the
 * input archive. If there is an error reading or writing the data, it
 * will return the error code directly.
 */
int ZipExtracter::copyData(struct archive* ar, struct archive* aw)
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

QList<QString> ZipExtracter::listFiles(const std::string& absolutepath)
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
QList<QString> ZipExtracter::extract(const std::string& extractdir,
                                     const std::string& absolutepath)
{
  struct archive* a;
  struct archive* ext;
  struct archive_entry* entry;
  int flags;
  int r;
  QList<QString> toReturn;

  // Ensure extractdir ends with a path separator
  std::string extractPrefix = extractdir;
  if (!extractPrefix.empty() && extractPrefix.back() != '/')
    extractPrefix += '/';

  /* Select which attributes we want to restore. */
  flags = ARCHIVE_EXTRACT_TIME;
  flags |= ARCHIVE_EXTRACT_PERM;
  flags |= ARCHIVE_EXTRACT_ACL;
  flags |= ARCHIVE_EXTRACT_FFLAGS;

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

    std::string newFilename = extractPrefix + archive_entry_pathname(entry);
    archive_entry_set_pathname(entry, newFilename.c_str());
    r = archive_write_header(ext, entry);
    if (r < ARCHIVE_OK)
      qWarning() << archive_error_string(ext);
    else if (archive_entry_size(entry) > 0) {
      r = copyData(a, ext);
      if (r < ARCHIVE_OK)
        qWarning() << archive_error_string(ext);
      if (r < ARCHIVE_WARN) {
        toReturn.append(
          QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
            .arg(archive_error_string(a)));
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
          .arg(archive_error_string(a)));
      cleanup();
      return toReturn;
    }
  }
  cleanup();
  return toReturn;
}

} // namespace Avogadro::QtPlugins
