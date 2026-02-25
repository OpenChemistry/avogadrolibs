/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "zipextracter.h"

#include <QtCore/QString>
namespace Avogadro::QtPlugins {

ZipExtracter::ZipExtracter() {}

ZipExtracter::~ZipExtracter() {}

/*************  ✨ Windsurf Command ⭐  *************/
/**
 * Copies data from one archive to another.
 *
 * This is a convenience function to copy data from one archive to another.
 * It will copy the data block by block until it reaches the end of the
 * input archive. If there is an error reading or writing the data, it
 * will return the error code directly.
 */
/*******  e529b3ce-4242-4d08-ab60-874f0aa6fefc  *******/
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
      fprintf(stderr, "%s\n", archive_error_string(aw));
      return (r);
    }
  }
}

char* ZipExtracter::convert(const std::string& str)
{
  char* result = new char[str.length() + 1];
  strncpy(result, str.c_str(), str.length() + 1); // make sure to nul-terminate
  return result;
}

QList<QString> ZipExtracter::listFiles(const std::string absolutepath)
{
  struct archive* a;
  struct archive_entry* entry;
  int r;

  a = archive_read_new();
  archive_read_support_format_zip(a);
  archive_read_support_filter_all(a);

  QList<QString> toReturn;

  if ((r = archive_read_open_filename(a, convert(absolutepath), 512))) {
    toReturn.append(
      QString(tr("ERROR: could not open zip file to list contents.\n(%1)",
                 "%1 is the error message from libarchive"))
        .arg(archive_error_string(a)));
    return toReturn;
  }

  for (;;) {
    r = archive_read_next_header(a, &entry);
    if (r < ARCHIVE_OK)
      break;

    toReturn.append(archive_entry_pathname(entry));
    archive_read_data_skip(a); // Note 2
  }
  r = archive_read_free(a);

  return toReturn;
}

// Extract method from libarchive docs, changed to return QList of errors
QList<QString> ZipExtracter::extract(std::string extractdir,
                                     std::string absolutepath)
{
  struct archive* a;
  struct archive* ext;
  struct archive_entry* entry;
  int flags;
  int r;
  QList<QString> toReturn;
  const std::string& extractdirectory = extractdir;
  std::string newFilename;
  std::string currentFilename;

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
  if ((r = archive_read_open_filename(a, convert(absolutepath), 10240))) {
    toReturn.append(
      QString(tr("ERROR: could not open zip file to extract files.\n(%1)",
                 "%1 is the error message from libarchive"))
        .arg(archive_error_string(a)));
    return toReturn;
  }
  [[maybe_unused]] long itrCount = 0;

  for (;;) {
    r = archive_read_next_header(a, &entry);

    if (r == ARCHIVE_EOF) {
      break;
    }
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(a));
    if (r < ARCHIVE_WARN) {
      toReturn.append(
        QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
          .arg(archive_error_string(a)));
      return toReturn;
    }

    currentFilename = archive_entry_pathname(entry);
    newFilename = extractdirectory;
    newFilename.append(currentFilename);

    archive_entry_set_pathname(entry, convert(newFilename));
    r = archive_write_header(ext, entry);
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(ext));
    else if (archive_entry_size(entry) > 0) {
      r = copyData(a, ext);
      if (r < ARCHIVE_OK)
        fprintf(stderr, "%s\n", archive_error_string(ext));
      if (r < ARCHIVE_WARN) {
        toReturn.append(
          QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
            .arg(archive_error_string(a)));
        return toReturn;
      }
    }
    r = archive_write_finish_entry(ext);
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(ext));
    if (r < ARCHIVE_WARN) {
      toReturn.append(
        QString(tr("Warning: (%1)", "%1 is the message from libarchive"))
          .arg(archive_error_string(a)));
      return toReturn;
    }
  }
  archive_read_close(a);
  archive_read_free(a);
  archive_write_close(ext);
  archive_write_free(ext);
  return toReturn;
}

} // namespace Avogadro::QtPlugins
