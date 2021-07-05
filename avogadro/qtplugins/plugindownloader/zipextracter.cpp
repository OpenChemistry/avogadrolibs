/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2017 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "zipextracter.h"

#include <QtCore/QString>
namespace Avogadro {

namespace QtPlugins {

ZipExtracter::ZipExtracter() {}

ZipExtracter::~ZipExtracter() {}

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
  strcpy(result, str.c_str());
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
    toReturn.append("ERROR - archive_read_open_filename == true");
    toReturn.append(QString::number(r));
    QString errorMsg = archive_error_string(a);
    toReturn.append(errorMsg);
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
  std::string extractdirectory = extractdir;
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
    toReturn.append("ERROR - archive_read_open_filename == true");
    toReturn.append(QString::number(r));
    QString errorMsg = archive_error_string(a);
    toReturn.append(errorMsg);
    return toReturn;
  }
  long itrCount = 0;

  for (;;) {
    r = archive_read_next_header(a, &entry);

    if (r == ARCHIVE_EOF) {
      break;
    }
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(a));
    if (r < ARCHIVE_WARN) {
      toReturn.append("ERROR - r < ARCHIVE_WARN");
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
        toReturn.append("ERROR - r < ARCHIVE_WARN");
        return toReturn;
      }
    }
    r = archive_write_finish_entry(ext);
    if (r < ARCHIVE_OK)
      fprintf(stderr, "%s\n", archive_error_string(ext));
    if (r < ARCHIVE_WARN) {
      toReturn.append("ERROR - r < ARCHIVE_WARN");
      return toReturn;
    }
  }
  archive_read_close(a);
  archive_read_free(a);
  archive_write_close(ext);
  archive_write_free(ext);
  return toReturn;
}

} // namespace QtPlugins
} // namespace Avogadro
