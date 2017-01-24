#include "archive.h"
#include "archive_entry.h"
#include <string>
#include <QtCore/QList>

namespace Avogadro {

namespace QtPlugins {

class ZipExtracter {
 public:
  ZipExtracter();
  ~ZipExtracter();
  char *convert(const std::string &);
  int copy_data(struct archive *ar, struct archive *aw);
  QList<QString> extract(const char *filename, std::string extractdir,
                         std::string absolutepath);
};
}
}
