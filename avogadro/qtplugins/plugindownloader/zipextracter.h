/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ZIPEXTRACTER_H
#define AVOGADRO_QTPLUGINS_ZIPEXTRACTER_H

#include <QtCore/QList>
#include <string>

#include "archive.h"
#include "archive_entry.h"

class QString;

namespace Avogadro {

namespace QtPlugins {

class ZipExtracter
{
public:
  ZipExtracter();
  ~ZipExtracter();
  char* convert(const std::string&);
  int copyData(struct archive* ar, struct archive* aw);
  QList<QString> extract(std::string extractdir, std::string absolutepath);
  QList<QString> listFiles(const std::string absolutepath);
};

} // namespace QtPlugins
} // namespace Avogadro

#endif