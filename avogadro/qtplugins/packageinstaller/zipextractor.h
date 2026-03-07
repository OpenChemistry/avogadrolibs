/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ZIPEXTRACTOR_H
#define AVOGADRO_QTPLUGINS_ZIPEXTRACTOR_H

#include <archive.h>
#include <archive_entry.h>
#include <QtCore/QObject>
#include <QtCore/QList>
#include <string>

namespace Avogadro {

namespace QtPlugins {

class ZipExtractor : public QObject
{
  Q_OBJECT

public:
  ZipExtractor();
  ~ZipExtractor();
  int copyData(struct archive* ar, struct archive* aw);
  QList<QString> extract(const std::string& extractdir,
                         const std::string& absolutepath);
  QList<QString> listFiles(const std::string& absolutepath);
};

} // namespace QtPlugins
} // namespace Avogadro

#endif
