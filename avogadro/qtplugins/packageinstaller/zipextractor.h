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
#include <QtCore/QString>
#include <string>

namespace Avogadro::QtPlugins {

class ZipExtractor : public QObject
{
  Q_OBJECT

public:
  ZipExtractor();
  ~ZipExtractor() override;
  int copyData(struct archive* ar, struct archive* aw);
  QList<QString> extract(const std::string& extractdir,
                         const std::string& absolutepath);
  QList<QString> listFiles(const std::string& absolutepath);

  /**
   * The package name for an archive whose first entry is @p firstEntry:
   * its top-level directory without the GitHub "{org}-" prefix and "-{sha}"
   * suffix. Empty if that is not a usable directory name (e.g., "..").
   */
  static QString packageDirectoryName(const QString& firstEntry);

  /** True if @p name is a single, ordinary path segment (not "." or ".."). */
  static bool isUsableName(const QString& name);
};

} // namespace Avogadro::QtPlugins

#endif
