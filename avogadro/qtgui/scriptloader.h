/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_SCRIPTLOADER_H
#define AVOGADRO_QTGUI_SCRIPTLOADER_H

#include "avogadroqtguiexport.h"

#include <QtCore/QMap>
#include <QtCore/QObject>
#include <QtCore/QString>

namespace Avogadro {
namespace QtGui {

/**
 * @brief The ScriptLoader class finds and verifies different types of
 * python utility scripts.
 *
 * For example, finding all the "charge" scripts
 * auto chargeScripts = ScriptLoader::scriptList("charge");
 */
class AVOGADROQTGUI_EXPORT ScriptLoader : public QObject
{
  Q_OBJECT
public:
  explicit ScriptLoader(QObject* parent_ = nullptr);

  ~ScriptLoader() override;

  /**
   * @return A map of name -> path for all scripts of the requested @arg type
   */
  static QMultiMap<QString, QString> scriptList(const QString& type);

  static bool queryProgramName(const QString& scriptFilePath,
                               QString& displayName);
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_SCRIPTLOADER_H
