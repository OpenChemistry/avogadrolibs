/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SCRIPTFILEFORMATS_H
#define AVOGADRO_QTPLUGINS_SCRIPTFILEFORMATS_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief This extension registers FileFormat reader/writers that are
 * implemented as external scripts.
 */
class ScriptFileFormats : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ScriptFileFormats(QObject* parent = nullptr);
  ~ScriptFileFormats() override;

  QString name() const override { return tr("Script File Formats"); }

  QString description() const override
  {
    return tr("Load file reader/writers from external scripts.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

private:
  QList<Io::FileFormat*> m_formats;

  void refreshFileFormats();
  void unregisterFileFormats();
  void registerFileFormats();
};
}
}

#endif // AVOGADRO_QTPLUGINS_QUANTUMOUTPUT_H
