/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SCRIPTFILEFORMATS_H
#define AVOGADRO_QTPLUGINS_SCRIPTFILEFORMATS_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QVariant>

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

  /**
   * Handle a feature registered by PackageManager.
   */
  void registerFeature(const QString& type, const QString& packageDir,
                       const QString& command, const QString& identifier,
                       const QVariantMap& metadata);

private:
  QList<Io::FileFormat*> m_formats;

  void refreshFileFormats();
  void unregisterFileFormats();
  void registerFileFormats();
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_QUANTUMOUTPUT_H
