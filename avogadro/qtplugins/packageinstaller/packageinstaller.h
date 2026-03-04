/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PACKAGEINSTALLER_H
#define AVOGADRO_QTPLUGINS_PACKAGEINSTALLER_H

#include <avogadro/qtgui/extensionplugin.h>

class QAction;

namespace Avogadro {
namespace QtPlugins {

class PackageManagerDialog;

/**
 * @brief Extension plugin that provides the "Manage Packages…" dialog,
 * allowing users to browse, install, update, and remove Avogadro packages.
 */
class PackageInstaller : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit PackageInstaller(QObject* parent = nullptr);
  ~PackageInstaller() override;

  QString name() const override { return tr("Package Installer"); }

  QString description() const override
  {
    return tr("Install, update, and remove Avogadro packages.");
  }

  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;
  void setMolecule(QtGui::Molecule*) override {}

private slots:
  void showDialog();

private:
  QAction* m_action = nullptr;
  PackageManagerDialog* m_dialog = nullptr;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PACKAGEINSTALLER_H
