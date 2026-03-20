/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "packageinstaller.h"
#include "packagemanagerdialog.h"

#include <QAction>

namespace Avogadro::QtPlugins {

PackageInstaller::PackageInstaller(QObject* parent_)
  : ExtensionPlugin(parent_), m_action(new QAction(this))
{
  m_action->setEnabled(true);
  m_action->setText(tr("Manage Plugins…"));
  m_action->setProperty("menu priority", 520);
  connect(m_action, &QAction::triggered, this, &PackageInstaller::showDialog);
}

PackageInstaller::~PackageInstaller()
{
  if (m_dialog)
    m_dialog->deleteLater();
}

QList<QAction*> PackageInstaller::actions() const
{
  return { m_action };
}

QStringList PackageInstaller::menuPath(QAction*) const
{
  return { tr("&Extensions") };
}

void PackageInstaller::showDialog()
{
  if (m_dialog == nullptr)
    m_dialog = new PackageManagerDialog(qobject_cast<QWidget*>(parent()));
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
}

} // namespace Avogadro::QtPlugins
