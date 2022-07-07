/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plugindownloader.h"
#include "downloaderwidget.h"
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QList>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtWidgets/QAction>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

//#include <libarchive/archive.h>
namespace Avogadro::QtPlugins {

PluginDownloader::PluginDownloader(QObject* parent_)
  : ExtensionPlugin(parent_), m_action(new QAction(this)), m_molecule(nullptr),
    m_network(nullptr), m_widget(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText(tr("Download Plugins…"));
  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
}

PluginDownloader::~PluginDownloader() = default;

QList<QAction*> PluginDownloader::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList PluginDownloader::menuPath(QAction*) const
{
  return QStringList() << tr("&Extensions");
}

void PluginDownloader::setMolecule(QtGui::Molecule* mol)
{
}

bool PluginDownloader::readMolecule(QtGui::Molecule& mol)
{
  return true;
}

void PluginDownloader::showDialog()
{
  if (m_widget == nullptr) {
    m_widget = new DownloaderWidget(qobject_cast<QWidget*>(parent()));
  }
  m_widget->show();
}

void PluginDownloader::replyFinished(QNetworkReply* reply)
{
}
}
