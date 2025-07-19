/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plugindownloader.h"
#include "downloaderwidget.h"
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QSettings>
#include <QtCore/QList>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

namespace Avogadro::QtPlugins {

PluginDownloader::PluginDownloader(QObject* parent_)
  : ExtensionPlugin(parent_), m_downloadAction(new QAction(this)),
    m_molecule(nullptr), m_network(nullptr), m_widget(nullptr)
{
  m_downloadAction->setEnabled(true);
  m_downloadAction->setText(tr("Download Plugins…"));
  m_downloadAction->setProperty("menu priority", 520);
  connect(m_downloadAction, SIGNAL(triggered()), SLOT(showDialog()));
}

PluginDownloader::~PluginDownloader() = default;

QList<QAction*> PluginDownloader::actions() const
{
  return QList<QAction*>() << m_downloadAction;
}

QStringList PluginDownloader::menuPath(QAction*) const
{
  return QStringList() << tr("&Extensions");
}

void PluginDownloader::showDialog()
{
  if (m_widget == nullptr) {
    m_widget = new DownloaderWidget(qobject_cast<QWidget*>(parent()));
  }
  m_widget->show();
}

void PluginDownloader::replyFinished(QNetworkReply*) {}

} // namespace Avogadro::QtPlugins
