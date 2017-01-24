#include "plugindownloader.h"
#include "downloaderwidget.h"
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtCore/QList>

//#include <libarchive/archive.h>
namespace Avogadro {
namespace QtPlugins {

PluginDownloader::PluginDownloader(QObject *parent_)
    : ExtensionPlugin(parent_),
      m_action(new QAction(this)),
      m_molecule(nullptr),
      m_network(nullptr) {
  m_action->setEnabled(true);
  m_action->setText("Plugin Downloader");
  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
}

PluginDownloader::~PluginDownloader() {}

QList<QAction *> PluginDownloader::actions() const {
  return QList<QAction *>() << m_action;
}

QStringList PluginDownloader::menuPath(QAction *) const {
  return QStringList() << tr("&Extensions");
}

void PluginDownloader::setMolecule(QtGui::Molecule *mol) {}

bool PluginDownloader::readMolecule(QtGui::Molecule &mol) { return true; }

void PluginDownloader::showDialog() {
  QList<QString> repos;
  DownloaderWidget *widget = new DownloaderWidget();
  widget->show();
}

void PluginDownloader::replyFinished(QNetworkReply *reply) {
  // Read in all the data
  if (!reply->isReadable()) {
    QMessageBox::warning(qobject_cast<QWidget *>(parent()),
                         tr("Network Download Failed"),
                         tr("Network timeout or other error."));
    reply->deleteLater();
    return;
  }

  m_moleculeData = reply->readAll();
  // Check if the file was successfully downloaded
  if (m_moleculeData.contains("Error report") ||
      m_moleculeData.contains("Page not found (404)")) {
    QMessageBox::warning(
        qobject_cast<QWidget *>(parent()), tr("Network Download Failed"),
        tr("Specified molecule could not be found: %1").arg(m_moleculeName));
    reply->deleteLater();
    return;
  }
  emit moleculeReady(1);
  reply->deleteLater();
}
}
}
