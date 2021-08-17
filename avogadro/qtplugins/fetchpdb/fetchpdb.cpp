/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fetchpdb.h"

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtWidgets/QAction>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

namespace Avogadro {
namespace QtPlugins {

FetchPDB::FetchPDB(QObject* parent_)
  : ExtensionPlugin(parent_), m_action(new QAction(this)), m_molecule(nullptr),
    m_network(nullptr), m_progressDialog(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText("Fetch from &PDB...");
  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
}

FetchPDB::~FetchPDB() {}

QList<QAction*> FetchPDB::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList FetchPDB::menuPath(QAction*) const
{
  return QStringList() << tr("&File") << tr("&Import");
}

void FetchPDB::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

bool FetchPDB::readMolecule(QtGui::Molecule& mol)
{
  if (m_moleculeData.isEmpty() || m_moleculeName.isEmpty())
    return false;

  bool readOK = Io::FileFormatManager::instance().readFile(
    mol, m_tempFileName.toStdString(), "mmtf");
  if (readOK) // worked, so set the filename
    mol.setData("name", m_moleculeName.toStdString());

  return readOK;
}

void FetchPDB::showDialog()
{
  if (!m_network) {
    m_network = new QNetworkAccessManager(this);
    connect(m_network, SIGNAL(finished(QNetworkReply*)), this,
            SLOT(replyFinished(QNetworkReply*)));
  }
  if (!m_progressDialog) {
    m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent()));
  }
  // Prompt for a chemical structure name
  bool ok;
  QString pdbCode = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("PDB Code"),
    tr("Chemical structure to download."), QLineEdit::Normal, "", &ok);

  if (!ok || pdbCode.isEmpty())
    return;

  // Hard coding the PDB download URL
  m_network->get(QNetworkRequest(
    //    QUrl("https://files.rcsb.org/download/" + pdbCode + ".pdb")));
    // prefer MMTF - smaller and more efficient (also could use .mmtf.gz)
    QUrl("https://mmtf.rcsb.org/v1.0/full/" + pdbCode)));

  m_moleculeName = pdbCode;
  m_progressDialog->setLabelText(tr("Querying for %1").arg(pdbCode));
  m_progressDialog->setRange(0, 0);
  m_progressDialog->show();
}

void FetchPDB::replyFinished(QNetworkReply* reply)
{
  m_progressDialog->hide();
  // Read in all the data
  if (!reply->isReadable()) {
    QMessageBox::warning(qobject_cast<QWidget*>(parent()),
                         tr("Network Download Failed"),
                         tr("Network timeout or other error."));
    reply->deleteLater();
    return;
  }

  m_moleculeData = reply->readAll();
  m_tempFileName =
    QDir::tempPath() + QDir::separator() + m_moleculeName + ".mmtf";
  QFile out(m_tempFileName);
  out.open(QIODevice::WriteOnly);
  out.write(m_moleculeData);
  out.close();

  // Check if the file was successfully downloaded
  if (m_moleculeData.contains("Error report") ||
      m_moleculeData.contains("Page not found (404)")) {
    QMessageBox::warning(
      qobject_cast<QWidget*>(parent()), tr("Network Download Failed"),
      tr("Specified molecule could not be found: %1").arg(m_moleculeName));
    reply->deleteLater();
    return;
  }
  emit moleculeReady(1);
  reply->deleteLater();
}
} // namespace QtPlugins
} // namespace Avogadro
