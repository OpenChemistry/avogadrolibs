/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fetchpdb.h"

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

namespace Avogadro::QtPlugins {

FetchPDB::FetchPDB(QObject* parent_)
  : ExtensionPlugin(parent_), m_action(new QAction(this)), m_molecule(nullptr),
    m_network(nullptr), m_progressDialog(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText("Fetch from &PDB…");
  m_action->setProperty("menu priority", 180);
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
    mol, m_tempFileName.toStdString(), "pdb");
  if (readOK) // worked, so set the filename
    mol.setData("name", m_moleculeName.toStdString());
  else
    // if it didn't read, show a dialog
    QMessageBox::warning(
      qobject_cast<QWidget*>(parent()), tr("Fetch PDB"),
      tr("Could not read the PDB molecule: %1").arg(m_moleculeName));

  return readOK;
}

void FetchPDB::showDialog()
{
  // Prompt for a chemical structure name
  bool ok;
  QString pdbCode = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("PDB Code"),
    tr("Chemical structure to download."), QLineEdit::Normal, "", &ok);

  if (!ok || pdbCode.isEmpty())
    return;

  // check if the PDB code matches the expected format
  if (pdbCode.length() != 4) {
    QMessageBox::warning(qobject_cast<QWidget*>(parent()),
                         tr("Invalid PDB Code"),
                         tr("The PDB code must be exactly 4 characters long."));
    return;
  }

  // first character should be 1-9
  if (!pdbCode.at(0).isDigit() || pdbCode.at(0).toLatin1() == '0') {
    QMessageBox::warning(
      qobject_cast<QWidget*>(parent()), tr("Invalid PDB Code"),
      tr("The first character of the PDB code must be 1-9."));
    return;
  }

  if (!m_network) {
    m_network = new QNetworkAccessManager(this);
    connect(m_network, SIGNAL(finished(QNetworkReply*)), this,
            SLOT(replyFinished(QNetworkReply*)));
  }

  // Hard coding the PDB download URL
  m_network->get(QNetworkRequest(
    QUrl("https://files.rcsb.org/download/" + pdbCode + ".pdb")));

  if (!m_progressDialog) {
    m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent()));
  }

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

  // Check if the file was successfully downloaded
  if (m_moleculeData.contains("Not Found") ||
      m_moleculeData.contains("Error report") ||
      m_moleculeData.contains("Page not found (404)")) {
    QMessageBox::warning(
      qobject_cast<QWidget*>(parent()), tr("Network Download Failed"),
      tr("Specified molecule could not be found: %1").arg(m_moleculeName));
    reply->deleteLater();
    return;
  }

  m_tempFileName =
    QDir::tempPath() + QDir::separator() + m_moleculeName + ".pdb";
  QFile out(m_tempFileName);
  out.open(QIODevice::WriteOnly);
  out.write(m_moleculeData);
  out.close();

  emit moleculeReady(1);
  reply->deleteLater();
}

} // namespace Avogadro::QtPlugins
