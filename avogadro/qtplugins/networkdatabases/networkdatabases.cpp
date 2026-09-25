/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "networkdatabases.h"

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QUrl>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QAction>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

#include <cmath>

namespace Avogadro::QtPlugins {

NetworkDatabases::NetworkDatabases(QObject* parent_)
  : ExtensionPlugin(parent_), m_action(new QAction(this)), m_molecule(nullptr),
    m_network(nullptr), m_progressDialog(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText("Download by &Name…");
  m_action->setProperty("menu priority", 190);
  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
}

NetworkDatabases::~NetworkDatabases() {}

QList<QAction*> NetworkDatabases::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList NetworkDatabases::menuPath(QAction*) const
{
  return QStringList() << tr("&File") << tr("&Import");
}

void NetworkDatabases::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

bool NetworkDatabases::readMolecule(QtGui::Molecule& mol)
{
  if (m_moleculeData.isEmpty() || m_moleculeName.isEmpty())
    return false;

  bool readOK = Io::FileFormatManager::instance().readString(
    mol, m_moleculeData.data(), "sdf");
  if (readOK) // worked, so set the filename
    mol.setData("name", m_moleculeName.toStdString());

  return readOK;
}

void NetworkDatabases::registerCommands()
{
  emit registerCommand(
    "fetchByName", tr("Download a structure by name from an online database."));
}

bool NetworkDatabases::handleCommand(const QString& command,
                                     const QVariantMap& options)
{
  if (command.compare("fetchByName", Qt::CaseInsensitive) != 0)
    return false;

  QString structureName = options.value("name").toString().trimmed();
  if (structureName.isEmpty()) {
    emit commandFailed(
      tr("fetchByName requires a non-empty 'name' parameter."));
    return true;
  }

  // Everything below hands the request to the network, so the caller's
  // reply is held until replyFinished() reports back (possibly after a
  // PubChem retry).
  emit commandStarted();
  m_commandPending = true;
  requestStructure(structureName);
  return true;
}

void NetworkDatabases::requestStructure(const QString& structureName)
{
  if (!m_network) {
    m_network = new QNetworkAccessManager(this);
    connect(m_network, SIGNAL(finished(QNetworkReply*)), this,
            SLOT(replyFinished(QNetworkReply*)));
  }

  // Hard coding the NIH resolver download URL - this could be used for other
  // services
  m_network->get(
    QNetworkRequest(QUrl("https://cactus.nci.nih.gov/chemical/structure/" +
                         structureName + "/file?format=sdf&get3d=true")));

  m_moleculeName = structureName;
  m_triedPubChem = false;
}

void NetworkDatabases::showDialog()
{
  // Prompt for a chemical structure name
  bool ok;
  QString structureName = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("Chemical Name"),
    tr("Chemical structure to download."), QLineEdit::Normal, "", &ok);

  if (!ok || structureName.isEmpty())
    return;

  requestStructure(structureName);

  if (!m_progressDialog) {
    m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent()));
  }
  m_progressDialog->setLabelText(tr("Querying for %1").arg(structureName));
  m_progressDialog->setRange(0, 0);
  m_progressDialog->show();
}

void NetworkDatabases::replyFinished(QNetworkReply* reply)
{
  // A fetchByName command never shows the progress dialog, so there may be
  // none to hide -- or the last one shown was for an earlier interactive
  // download and should not be touched here.
  if (!m_commandPending && m_progressDialog)
    m_progressDialog->hide();

  // Read in all the data
  if (!reply->isReadable()) {
    reply->deleteLater();
    QString message = tr("Network timeout or other error.");
    if (m_commandPending) {
      m_commandPending = false;
      m_triedPubChem = false;
      emit commandFailed(message);
    } else {
      QMessageBox::warning(qobject_cast<QWidget*>(parent()),
                           tr("Network Download Failed"), message);
    }
    return;
  }

  QByteArray data = reply->readAll();
  reply->deleteLater();

  bool isError = data.contains("Error report") ||
                 data.contains("Page not found (404)") ||
                 data.contains("PUGREST.NotFound") || data.isEmpty();

  // Cactus sometimes returns 2D coordinates even with get3d=true (e.g.
  // cholesterol). If so, fall back to PubChem's 3D record endpoint.
  if (!m_triedPubChem) {
    if (!isError && sdfHasThreeDCoordinates(data)) {
      m_moleculeData = data;
      QString name = m_moleculeName;
      emit moleculeReady(1);
      reportCommandSuccess(name, QStringLiteral("cactus"));
      return;
    }

    m_triedPubChem = true;
    QByteArray encoded = QUrl::toPercentEncoding(m_moleculeName);
    QUrl pubchemUrl(
      QStringLiteral("https://pubchem.ncbi.nlm.nih.gov/rest/pug/compound/"
                     "name/") +
      QString::fromUtf8(encoded) + QStringLiteral("/SDF?record_type=3d"));
    m_network->get(QNetworkRequest(pubchemUrl));
    if (!m_commandPending) {
      m_progressDialog->setLabelText(
        tr("Querying PubChem for %1").arg(m_moleculeName));
      m_progressDialog->setRange(0, 0);
      m_progressDialog->show();
    }
    return;
  }

  // Second pass: response from PubChem.
  m_triedPubChem = false;
  if (isError || !sdfHasThreeDCoordinates(data)) {
    QString message =
      tr("Specified molecule could not be found: %1").arg(m_moleculeName);
    if (m_commandPending) {
      m_commandPending = false;
      emit commandFailed(message);
    } else {
      QMessageBox::warning(qobject_cast<QWidget*>(parent()),
                           tr("Network Download Failed"), message);
    }
    return;
  }

  m_moleculeData = data;
  QString name = m_moleculeName;
  emit moleculeReady(1);
  reportCommandSuccess(name, QStringLiteral("pubchem"));
}

void NetworkDatabases::reportCommandSuccess(const QString& name,
                                            const QString& source)
{
  if (!m_commandPending)
    return;
  m_commandPending = false;

  // By the time moleculeReady() returns, MainWindow has synchronously called
  // readMolecule() and setMolecule(), and the resulting moleculeChanged()
  // signal has already updated m_molecule via setMolecule() above -- so it
  // is safe to report atomCount/formula from it here.
  QVariantMap result;
  result["name"] = name;
  result["source"] = source;
  if (m_molecule != nullptr) {
    result["atomCount"] = static_cast<int>(m_molecule->atomCount());
    result["formula"] = QString::fromStdString(m_molecule->formula());
  }
  emit commandFinished(tr("Downloaded %1").arg(name), result);
}

bool NetworkDatabases::sdfHasThreeDCoordinates(const QByteArray& data)
{
  // MDL MOL/SDF layout: line 0 title, line 1 metadata, line 2 comment,
  // line 3 counts ("aaabbb..."), then `aaa` atom lines with x/y/z in
  // columns 0-9, 10-19, 20-29.
  QList<QByteArray> lines = data.split('\n');
  if (lines.size() < 5)
    return false;

  bool ok = false;
  int atomCount = lines[3].left(3).trimmed().toInt(&ok);
  if (!ok || atomCount <= 0)
    return false;
  if (lines.size() < 4 + atomCount)
    return false;

  for (int i = 0; i < atomCount; ++i) {
    const QByteArray& atomLine = lines[4 + i];
    if (atomLine.size() < 30)
      continue;
    double z = atomLine.mid(20, 10).trimmed().toDouble(&ok);
    if (ok && std::fabs(z) > 1e-4)
      return true;
  }
  return false;
}
} // namespace Avogadro::QtPlugins
