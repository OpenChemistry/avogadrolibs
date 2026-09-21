/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fetchpdb.h"

#include <avogadro/io/compression.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <cstddef>

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
  m_lastReadOk = false;

  if (m_moleculeData.isEmpty() || m_moleculeName.isEmpty())
    return false;

  bool readOK = Io::FileFormatManager::instance().readFile(
    mol, m_tempFileName.toStdString(), "pdb");
  if (readOK) // worked, so set the filename
    mol.setData("name", m_moleculeName.toStdString());
  else if (!m_commandPending)
    // if it didn't read, show a dialog -- unless a command is waiting, in
    // which case replyFinished() reports the failure through commandFailed()
    QMessageBox::warning(
      qobject_cast<QWidget*>(parent()), tr("Fetch PDB"),
      tr("Could not read the PDB molecule: %1").arg(m_moleculeName));

  m_lastReadOk = readOK;
  return readOK;
}

void FetchPDB::registerCommands()
{
  emit registerCommand("fetchPDB",
                       tr("Download a structure from the Protein Data Bank."));
}

bool FetchPDB::handleCommand(const QString& command, const QVariantMap& options)
{
  if (command.compare("fetchPDB", Qt::CaseInsensitive) != 0)
    return false;

  QString pdbCode = options.value("code").toString().trimmed();
  QString error;
  if (!isValidPdbCode(pdbCode, &error)) {
    emit commandFailed(error);
    return true;
  }

  // The request goes to the network, so the caller's reply is held until
  // replyFinished() reports back.
  emit commandStarted();
  m_commandPending = true;
  requestStructure(pdbCode);
  return true;
}

bool FetchPDB::isValidPdbCode(const QString& pdbCode, QString* error)
{
  QString message;

  if (pdbCode.isEmpty())
    message = tr("fetchPDB requires a non-empty 'code' parameter.");
  else if (pdbCode.length() != 4)
    message = tr("The PDB code must be exactly 4 characters long.");
  else if (!pdbCode.at(0).isDigit() || pdbCode.at(0) == QLatin1Char('0'))
    message = tr("The first character of the PDB code must be 1-9.");
  else {
    // The code is pasted into a URL and used as a temporary file name, so
    // only accept the ASCII letters and digits the format actually allows.
    for (const QChar& character : pdbCode) {
      const char latin1 = character.toLatin1();
      const bool alphanumeric = (latin1 >= '0' && latin1 <= '9') ||
                                (latin1 >= 'a' && latin1 <= 'z') ||
                                (latin1 >= 'A' && latin1 <= 'Z');
      if (!alphanumeric) {
        message = tr("The PDB code must contain only letters and digits.");
        break;
      }
    }
  }

  if (message.isEmpty())
    return true;

  if (error != nullptr)
    *error = message;
  return false;
}

void FetchPDB::requestStructure(const QString& pdbCode)
{
  if (!m_network) {
    m_network = new QNetworkAccessManager(this);
    connect(m_network, SIGNAL(finished(QNetworkReply*)), this,
            SLOT(replyFinished(QNetworkReply*)));
  }

  // RCSB serves every entry gzipped as well, at roughly a fifth the size,
  // and Io reads it back transparently. Builds without the compression back
  // ends (USE_LIBARCHIVE=OFF, as the Python wheels are configured) cannot
  // decode it, so ask those for the plain file instead.
  m_downloadSuffix = Io::compressionSupported(Io::Compression::Gzip)
                       ? QStringLiteral(".pdb.gz")
                       : QStringLiteral(".pdb");

  // Hard coding the PDB download URL
  m_network->get(QNetworkRequest(
    QUrl("https://files.rcsb.org/download/" + pdbCode + m_downloadSuffix)));

  m_moleculeName = pdbCode;
}

void FetchPDB::reportFailure(const QString& title, const QString& message)
{
  if (m_commandPending) {
    m_commandPending = false;
    emit commandFailed(message);
  } else {
    QMessageBox::warning(qobject_cast<QWidget*>(parent()), title, message);
  }
}

void FetchPDB::reportCommandSuccess(const QString& pdbCode)
{
  if (!m_commandPending)
    return;
  m_commandPending = false;

  // By the time moleculeReady() returns, MainWindow has synchronously called
  // readMolecule() and setMolecule(), and the resulting moleculeChanged()
  // signal has already updated m_molecule -- so it is safe to report
  // atomCount and friends from it here.
  QVariantMap result;
  result["name"] = pdbCode;
  result["source"] = QStringLiteral("rcsb");
  if (m_molecule != nullptr) {
    result["atomCount"] = static_cast<int>(m_molecule->atomCount());
    result["residueCount"] = static_cast<int>(m_molecule->residueCount());
    result["formula"] = QString::fromStdString(m_molecule->formula());
  }
  emit commandFinished(tr("Downloaded %1").arg(pdbCode), result);
}

void FetchPDB::showDialog()
{
  // Prompt for a chemical structure name
  bool ok;
  QString pdbCode = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("PDB Code"),
    tr("Chemical structure to download."), QLineEdit::Normal, "", &ok);

  pdbCode = pdbCode.trimmed();
  if (!ok || pdbCode.isEmpty())
    return;

  // check if the PDB code matches the expected format
  QString error;
  if (!isValidPdbCode(pdbCode, &error)) {
    QMessageBox::warning(qobject_cast<QWidget*>(parent()),
                         tr("Invalid PDB Code"), error);
    return;
  }

  requestStructure(pdbCode);

  if (!m_progressDialog) {
    m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent()));
  }

  m_progressDialog->setLabelText(tr("Querying for %1").arg(pdbCode));
  m_progressDialog->setRange(0, 0);
  m_progressDialog->show();
}

void FetchPDB::replyFinished(QNetworkReply* reply)
{
  // A fetchPDB command never shows the progress dialog, so there may be none
  // to hide -- and one left over from an earlier interactive download should
  // not be touched here.
  if (!m_commandPending && m_progressDialog)
    m_progressDialog->hide();

  // Read in all the data
  if (!reply->isReadable()) {
    reply->deleteLater();
    reportFailure(tr("Network Download Failed"),
                  tr("Network timeout or other error."));
    return;
  }

  m_moleculeData = reply->readAll();
  reply->deleteLater();

  // RCSB answers an unknown code with an HTML error page, so the payload is
  // what says whether the download worked. Gzip magic is a positive answer:
  // no error page carries it, and the string matches below would be
  // unreliable against compressed bytes, which can hold any sequence at all.
  // Checking the content rather than the requested suffix also keeps this
  // right if the body arrives decoded (a proxy, or a future Content-Encoding
  // from RCSB) -- a plain PDB body simply falls through to the same checks
  // the uncompressed download has always used.
  const bool gzipped =
    Io::detectCompression(m_moleculeData.constData(),
                          static_cast<std::size_t>(m_moleculeData.size())) ==
    Io::Compression::Gzip;

  // Check if the file was successfully downloaded
  if (!gzipped &&
      (m_moleculeData.isEmpty() || m_moleculeData.contains("Not Found") ||
       m_moleculeData.contains("Error report") ||
       m_moleculeData.contains("Page not found (404)"))) {
    reportFailure(
      tr("Network Download Failed"),
      tr("Specified molecule could not be found: %1").arg(m_moleculeName));
    return;
  }

  m_tempFileName =
    QDir::tempPath() + QDir::separator() + m_moleculeName + m_downloadSuffix;
  QFile out(m_tempFileName);
  if (!out.open(QIODevice::WriteOnly)) {
    reportFailure(tr("Error"), tr("Cannot save file %1.").arg(m_tempFileName));
    return;
  }
  out.write(m_moleculeData);
  out.close();

  const QString pdbCode = m_moleculeName;
  emit moleculeReady(1);

  // MainWindow calls readMolecule() synchronously from moleculeReady() but
  // does not pass its result back, so m_lastReadOk carries it. Only the
  // command path needs it: readMolecule() has already warned the user
  // itself when there is no command waiting.
  if (m_commandPending) {
    if (m_lastReadOk)
      reportCommandSuccess(pdbCode);
    else
      reportFailure(tr("Fetch PDB"),
                    tr("Could not read the PDB molecule: %1").arg(pdbCode));
  }
}

} // namespace Avogadro::QtPlugins
