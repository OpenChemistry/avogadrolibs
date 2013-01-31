/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "openbabel.h"

#include "obprocess.h"

#include <avogadro/io/fileformatmanager.h>

#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDebug>
#include <QtCore/QSettings>

#include <QtGui/QAction>
#include <QtGui/QFileDialog>
#include <QtGui/QMessageBox>
#include <QtGui/QProgressDialog>

#include <string>

namespace Avogadro {
namespace QtPlugins {

OpenBabel::OpenBabel(QObject *p) :
  ExtensionPlugin(p),
  m_process(new OBProcess(this)),
  m_progress(NULL)
{
  QAction *action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Load molecule via OpenBabel..."));
  connect(action, SIGNAL(triggered()), SLOT(onOpenFile()));
  m_actions.push_back(action);

  refreshReadFormats();
}

OpenBabel::~OpenBabel()
{
}

QList<QAction *> OpenBabel::actions() const
{
  return m_actions;
}

QStringList OpenBabel::menuPath(QAction *) const
{
  return QStringList() << tr("&File");
}

void OpenBabel::setMolecule(QtGui::Molecule *)
{
  // no-op
}

bool OpenBabel::readMolecule(QtGui::Molecule &mol)
{
  m_progress->setLabelText(tr("Loading file via OpenBabel:\n\n%1")
                           .arg(tr("Loading molecule from CML...")));

  bool result = false;

  if (m_moleculeQueue.isEmpty()) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Error"),
                          tr("An internal error occurred: "
                             "OpenBabel::readMolecule called, but no obabel "
                             "output is available to parse!"),
                          QMessageBox::Ok);
  }
  else {
    QByteArray output = m_moleculeQueue.takeFirst();
    // Empty output means openbabel crashed, etc.
    if (output.isEmpty()) {
      QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                            tr("Error"),
                            tr("An error occurred while running OpenBabel "
                               "(%1).")
                            .arg(m_process->obabelExecutable()),
                            QMessageBox::Ok);
    }
    else {
      result = Io::FileFormatManager::instance().readString(
            mol, output.constData(), "cml");
      if (!result) {
        qWarning() << "Error parsing OpenBabel CML output:\n" << output;
        QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                              tr("Error"),
                              tr("Error parsing openbabel output."),
                            QMessageBox::Ok);
      }
    }
  }

  m_progress->hide();
  return result;
}

void OpenBabel::onOpenFile()
{
  // If the filter string is not set, there is probably a problem with the
  // obabel executable. Warn the user and return.
  if (m_readFormatsFilterString.isEmpty()) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Error"),
                          tr("An error occurred while retrieving the list of "
                             "supported formats. (using '%1').")
                          .arg(m_process->obabelExecutable()),
                          QMessageBox::Ok);
    return;
  }

  // Fail here if the process is already in use
  if (m_process->inUse()) {
    showProcessInUseError(tr("Cannot open file with OpenBabel."));
    return;
  }

  QSettings settings;
  QString lastFileName =
      settings.value("openbabel/openFile/lastFileName", "").toString();
  QString fileName = QFileDialog::getOpenFileName(
        qobject_cast<QWidget*>(parent()), tr("Open file with OpenBabel"),
        lastFileName,
        m_readFormatsFilterString);

  // User cancel
  if (fileName.isNull())
    return;

  settings.setValue("openbabel/openFile/lastFileName", fileName);

  // Setup progress dialog
  if (!m_progress)
    m_progress = new QProgressDialog(qobject_cast<QWidget*>(parent()));
  m_progress->setLabelText(tr("Loading file via OpenBabel:\n\n%1")
                           .arg(tr("Converting to CML with %1...")
                                .arg(m_process->obabelExecutable())));
  m_progress->setRange(0, 0);
  m_progress->setMinimumDuration(0);
  m_progress->setValue(0);

  // Connect process
  disconnect(m_process);
  m_process->disconnect(this);
  connect(m_progress, SIGNAL(canceled()), m_process, SLOT(abort()));
  connect(m_process, SIGNAL(readFileFinished(QByteArray)),
          SLOT(onOpenFileReadFinished(QByteArray)));

  m_progress->show();
  m_process->readFile(fileName, "cml");
}

void OpenBabel::onOpenFileReadFinished(const QByteArray &output)
{
  m_progress->setLabelText(tr("Loading file via OpenBabel:\n\n%1")
                           .arg(tr("Retrieving CML from %1...")
                                .arg(m_process->obabelExecutable())));

  m_moleculeQueue.append(output);
  emit moleculeReady(1);
}

void OpenBabel::refreshReadFormats()
{
  // No need to check if the member process is in use -- we use a temporary
  // process for the refresh methods.
  OBProcess *proc = new OBProcess(this);

  connect(proc,
          SIGNAL(queryReadFormatsFinished(QMap<QString,QString>)),
          SLOT(handleReadFormatUpdate(QMap<QString,QString>)));

  proc->queryReadFormats();
}

void OpenBabel::handleReadFormatUpdate(const QMap<QString, QString> &fmts)
{
  m_readFormatsFilterString.clear();

  OBProcess *proc = qobject_cast<OBProcess*>(sender());
  if (proc)
    proc->deleteLater();

  m_readFormats = fmts;
  qDebug() << fmts.size() << "formats available through OpenBabel.";

  if (fmts.isEmpty())
    return;

  // This is a list of "extensions" returned by OB that are not actually
  // file extensions, but rather the full filename of the file. These
  // will be used as-is in the filter string, while others will be prepended
  // with "*.".
  QStringList nonExtensions;
  nonExtensions
      << "POSCAR"  // VASP input geometry
      << "CONTCAR" // VASP output geometry
      << "HISTORY" // DL-POLY history file
      << "CONFIG"  // DL-POLY config file
         ;

  // This holds all known extensions:
  QStringList allExtensions;

  foreach (const QString &desc, m_readFormats.uniqueKeys()) {
    QStringList extensions;
    foreach (QString extension, m_readFormats.values(desc)) {
      if (!nonExtensions.contains(extension))
        extension.prepend("*.");
      extensions << extension;
    }
    allExtensions << extensions;
    m_readFormatsFilterString += QString("%1 (%2);;").arg(desc,
                                                          extensions.join(" "));
  }

  m_readFormatsFilterString.prepend(tr("All supported formats (%1);;"
                                       "All files (*);;")
                                    .arg(allExtensions.join(" ")));
}

void OpenBabel::showProcessInUseError(const QString &title) const
{
  QMessageBox::critical(qobject_cast<QWidget*>(parent()), title,
                        tr("Already running OpenBabel. Wait for the other "
                           "operation to complete and try again."),
                        QMessageBox::Ok);
}

}
}
