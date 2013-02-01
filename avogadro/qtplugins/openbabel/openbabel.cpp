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

#include "obforcefielddialog.h"
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
  m_molecule(NULL),
  m_process(new OBProcess(this)),
  m_progress(NULL)
{
  QAction *action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Load molecule via OpenBabel..."));
  connect(action, SIGNAL(triggered()), SLOT(onOpenFile()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Optimize Geometry via OpenBabel..."));
  connect(action, SIGNAL(triggered()), SLOT(onOptimizeGeometry()));
  m_actions.push_back(action);

  refreshReadFormats();
  refreshForceFields();
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

void OpenBabel::setMolecule(QtGui::Molecule *mol)
{
  if (mol != m_molecule)
    m_molecule = mol;
}

bool OpenBabel::readMolecule(QtGui::Molecule &mol)
{
  m_progress->setLabelText(tr("Loading molecule from CML..."));

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

  m_progress->setWindowTitle(tr("Loading file (OpenBabel, %1)")
                             .arg(fileName));
  m_progress->setLabelText(tr("Converting to CML with %1...")
                           .arg(m_process->obabelExecutable()));
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
  m_progress->setLabelText(tr("Retrieving CML from %1...")
                           .arg(m_process->obabelExecutable()));

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

void OpenBabel::refreshForceFields()
{
  // No need to check if the member process is in use -- we use a temporary
  // process for the refresh methods.
  OBProcess *proc = new OBProcess(this);

  connect(proc,
          SIGNAL(queryForceFieldsFinished(QMap<QString,QString>)),
          SLOT(handleForceFieldsUpdate(QMap<QString,QString>)));

  proc->queryForceFields();
}

void OpenBabel::handleForceFieldsUpdate(const QMap<QString, QString> &ffMap)
{
  OBProcess *proc = qobject_cast<OBProcess*>(sender());
  if (proc)
    proc->deleteLater();

  m_forceFields = ffMap;
  qDebug() << m_forceFields.size()
           << "forcefields available through OpenBabel.";
  qDebug() << m_forceFields;
}

void OpenBabel::onOptimizeGeometry()
{
  if (!m_molecule || m_molecule->atomCount() == 0) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Error"),
                          tr("Molecule invalid. Cannot optimize geometry.")
                          .arg(m_process->obabelExecutable()),
                          QMessageBox::Ok);
    return;
  }

  // If the force field map is empty, there is probably a problem with the
  // obabel executable. Warn the user and return.
  if (m_forceFields.isEmpty()) {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Error"),
                          tr("An error occurred while retrieving the list of "
                             "supported forcefields. (using '%1').")
                          .arg(m_process->obabelExecutable()),
                          QMessageBox::Ok);
    return;
  }

  // Fail here if the process is already in use
  if (m_process->inUse()) {
    showProcessInUseError(tr("Cannot optimize geometry with OpenBabel."));
    return;
  }

  QSettings settings;
  QStringList options =
      settings.value("openbabel/optimizeGeometry/lastOptions").toStringList();
  /// @todo guess best forcefield from molecule.
  options = OBForceFieldDialog::prompt(qobject_cast<QWidget*>(parent()),
                                       m_forceFields.keys(), options);

  // User cancel
  if (options.isEmpty())
    return;

  settings.setValue("openbabel/optimizeGeometry/lastOptions", options);

  // Setup progress dialog
  if (!m_progress)
    m_progress = new QProgressDialog(qobject_cast<QWidget*>(parent()));
  m_progress->setWindowTitle(tr("Optimizing Geometry (OpenBabel)"));
  m_progress->setLabelText(tr("Generating CML..."));
  m_progress->setRange(0, 0);
  m_progress->setMinimumDuration(0);
  m_progress->setValue(0);

  // Connect process
  disconnect(m_process);
  m_process->disconnect(this);
  connect(m_progress, SIGNAL(canceled()), m_process, SLOT(abort()));
  connect(m_process,
          SIGNAL(optimizeGeometryStatusUpdate(int,int,double,double)),
          SLOT(onOptimizeGeometryStatusUpdate(int,int,double,double)));
  connect(m_process, SIGNAL(optimizeGeometryFinished(QByteArray)),
          SLOT(onOptimizeGeometryFinished(QByteArray)));

  m_progress->show();

  // Generate CML
  std::string cml;
  if (!Io::FileFormatManager::instance().writeString(*m_molecule, cml, "cml")) {
    m_progress->hide();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Error"),
                          tr("An internal error occurred while generating a "
                             "CML representation of the current molecule."),
                          QMessageBox::Ok);
    return;
  }

  m_progress->setLabelText(tr("Starting %1...", "arg is an executable file.")
                           .arg(m_process->obabelExecutable()));

  // Run obabel
  m_process->optimizeGeometry(QByteArray(cml.c_str()), options);
}

void OpenBabel::onOptimizeGeometryStatusUpdate(int step, int numSteps,
                                               double energy, double lastEnergy)
{
  QString status;

  if (step == 0) {
    status = tr("Step %1 of %2\nCurrent energy: %3\ndE: %4")
        .arg(step).arg(numSteps)
        .arg(fabs(energy) > 1e-10 ? QString::number(energy, 'g', 5)
                                  : QString("(pending)"))
        .arg("(pending)");
  }
  else {
    double dE = energy - lastEnergy;
    status = tr("Step %1 of %2\nCurrent energy: %3\ndE: %4")
        .arg(step).arg(numSteps)
        .arg(energy, 0, 'g', 5)
        .arg(dE, 0, 'g', 5);
  }

  m_progress->setRange(0, numSteps);
  m_progress->setValue(step);
  m_progress->setLabelText(status);
}

void OpenBabel::onOptimizeGeometryFinished(const QByteArray &output)
{
  m_progress->setLabelText(tr("Updating molecule..."));

  // CML --> molecule
  Core::Molecule mol;
  if (!Io::FileFormatManager::instance().readString(mol, output.constData(),
                                                    "cml")) {
    m_progress->hide();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Error"),
                          tr("Error interpreting obabel CML output."),
                          QMessageBox::Ok);
    return;
  }

  /// @todo cache a pointer to the current molecule in the above slot, and
  /// verify that we're still operating on the same molecule.

  // Check that the atom count hasn't changed:
  if (mol.atomCount() != m_molecule->atomCount()) {
    m_progress->hide();
    QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                          tr("Error"),
                          tr("Number of atoms in obabel output (%1) does not "
                             "match the number of atoms in the original "
                             "molecule (%2).")
                          .arg(mol.atomCount()).arg(m_molecule->atomCount()),
                          QMessageBox::Ok);
    return;
  }

  std::swap(mol.atomPositions3d(), m_molecule->atomPositions3d());
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Modified);
  m_progress->hide();
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
