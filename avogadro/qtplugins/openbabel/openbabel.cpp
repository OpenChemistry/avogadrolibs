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

#include <string>

namespace Avogadro {
namespace QtPlugins {

OpenBabel::OpenBabel(QObject *p) :
  ExtensionPlugin(p),
  m_readFormatsFilterString(tr("All files (*)"))
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
  if (!m_molecules.isEmpty()) {
    QtGui::Molecule *newMol = m_molecules.takeFirst();
    mol = *newMol;
    newMol->deleteLater();
    return true;
  }
  return false;
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
                          .arg(OBProcess().obabelExecutable()),
                          QMessageBox::Ok);
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

  // This will be cleaned up in onOpenFileReadFinished
  OBProcess *proc = new OBProcess(this);

  connect(proc, SIGNAL(readFileFinished(QByteArray)),
          SLOT(onOpenFileReadFinished(QByteArray)));

  proc->readFile(fileName);
}

void OpenBabel::onOpenFileReadFinished(const QByteArray &output)
{
  OBProcess *proc = qobject_cast<OBProcess*>(sender());
  if (proc)
    proc->deleteLater();

  QtGui::Molecule *newMolecule = new QtGui::Molecule(this);

  /// @todo error handling:
  Io::FileFormatManager::instance().readString(*newMolecule,
                                               output.constData(),
                                               "cml");
  m_molecules.push_back(newMolecule);
  emit moleculeReady(1);
}

void OpenBabel::refreshReadFormats()
{
  OBProcess *fetchReadFormats = new OBProcess(this);

  connect(fetchReadFormats,
          SIGNAL(queryReadFormatsFinished(QMap<QString,QString>)),
          SLOT(handleReadFormatUpdate(QMap<QString,QString>)));

  fetchReadFormats->queryReadFormats();
}

void OpenBabel::handleReadFormatUpdate(QMap<QString, QString> fmts)
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

  foreach (const QString &description, m_readFormats.uniqueKeys()) {
    QStringList extensions;
    foreach (QString extension, m_readFormats.values(description)) {
      if (!nonExtensions.contains(extension))
        extension.prepend("*.");
      extensions << extension;
    }
    allExtensions << extensions;
    m_readFormatsFilterString += QString("%1 (%2);;").arg(description,
                                                          extensions.join(" "));
  }
  m_readFormatsFilterString.prepend(tr("All supported formats (%1);;"
                                       "All files (*);;")
                                    .arg(allExtensions.join(" ")));
}

}
}
