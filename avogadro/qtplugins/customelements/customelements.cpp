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

#include "customelements.h"

#include <avogadro/qtgui/backgroundfileformat.h>
#include <avogadro/qtgui/customelementdialog.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QSettings>
#include <QtCore/QThread>
#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

using Avogadro::QtGui::BackgroundFileFormat;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

CustomElements::CustomElements(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_reassignUsingTool(nullptr), m_reassignFromFile(nullptr),
    m_fileReadThread(nullptr), m_threadedReader(nullptr),
    m_fileReadMolecule(nullptr), m_progressDialog(nullptr)
{
  m_reassignUsingTool = new QAction(tr("Reassign &Custom Elements..."), this);
  m_reassignFromFile =
    new QAction(tr("&Import Coordinate/Topology File..."), this);
  connect(m_reassignUsingTool, SIGNAL(triggered()), SLOT(reassign()));
  connect(m_reassignFromFile, SIGNAL(triggered()), SLOT(importMapFile()));

  updateReassignAction();
}

CustomElements::~CustomElements() {}

QString CustomElements::description() const
{
  return tr("Manipulate custom element types in the current molecule.");
}

QList<QAction*> CustomElements::actions() const
{
  return QList<QAction*>() << m_reassignUsingTool << m_reassignFromFile;
}

QStringList CustomElements::menuPath(QAction*) const
{
  return QStringList() << tr("&Build");
}

void CustomElements::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule != mol) {
    if (m_molecule)
      m_molecule->disconnect(this);

    m_molecule = mol;

    if (m_molecule)
      connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

    updateReassignAction();
  }
}

void CustomElements::moleculeChanged(unsigned int c)
{
  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);
  if (changes & Molecule::Atoms &&
      (changes & (Molecule::Added | Molecule::Modified))) {
    updateReassignAction();
  }
}

void CustomElements::reassign()
{
  if (m_molecule) {
    QtGui::CustomElementDialog::resolve(qobject_cast<QWidget*>(parent()),
                                        *m_molecule);
  }
}

bool CustomElements::openFile(const QString& fileName, Io::FileFormat* reader)
{
  if (fileName.isEmpty() || reader == nullptr) {
    delete reader;
    return false;
  }

  QString ident = QString::fromStdString(reader->identifier());

  // Prepare the background thread to read in the selected file.
  if (!m_fileReadThread)
    m_fileReadThread = new QThread(qobject_cast<QWidget*>(parent()));
  if (m_threadedReader)
    m_threadedReader->deleteLater();
  m_threadedReader = new BackgroundFileFormat(reader);
  if (m_fileReadMolecule)
    m_fileReadMolecule->deleteLater();
  m_fileReadMolecule = new Molecule(qobject_cast<QWidget*>(parent()));
  m_fileReadMolecule->setData("fileName", fileName.toLocal8Bit().data());
  m_threadedReader->moveToThread(m_fileReadThread);
  m_threadedReader->setMolecule(m_fileReadMolecule);
  m_threadedReader->setFileName(fileName);

  // Setup a progress dialog in case file loading is slow
  m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent()));
  m_progressDialog->setRange(0, 0);
  m_progressDialog->setValue(0);
  m_progressDialog->setMinimumDuration(750);
  m_progressDialog->setWindowTitle(tr("Reading File"));
  m_progressDialog->setLabelText(
    tr("Opening file '%1'\nwith '%2'").arg(fileName).arg(ident));
  m_progressDialog->setCancelButton(nullptr);
  connect(m_progressDialog, SIGNAL(canceled()), m_fileReadThread, SLOT(quit()));
  connect(m_fileReadThread, SIGNAL(started()), m_threadedReader, SLOT(read()));
  connect(m_threadedReader, SIGNAL(finished()), m_fileReadThread, SLOT(quit()));
  connect(m_threadedReader, SIGNAL(finished()),
          SLOT(backgroundReaderFinished()));

  // Start the file operation
  m_fileReadThread->start();
  m_progressDialog->show();

  return true;
}

void CustomElements::backgroundReaderFinished()
{
  QString fileName = m_threadedReader->fileName();
  if (m_progressDialog->wasCanceled()) {
    delete m_fileReadMolecule;
  } else if (m_threadedReader->success()) {
    if (!fileName.isEmpty()) {
      m_fileReadMolecule->setData("fileName", fileName.toLocal8Bit().data());
    } else {
      m_fileReadMolecule->setData("fileName", Core::Variant());
    }
    setMapFromMolecule(m_fileReadMolecule);
  } else {
    QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("File error"),
                          tr("Error while reading file '%1':\n%2")
                            .arg(fileName)
                            .arg(m_threadedReader->error()));
    delete m_fileReadMolecule;
  }
  m_fileReadThread->deleteLater();
  m_fileReadThread = nullptr;
  m_threadedReader->deleteLater();
  m_threadedReader = nullptr;
  m_fileReadMolecule = nullptr;
  m_progressDialog->hide();
  m_progressDialog->deleteLater();
  m_progressDialog = nullptr;
}

void CustomElements::setMapFromMolecule(QtGui::Molecule* mol)
{
  if (mol->atomCount() != m_molecule->atomCount()) {
    QMessageBox::critical(
      qobject_cast<QWidget*>(parent()), tr("Error"),
      tr("Atom count mismatch.\nExpected %1 atoms, found %2.")
        .arg(m_molecule->atomCount())
        .arg(mol->atomCount()));
  } else {
    size_t n = m_molecule->atomCount(), i;
    for (i = 0; i < n; ++i) {
      m_molecule->atom(i).setAtomicNumber(mol->atom(i).atomicNumber());
    }
    n = m_molecule->bondCount();
    for (i = 0; i < n; ++i) {
      m_molecule->addBond(mol->bond(i).atom1(), mol->bond(i).atom2(),
                          mol->bond(i).order());
    }
    m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
  }
}

void CustomElements::importMapFile()
{
  QSettings settings;
  QString dir = settings.value("MainWindow/lastOpenDir").toString();

  QtGui::FileFormatDialog::FormatFilePair reply =
    QtGui::FileFormatDialog::fileToRead(qobject_cast<QWidget*>(parent()),
                                        tr("Open Molecule"), dir);

  if (reply.first == NULL) // user cancel
    return;

  dir = QFileInfo(reply.second).absoluteDir().absolutePath();
  settings.setValue("MainWindow/lastOpenDir", dir);

  if (!openFile(reply.second, reply.first->newInstance())) {
    QMessageBox::information(
      qobject_cast<QWidget*>(parent()), tr("Cannot open file"),
      tr("Can't open supplied file %1").arg(reply.second));
  }
}

void CustomElements::updateReassignAction()
{
  m_reassignUsingTool->setEnabled(m_molecule &&
                                  m_molecule->hasCustomElements());
  m_reassignFromFile->setEnabled(m_molecule && m_molecule->atomCount());
}

} // namespace QtPlugins
} // namespace Avogadro
