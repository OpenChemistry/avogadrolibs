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

#include "copypaste.h"

#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QMimeData>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QApplication>
#include <QtGui/QClipboard>

#include <string>
#include <vector>

namespace Avogadro {
namespace QtPlugins {

using namespace Avogadro::QtGui;

CopyPaste::CopyPaste(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_pastedFormat(NULL),
  m_copyAction(new QAction(tr("Copy"), this)),
  m_cutAction(new QAction(tr("Cut"), this)),
  m_clearAction(new QAction(tr("Clear"), this)),
  m_pasteAction(new QAction(tr("Paste"), this))
{
  m_copyAction->setShortcut(QKeySequence::Copy);
  m_copyAction->setIcon(QIcon::fromTheme("edit-copy"));
  connect(m_copyAction, SIGNAL(triggered()), SLOT(copy()));

  m_cutAction->setShortcut(QKeySequence::Cut);
  m_cutAction->setIcon(QIcon::fromTheme("edit-cut"));
  connect(m_cutAction, SIGNAL(triggered()), SLOT(cut()));

  m_pasteAction->setShortcut(QKeySequence::Paste);
  m_pasteAction->setIcon(QIcon::fromTheme("edit-paste"));
  connect(m_pasteAction, SIGNAL(triggered()), SLOT(paste()));

  m_clearAction->setShortcut(QKeySequence::Delete);
  m_clearAction->setIcon(QIcon::fromTheme("edit-clear"));
  connect(m_clearAction, SIGNAL(triggered()), SLOT(clear()));
}

CopyPaste::~CopyPaste()
{
  delete m_pastedFormat;
}

QList<QAction *> CopyPaste::actions() const
{
  QList<QAction *> result;
  return result << m_copyAction << m_cutAction
                << m_pasteAction << m_clearAction;
}

QStringList CopyPaste::menuPath(QAction *) const
{
  return QStringList() << tr("&Edit");
}

void CopyPaste::setMolecule(QtGui::Molecule *mol)
{
  m_molecule = mol;
}

bool CopyPaste::copy()
{
  if (!m_molecule)
    return false;

  std::string output;

  Io::CjsonFormat cjson;
  if (!cjson.writeString(output, *m_molecule)) {
    QMessageBox::warning(
          qobject_cast<QWidget*>(this->parent()), tr("Error Clipping Molecule"),
          tr("Error generating clipboard data.") + "\n"
          + tr("Output format: %1\n%2", "file format")
          .arg(QString::fromStdString(m_pastedFormat->name()))
          .arg(QString::fromStdString(m_pastedFormat->description()))+ "\n\n"
          + tr("Reader error:\n%1")
          .arg(QString::fromStdString(m_pastedFormat->error())));
    return false;
  }

  QByteArray outputBA(output.c_str(), static_cast<int>(output.length()));

  QMimeData *mimeData(new QMimeData);

  std::vector<std::string> mimeTypes(cjson.mimeTypes());
  for (size_t i = 0; i < mimeTypes.size(); ++i)
    mimeData->setData(QString::fromStdString(mimeTypes[i]), outputBA);

  mimeData->setData("text/plain", outputBA);
  QApplication::clipboard()->setMimeData(mimeData);
  return true;
}

void CopyPaste::cut()
{
  if (!copy())
    return;

  m_molecule->undoMolecule()->clearAtoms();
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Bonds
                          | QtGui::Molecule::Removed );
}

void CopyPaste::clear()
{
  m_molecule->undoMolecule()->clearAtoms();
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Bonds
                          | QtGui::Molecule::Removed );
}

void CopyPaste::paste()
{
  // Delete any old clipboard data.
  if (m_pastedFormat) {
    delete m_pastedFormat;
    m_pastedFormat = NULL;
    m_pastedData.clear();
  }

  if (!m_molecule)
    return; // nothing to do

  const QMimeData *mimeData(QApplication::clipboard()->mimeData());

  if (!mimeData) {
    QMessageBox::warning(qobject_cast<QWidget*>(this->parent()),
                         tr("Error Pasting Molecule"),
                         tr("Cannot paste molecule: Clipboard empty!"));
    return;
  }

  // Try to find a reader that can handle the available mime-types.
  Io::FileFormatManager &mgr = Io::FileFormatManager::instance();
  QStringList mimeTypes(mimeData->formats());
  Io::FileFormat::Operations ops(Io::FileFormat::Read | Io::FileFormat::String);
  foreach (const QString &mimeType, mimeTypes) {
    if ((m_pastedFormat = mgr.newFormatFromMimeType(mimeType.toStdString(),
                                                    ops))) {
      m_pastedData = mimeData->data(mimeType);
      break;
    }
  }

  // No mime-type match, default to cjson.
  if (!m_pastedFormat && mimeData->hasText()) {
    m_pastedFormat = new Io::CjsonFormat;
    m_pastedData = mimeData->text().toLatin1();
  }

  if (!m_pastedFormat)
    return;

  // we have a format, so try to insert the new bits into m_molecule
  Avogadro::QtGui::Molecule mol(m_molecule->parent());
  bool success = m_pastedFormat->readString(
        std::string(m_pastedData.constData(), m_pastedData.size()), mol);

  if (!success) {
    QMessageBox::warning(
          qobject_cast<QWidget*>(this->parent()), tr("Error Pasting Molecule"),
          tr("Error reading clipboard data.") + "\n"
          + tr("Detected format: %1\n%2", "file format description")
          .arg(QString::fromStdString(m_pastedFormat->name()))
          .arg(QString::fromStdString(m_pastedFormat->description()))+ "\n\n"
          + tr("Reader error:\n%1")
          .arg(QString::fromStdString(m_pastedFormat->error())));
  }

  // insert mol into m_molecule
  m_molecule->undoMolecule()->appendMolecule(mol, "Paste Molecule");

  delete m_pastedFormat;
  m_pastedFormat = NULL;
  m_pastedData.clear();
}

} // namespace QtPlugins
} // namespace Avogadro
