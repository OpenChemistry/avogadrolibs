/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "copypaste.h"

#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QMimeData>

#include <QAction>
#include <QtGui/QClipboard>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMessageBox>

#include <string>
#include <vector>

namespace Avogadro::QtPlugins {

using namespace Avogadro::QtGui;

CopyPaste::CopyPaste(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_pastedFormat(nullptr),
    m_copyAction(new QAction(tr("Copy"), this)),
    m_copySMILES(new QAction(tr("SMILES"), this)),
    m_copyInChI(new QAction(tr("InChI"), this)),
    m_cutAction(new QAction(tr("Cut"), this)),
    m_clearAction(new QAction(tr("Clear"), this)),
    m_pasteAction(new QAction(tr("&Paste"), this))
{
  m_cutAction->setShortcut(QKeySequence::Cut);
  m_cutAction->setIcon(QIcon::fromTheme("edit-cut"));
  m_cutAction->setProperty("menu priority", 560);
  connect(m_cutAction, &QAction::triggered, this, &CopyPaste::cut);

  m_copyAction->setShortcut(QKeySequence::Copy);
  m_copyAction->setIcon(QIcon::fromTheme("edit-copy"));
  m_copyAction->setProperty("menu priority", 550);
  connect(m_copyAction, &QAction::triggered, this, &CopyPaste::copyCJSON);

  m_copySMILES->setProperty("menu priority", 540);
  connect(m_copySMILES, &QAction::triggered, this, &CopyPaste::copySMILES);

  m_copyInChI->setProperty("menu priority", 530);
  connect(m_copyInChI, &QAction::triggered, this, &CopyPaste::copyInChI);

  m_pasteAction->setShortcut(QKeySequence::Paste);
  m_pasteAction->setIcon(QIcon::fromTheme("edit-paste"));
  m_pasteAction->setProperty("menu priority", 510);
  connect(m_pasteAction, &QAction::triggered, this, &CopyPaste::paste);

  m_clearAction->setShortcut(QKeySequence::Delete);
  m_clearAction->setIcon(QIcon::fromTheme("edit-clear"));
  m_clearAction->setProperty("menu priority", 500);
  connect(m_clearAction, &QAction::triggered, this, &CopyPaste::clear);
}

CopyPaste::~CopyPaste()
{
  delete m_pastedFormat;
}

QList<QAction*> CopyPaste::actions() const
{
  QList<QAction*> result;
  return result << m_copyAction << m_copySMILES << m_copyInChI << m_cutAction
                << m_pasteAction << m_clearAction;
}

QStringList CopyPaste::menuPath(QAction* action) const
{
  if (action->text() != tr("SMILES") && action->text() != tr("InChI"))
    return QStringList() << tr("&Edit");
  else
    return QStringList() << tr("&Edit") << tr("Copy As");
}

void CopyPaste::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

bool CopyPaste::copyCJSON()
{
  Io::CjsonFormat cjson;
  return copy(&cjson);
}

void CopyPaste::copySMILES()
{
  Io::FileFormatManager& formats = Io::FileFormatManager::instance();
  Io::FileFormat* format(formats.newFormatFromFileExtension("smi"));

  copy(format);
  delete format;
}

void CopyPaste::copyInChI()
{
  Io::FileFormatManager& formats = Io::FileFormatManager::instance();
  Io::FileFormat* format(formats.newFormatFromFileExtension("inchi"));

  copy(format);
  delete format;
}

bool CopyPaste::copy(Io::FileFormat* format)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0 ||
      format == nullptr)
    return false;

  std::string output;
  QtGui::Molecule* copy = m_molecule;

  if (!m_molecule->isSelectionEmpty()) {
    // create a copy of the selected atoms only
    copy = new QtGui::Molecule(m_molecule->parent());

    // go through the selected atoms and add them
    // make sure to track the new index
    std::vector<Index> atomIndex(m_molecule->atomCount(), 0);
    for (Index i = 0; i < m_molecule->atomCount(); ++i)
      if (m_molecule->atomSelected(i)) {
        auto a = copy->addAtom(m_molecule->atomicNumber(i));
        a.setPosition3d(m_molecule->atomPosition3d(i));

        // track the index
        atomIndex[i] = a.index();
      }

    for (Index i = 0; i < m_molecule->bondCount(); ++i) {
      Core::Bond bond = m_molecule->bond(i);
      Index start = bond.atom1().index();
      Index end = bond.atom2().index();
      if (m_molecule->atomSelected(start) && m_molecule->atomSelected(start)) {
        copy->addBond(atomIndex[start], atomIndex[end], bond.order());
      }
    }
  }

  if (!format->writeString(output, *copy)) {
    QMessageBox::warning(
      qobject_cast<QWidget*>(this->parent()), tr("Error Clipping Molecule"),
      tr("Error generating clipboard data.") + "\n" +
        tr("Output format: %1\n%2", "file format")
          .arg(QString::fromStdString(m_pastedFormat->name()))
          .arg(QString::fromStdString(m_pastedFormat->description())) +
        "\n\n" +
        tr("Reader error:\n%1")
          .arg(QString::fromStdString(m_pastedFormat->error())));
    return false;
  }

  QByteArray outputBA(output.c_str(), static_cast<int>(output.length()));

  auto* mimeData(new QMimeData);

  std::vector<std::string> mimeTypes(format->mimeTypes());
  for (auto& mimeType : mimeTypes)
    mimeData->setData(QString::fromStdString(mimeType), outputBA);

  mimeData->setData("text/plain", outputBA);
  QApplication::clipboard()->setMimeData(mimeData);

  if (!m_molecule->isSelectionEmpty())
    copy->deleteLater(); // don't leak our copy

  return true;
}

void CopyPaste::cut()
{
  if (!copyCJSON())
    return;

  if (m_molecule->isSelectionEmpty())
    m_molecule->undoMolecule()->clearAtoms();
  else {
    // Remove atoms from the largest to the smallest index
    // (that way, the index doesn't change)
    for (Index i = m_molecule->atomCount(); i > 0; --i)
      // atoms go from 0 to atomCount()-1
      if (m_molecule->atomSelected(i - 1))
        m_molecule->undoMolecule()->removeAtom(i - 1);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Bonds |
                          QtGui::Molecule::Removed);
}

void CopyPaste::clear()
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0)
    return;

  if (m_molecule->isSelectionEmpty())
    m_molecule->undoMolecule()->clearAtoms();
  else {
    // Remove atoms from the largest to the smallest index
    // (that way, the index doesn't change)
    for (Index i = m_molecule->atomCount(); i > 0; --i) {
      // atoms go from 0 to atomCount()-1
      if (m_molecule->atomSelected(i - 1))
        m_molecule->undoMolecule()->removeAtom(i - 1);
    }
  }
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Bonds |
                          QtGui::Molecule::Removed);
}

void CopyPaste::paste()
{
  // Delete any old clipboard data.
  if (m_pastedFormat) {
    delete m_pastedFormat;
    m_pastedFormat = nullptr;
    m_pastedData.clear();
  }

  if (!m_molecule)
    return; // nothing to do

  // make sure we clear the current selection
  for (Index i = 0; i < m_molecule->atomCount(); ++i)
    m_molecule->setAtomSelected(i, false);

  const QMimeData* mimeData(QApplication::clipboard()->mimeData());

  if (!mimeData) {
    QMessageBox::warning(qobject_cast<QWidget*>(this->parent()),
                         tr("Error Pasting Molecule"),
                         tr("Cannot paste molecule: Clipboard empty!"));
    return;
  }

  // Try to find a reader that can handle the available mime-types.
  Io::FileFormatManager& mgr = Io::FileFormatManager::instance();
  QStringList mimeTypes(mimeData->formats());
  Io::FileFormat::Operations ops(Io::FileFormat::Read | Io::FileFormat::String);
  foreach (const QString& mimeType, mimeTypes) {
    if ((m_pastedFormat =
           mgr.newFormatFromMimeType(mimeType.toStdString(), ops))) {
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
      tr("Error reading clipboard data.") + "\n" +
        tr("Detected format: %1\n%2", "file format description")
          .arg(QString::fromStdString(m_pastedFormat->name()))
          .arg(QString::fromStdString(m_pastedFormat->description())) +
        "\n\n" +
        tr("Reader error:\n%1")
          .arg(QString::fromStdString(m_pastedFormat->error())));
  }

  // insert mol into m_molecule
  m_molecule->undoMolecule()->appendMolecule(mol, "Paste Molecule");
  emit requestActiveTool("Manipulator");

  delete m_pastedFormat;
  m_pastedFormat = nullptr;
  m_pastedData.clear();
}

} // namespace Avogadro::QtPlugins
