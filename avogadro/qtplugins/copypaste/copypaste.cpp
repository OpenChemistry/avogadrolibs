/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "copypaste.h"

#include "copyasdialog.h"

#include <avogadro/core/stereo.h>
#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/io/smilesformat.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QMimeData>
#include <QtCore/QSettings>

#include <QAction>
#include <QtGui/QClipboard>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMessageBox>

#include <memory>
#include <string>
#include <vector>

namespace Avogadro::QtPlugins {

using namespace Avogadro::QtGui;

namespace {

// Build a molecule from the selected atoms (and the bonds between them) of
// mol, keeping the per-atom data the clipboard formats can carry.
std::unique_ptr<QtGui::Molecule> selectionCopy(const QtGui::Molecule& mol)
{
  auto copy = std::make_unique<QtGui::Molecule>();

  // MaxIndex marks an atom that was not copied
  std::vector<Index> atomIndex(mol.atomCount(), MaxIndex);
  for (Index i = 0; i < mol.atomCount(); ++i) {
    if (!mol.atomSelected(i))
      continue;
    auto a = copy->addAtom(mol.atomicNumber(i));
    a.setPosition3d(mol.atomPosition3d(i));
    a.setFormalCharge(mol.formalCharge(i));
    a.setIsotope(mol.isotope(i));
    const std::string label = mol.atomLabel(i);
    if (!label.empty())
      copy->setAtomLabel(a.index(), label);

    if (Core::atomStereoUnspecified(mol, i))
      Core::setAtomStereoUnspecified(*copy, a.index());

    // track the index
    atomIndex[i] = a.index();
  }

  for (Index i = 0; i < mol.bondCount(); ++i) {
    Core::Bond bond = mol.bond(i);
    Index start = bond.atom1().index();
    Index end = bond.atom2().index();
    if (atomIndex[start] != MaxIndex && atomIndex[end] != MaxIndex) {
      Core::Bond newBond =
        copy->addBond(atomIndex[start], atomIndex[end], bond.order());
      if (Core::bondStereoUnspecified(mol, i))
        Core::setBondStereoUnspecified(*copy, newBond.index());
    }
  }

  // Residues keep only the selected atoms; PDB-style writers need them.
  for (Index r = 0; r < mol.residueCount(); ++r) {
    const Core::Residue& residue = mol.residue(r);
    std::vector<Core::Atom> kept;
    for (const Core::Atom& atom : residue.residueAtoms())
      if (atom.index() < atomIndex.size() &&
          atomIndex[atom.index()] != MaxIndex)
        kept.push_back(atom);
    if (kept.empty())
      continue;

    std::string name = residue.residueName();
    Index number = residue.residueId();
    char chain = residue.chainId();
    Core::Residue& newResidue = copy->addResidue(name, number, chain);
    newResidue.setHeterogen(residue.isHeterogen());
    newResidue.setSecondaryStructure(residue.secondaryStructure());
    for (const Core::Atom& atom : kept)
      newResidue.addResidueAtom(residue.atomName(atom),
                                copy->atom(atomIndex[atom.index()]));
  }

  return copy;
}

} // namespace

CopyPaste::CopyPaste(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_pastedFormat(nullptr),
    m_molecule(nullptr), m_copyAction(new QAction(tr("Copy"), this)),
    // don't translate SMILES, InChI, or XYZ
    m_copySMILES(new QAction("SMILES", this)),
    m_copyMappedSMILES(new QAction(tr("Atom Mapped SMILES"), this)),
    m_copyInChI(new QAction("InChI", this)),
    m_copyXYZ(new QAction("XYZ", this)),
    m_copyOther(new QAction(tr("Other Format…"), this)),
    m_cutAction(new QAction(tr("Cut"), this)),
    m_clearAction(new QAction(tr("Delete"), this)),
    m_pasteAction(new QAction(tr("&Paste"), this))
{
  m_cutAction->setShortcut(QKeySequence::Cut);
  m_cutAction->setIcon(QIcon::fromTheme("edit-cut"));
  m_cutAction->setProperty("menu priority", 560);
  connect(m_cutAction, SIGNAL(triggered()), SLOT(cut()));

  m_copyAction->setShortcut(QKeySequence::Copy);
  m_copyAction->setIcon(QIcon::fromTheme("edit-copy"));
  m_copyAction->setProperty("menu priority", 550);
  connect(m_copyAction, SIGNAL(triggered()), SLOT(copyCJSON()));

  const QString copyAs = tr("Copy As");

  m_copySMILES->setProperty("menu priority", 540);
  m_copySMILES->setProperty("menu submenu", copyAs);
  connect(m_copySMILES, SIGNAL(triggered()), SLOT(copySMILES()));

  m_copyMappedSMILES->setProperty("menu priority", 535);
  m_copyMappedSMILES->setProperty("menu submenu", copyAs);
  connect(m_copyMappedSMILES, SIGNAL(triggered()), SLOT(copyMappedSMILES()));

  m_copyInChI->setProperty("menu priority", 530);
  m_copyInChI->setProperty("menu submenu", copyAs);
  connect(m_copyInChI, SIGNAL(triggered()), SLOT(copyInChI()));

  m_copyXYZ->setProperty("menu priority", 520);
  m_copyXYZ->setProperty("menu submenu", copyAs);
  connect(m_copyXYZ, SIGNAL(triggered()), SLOT(copyXYZ()));

  // last in the submenu, but above Paste (which is in the Edit menu itself)
  m_copyOther->setProperty("menu priority", 515);
  m_copyOther->setProperty("menu submenu", copyAs);
  connect(m_copyOther, SIGNAL(triggered()), SLOT(copyOther()));

  m_pasteAction->setShortcut(QKeySequence::Paste);
  m_pasteAction->setIcon(QIcon::fromTheme("edit-paste"));
  m_pasteAction->setProperty("menu priority", 510);
  connect(m_pasteAction, SIGNAL(triggered()), SLOT(paste()));

  m_clearAction->setShortcut(QKeySequence::Delete);
  m_clearAction->setIcon(QIcon::fromTheme("edit-delete"));
  m_clearAction->setProperty("menu priority", 500);
  connect(m_clearAction, SIGNAL(triggered()), SLOT(clear()));
}

CopyPaste::~CopyPaste()
{
  delete m_pastedFormat;
}

QList<QAction*> CopyPaste::actions() const
{
  QList<QAction*> result;
  return result << m_copyAction << m_copySMILES << m_copyMappedSMILES
                << m_copyInChI << m_copyXYZ << m_copyOther << m_cutAction
                << m_pasteAction << m_clearAction;
}

QStringList CopyPaste::menuPath(QAction* action) const
{
  // Each action carries its own submenu, in the same spirit as the "menu
  // priority" property set above. Matching on text would not work here: the
  // format names are deliberately untranslated.
  const QVariant submenu = action->property("menu submenu");
  if (submenu.isValid())
    return QStringList() << tr("&Edit") << submenu.toString();

  return QStringList() << tr("&Edit");
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

void CopyPaste::copyMappedSMILES()
{
  // Named directly rather than looked up by extension, because atom mapping is
  // a setting only this format has. Plain "Copy as SMILES" reaches the same
  // writer through the manager, so the two agree on everything else.
  Io::SmilesFormat format;
  format.setAtomMaps(true);

  // The map classes number the atoms of whatever is written, one-based. With
  // a selection active, copy() writes a re-indexed copy of the selected atoms,
  // so the classes follow that fragment rather than the full molecule.
  copy(&format);
}

void CopyPaste::copyInChI()
{
  Io::FileFormatManager& formats = Io::FileFormatManager::instance();
  Io::FileFormat* format(formats.newFormatFromFileExtension("inchi"));

  copy(format);
  delete format;
}

void CopyPaste::copyXYZ()
{
  Io::FileFormatManager& formats = Io::FileFormatManager::instance();
  Io::FileFormat* format(formats.newFormatFromFileExtension("xyz"));

  copy(format);
  delete format;
}

void CopyPaste::copyOther()
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0)
    return;

  const std::vector<CopyAsFormat> formats = CopyAsDialog::availableFormats();
  if (formats.empty())
    return;

  QSettings settings;
  const QString key("copypaste/lastCopyAsFormat");
  CopyAsDialog dialog(formats, settings.value(key).toString(),
                      qobject_cast<QWidget*>(this->parent()));
  if (dialog.exec() != QDialog::Accepted)
    return;

  const int index = dialog.selectedIndex();
  if (index < 0 || index >= static_cast<int>(formats.size()))
    return;

  settings.setValue(key, formats[index].label);
  std::unique_ptr<Io::FileFormat> format =
    CopyAsDialog::createFormat(formats[index]);
  copy(format.get());
}

bool CopyPaste::copy(Io::FileFormat* format)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0 ||
      format == nullptr)
    return false;

  std::string output;
  const QtGui::Molecule* copy = m_molecule;
  std::unique_ptr<QtGui::Molecule> selection; // owns the copy, if any

  if (!m_molecule->isSelectionEmpty()) {
    selection = selectionCopy(*m_molecule);
    copy = selection.get();
  }

  if (!format->writeString(output, *copy)) {
    QMessageBox::warning(
      qobject_cast<QWidget*>(this->parent()), tr("Error Clipping Molecule"),
      tr("Error generating clipboard data.") + "\n" +
        tr("Output format: %1\n%2", "file format")
          .arg(QString::fromStdString(format->name()))
          .arg(QString::fromStdString(format->description())) +
        "\n\n" +
        tr("Writer error:\n%1").arg(QString::fromStdString(format->error())));
    return false;
  }

  QByteArray outputBA(output.c_str(), static_cast<int>(output.length()));

  auto* mimeData(new QMimeData);

  std::vector<std::string> mimeTypes(format->mimeTypes());
  for (auto& mimeType : mimeTypes)
    mimeData->setData(QString::fromStdString(mimeType), outputBA);

  mimeData->setData("text/plain", outputBA);
  QApplication::clipboard()->setMimeData(mimeData);

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
