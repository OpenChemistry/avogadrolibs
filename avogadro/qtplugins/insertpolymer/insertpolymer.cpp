/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "insertpolymer.h"

#include "insertpolymerdialog.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <QAction>
#include <QMessageBox>
#include <QProgressDialog>

using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;

namespace Avogadro::QtPlugins {

InsertPolymer::InsertPolymer(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_dialog(nullptr)
{
  auto* action = new QAction(tr("Polymer…"), this);
  action->setProperty("menu priority", 780);
  connect(action, &QAction::triggered, this, &InsertPolymer::showDialog);
  m_actions.append(action);
}

InsertPolymer::~InsertPolymer() = default;

QList<QAction*> InsertPolymer::actions() const
{
  return m_actions;
}

QStringList InsertPolymer::menuPath(QAction*) const
{
  return QStringList() << tr("&Build") << tr("&Insert");
}

void InsertPolymer::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void InsertPolymer::showDialog()
{
  if (!m_molecule)
    return;

  QWidget* parentAsWidget = qobject_cast<QWidget*>(parent());

  if (!m_dialog) {
    m_dialog = new InsertPolymerDialog(parentAsWidget);
    connect(m_dialog, &InsertPolymerDialog::buildPolymer, this,
            &InsertPolymer::buildPolymer);
  }
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
}

void InsertPolymer::buildPolymer(const QString& smiles)
{
  if (!m_molecule || smiles.isEmpty())
    return;

  QWidget* parentAsWidget = qobject_cast<QWidget*>(parent());

  // Find the SMILES format reader
  const FileFormat::Operations ops = FileFormat::Read | FileFormat::String;
  auto readers =
    FileFormatManager::instance().fileFormatsFromFileExtension("smi", ops);
  if (readers.empty()) {
    QMessageBox::warning(parentAsWidget, tr("Error"),
                         tr("No SMILES format reader found. "
                            "Is Open Babel available?"));
    return;
  }

  QProgressDialog progDlg(parentAsWidget);
  progDlg.setModal(true);
  progDlg.setWindowTitle(tr("Insert Polymer"));
  progDlg.setLabelText(tr("Generating 3D structure…"));
  progDlg.setRange(0, 0);
  progDlg.setValue(0);
  progDlg.show();

  auto* reader = readers[0]->newInstance();
  QtGui::Molecule newMol;
  bool ok = reader->readString(smiles.toStdString(), newMol);
  delete reader;

  if (!ok || newMol.atomCount() == 0) {
    progDlg.close();
    QMessageBox::warning(
      parentAsWidget, tr("Error"),
      tr("Failed to generate polymer from SMILES:\n%1").arg(smiles));
    return;
  }

  m_molecule->undoMolecule()->appendMolecule(newMol, tr("Insert Polymer"));
  emit requestActiveTool("Manipulator");
}

} // namespace Avogadro::QtPlugins
