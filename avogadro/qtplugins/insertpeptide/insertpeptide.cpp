/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "insertpeptide.h"
#include "ui_insertpeptidedialog.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QDebug>

#include <QtWidgets/QAction>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

  class InsertPeptideDialog : public QDialog, public Ui::InsertPeptideDialog
    {
    public:
    InsertPeptideDialog(QWidget *parent=0) : QDialog(parent) {
        setWindowFlags(Qt::Dialog | Qt::Tool);
        setupUi(this);
      }
    };

InsertPeptide::InsertPeptide(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_dialog(nullptr)
{
  auto* action = new QAction(tr("Peptide…"), this);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);
}

InsertPeptide::~InsertPeptide()
{
}

QList<QAction*> InsertPeptide::actions() const
{
  return m_actions;
}

QStringList InsertPeptide::menuPath(QAction* action) const
{
  return QStringList() << tr("&Build") << tr("&Insert");
}

void InsertPeptide::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void InsertPeptide::showDialog()
{
  if (m_molecule == nullptr)
    return;

  if (m_dialog == nullptr) {
    m_dialog = new InsertPeptideDialog(qobject_cast<QWidget*>(parent()));
  }

  m_dialog->show();
}

void InsertPeptide::performInsert(const QString& sequence)
{
  if (m_molecule == nullptr)
    return;

  // read the file into the new fragment
  Avogadro::QtGui::Molecule newMol(m_molecule->parent());

  //m_molecule->undoMolecule()->appendMolecule(newMol, tr("Insert Peptide"));
  emit requestActiveTool("Manipulator");
}

} // namespace Avogadro
