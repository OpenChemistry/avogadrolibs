/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "constraintsdialog.h"
#include "ui_constraintsdialog.h"

#include <QDebug>
#include <QtCore/QSortFilterProxyModel>

#include <avogadro/qtgui/rwmolecule.h>

using Avogadro::Core::Constraint;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

ConstraintsDialog::ConstraintsDialog(QWidget* parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), ui(new Ui::ConstraintsDialog),
    m_model(new ConstraintsModel)
{
  ui->setupUi(this);

  connect(ui->comboType, SIGNAL(currentIndexChanged(int)), this,
          SLOT(changeType(int)));
  connect(ui->okButton, SIGNAL(clicked()), this, SLOT(acceptConstraints()));
  connect(ui->addConstraint, SIGNAL(clicked()), this, SLOT(addConstraint()));
  connect(ui->deleteConstraint, SIGNAL(clicked()), this,
          SLOT(deleteConstraint()));
  connect(ui->deleteAllConstraints, SIGNAL(clicked()), this,
          SLOT(deleteAllConstraints()));

  changeType(0);

  // TODO use sort model
  auto* proxyModel = new QSortFilterProxyModel(this);
  proxyModel->setSourceModel(m_model);
  proxyModel->setDynamicSortFilter(true);
  proxyModel->setSortLocaleAware(true);
  // this role will received direct floating-point numbers from the model
  proxyModel->setSortRole(Qt::UserRole);

  auto* view = ui->constraintsTableView;
  view->setModel(proxyModel);
  view->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  view->resizeColumnsToContents();
  view->setSelectionBehavior(QAbstractItemView::SelectRows);
  view->setAlternatingRowColors(true);
  // TODO: Allow sorting the table
  // requires remapping

  connect(view->selectionModel(),
          SIGNAL(currentChanged(const QModelIndex&, const QModelIndex&)), this,
          SLOT(highlightSelected(const QModelIndex&, const QModelIndex&)));
}

ConstraintsDialog::~ConstraintsDialog()
{
  delete ui;
  m_model->deleteLater();
}

void ConstraintsDialog::setMolecule(QtGui::Molecule* molecule)
{
  m_molecule = molecule;
  m_model->setConstraints(molecule->constraints());

  connect(m_molecule, SIGNAL(changed(unsigned int)), this,
          SLOT(updateConstraints()));
}

void ConstraintsDialog::highlightSelected(const QModelIndex& newIndex,
                                          const QModelIndex& oldIndex)
{
  // get the selected row in the table
  auto row = ui->constraintsTableView->currentIndex().row();
  if (row < 0 || row >= m_model->rowCount())
    return;
  // get the constraint
  auto constraint = m_model->constraint(row);
  if (constraint.type() == Constraint::None)
    return;

  // unselect everything else in the molecule
  for (Index i = 0; i < m_molecule->atomCount(); ++i)
    m_molecule->undoMolecule()->setAtomSelected(i, false);

  // select the atoms in the constraint
  m_molecule->undoMolecule()->setAtomSelected(constraint.aIndex(), true);
  m_molecule->undoMolecule()->setAtomSelected(constraint.bIndex(), true);
  if (constraint.cIndex() != MaxIndex)
    m_molecule->undoMolecule()->setAtomSelected(constraint.cIndex(), true);
  if (constraint.dIndex() != MaxIndex)
    m_molecule->undoMolecule()->setAtomSelected(constraint.dIndex(), true);

  m_molecule->emitChanged(Molecule::Selection);
}

void ConstraintsDialog::updateConstraints()
{
  if (m_molecule == nullptr || m_model == nullptr)
    return;

  m_model->setConstraints(m_molecule->constraints());
  ui->constraintsTableView->resizeColumnsToContents();

  // update the maximum atoms on the spin boxes
  Index maxAtom = m_molecule->atomCount() - 1;
  ui->editA->setMaximum(maxAtom);
  ui->editB->setMaximum(maxAtom);
  ui->editC->setMaximum(maxAtom);
  ui->editD->setMaximum(maxAtom);
}

void ConstraintsDialog::changeType(int newType)
{
  // disable B-C-D and enable what we need
  ui->editB->setEnabled(false);
  ui->editC->setEnabled(false);
  ui->editD->setEnabled(false);

  ui->editB->setMinimum(0);
  ui->editC->setMinimum(0);
  ui->editD->setMinimum(0);

  switch (newType) {
    case 2: // torsion
      ui->editD->setEnabled(true);
      ui->editD->setMinimum(1);
    case 1: // angle
      ui->editC->setEnabled(true);
      ui->editC->setMinimum(1);
    case 0: // distance
      ui->editB->setEnabled(true);
      ui->editB->setMinimum(1);
  }

  if (newType == 0)
    ui->editValue->setSuffix("Å");
  else
    ui->editValue->setSuffix("°");
}

void ConstraintsDialog::acceptConstraints()
{
  hide();
}

void ConstraintsDialog::deleteConstraint()
{
  if (m_molecule == nullptr || m_molecule == nullptr)
    return;

  auto row = ui->constraintsTableView->currentIndex().row();
  m_model->deleteConstraint(row);
  // get the new constraints
  m_molecule->setConstraints(m_model->constraints());
  m_molecule->emitChanged(Molecule::Constraints);
}

void ConstraintsDialog::addConstraint()
{
  if (m_molecule == nullptr)
    return;

  // TODO: Check user input for sanity
  Constraint::Type type;
  switch (ui->comboType->currentIndex()) {
    case 1:
      type = Constraint::AngleConstraint;
      break;
    case 2:
      type = Constraint::TorsionConstraint;
      break;
    case 0:
    default:
      type = Constraint::DistanceConstraint;
      break;
  }
  double value = ui->editValue->value();
  int atomIdA = ui->editA->value();
  int atomIdB = ui->editB->value();
  int atomIdC = ui->editC->value();
  int atomIdD = ui->editD->value();

  Index a, b, c, d;
  if (atomIdA < 1 || atomIdA > m_molecule->atomCount())
    return;
  else
    a = atomIdA - 1;

  if (atomIdB < 1 || atomIdB > m_molecule->atomCount())
    return;
  else
    b = atomIdB - 1;

  if (atomIdC < 1 || atomIdC > m_molecule->atomCount())
    c = MaxIndex;
  else
    c = atomIdC - 1;

  if (atomIdD < 1 || atomIdD > m_molecule->atomCount())
    d = MaxIndex;
  else
    d = atomIdD - 1;

  if (type == Constraint::DistanceConstraint) {
    if (a == b || value == 0.0)
      return;
  } else if (type == Constraint::AngleConstraint) {
    if (a == b || b == c)
      return;
  } else if (type == Constraint::TorsionConstraint)
    if (a == b || a == c || a == d || b == c || b == d || c == d)
      return;

  Constraint newConstraint(a, b, c, d, value);
  newConstraint.setType(type);
  m_molecule->addConstraint(newConstraint);
  m_model->addConstraint(type, a, b, c, d, value);
  m_molecule->emitChanged(Molecule::Constraints);
}

void ConstraintsDialog::deleteAllConstraints()
{
  if (m_molecule == nullptr)
    return;

  m_molecule->clearConstraints();
  m_molecule->emitChanged(Molecule::Constraints);
  // update the model
  m_model->clear();
}

} // namespace QtPlugins
} // namespace Avogadro
