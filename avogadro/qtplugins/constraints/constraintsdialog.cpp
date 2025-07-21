/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "constraintsdialog.h"
#include "ui_constraintsdialog.h"

#include <QDebug>
#include <QtCore/QSortFilterProxyModel>

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
  view->setModel(m_model);
  view->resizeColumnsToContents();
  // Alternating row colors
  view->setAlternatingRowColors(true);
  // Allow sorting the table
  view->setSortingEnabled(true);
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

void ConstraintsDialog::highlightSelected()
{
  // TODO: select the constraint atoms in the molecule
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
  if (m_molecule == nullptr)
    return;

  auto row = ui->constraintsTableView->currentIndex().row();
}

void ConstraintsDialog::addConstraint()
{
  if (m_molecule == nullptr)
    return;

  // TODO: Check user input for sanity
  int type = ui->comboType->currentIndex();
  double value = ui->editValue->value();
  int AtomIdA = ui->editA->value();
  int AtomIdB = ui->editB->value();
  int AtomIdC = ui->editC->value();
  int AtomIdD = ui->editD->value();

  // adding the constraint to the molecule's CosntraintsModel
  // m_molecule->addConstraint(type, AtomIdA, AtomIdB, AtomIdC, AtomIdD,
  //                                      value);
}

void ConstraintsDialog::deleteAllConstraints()
{
  if (m_molecule != nullptr)
    m_molecule->clearConstraints();
}

} // namespace QtPlugins
} // namespace Avogadro
