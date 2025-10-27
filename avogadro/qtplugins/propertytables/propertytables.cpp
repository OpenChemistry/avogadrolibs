/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertytables.h"
#include "propertymodel.h"
#include "propertyview.h"

#include <QAction>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QStringList>

#include <avogadro/qtgui/molecule.h>

namespace Avogadro::QtPlugins {

PropertyTables::PropertyTables(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr)
{
  auto* action = new QAction(this);
  action->setText(tr("Atom Properties…"));
  action->setData(PropertyType::AtomType);
  action->setProperty("menu priority", 880);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Bond Properties…"));
  action->setData(PropertyType::BondType);
  action->setProperty("menu priority", 870);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Angle Properties…"));
  action->setData(PropertyType::AngleType);
  action->setProperty("menu priority", 860);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Torsion Properties…"));
  action->setData(PropertyType::TorsionType);
  action->setProperty("menu priority", 850);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Residue Properties…"));
  action->setData(PropertyType::ResidueType);
  action->setProperty("menu priority", 840);
  action->setEnabled(false); // changed by molecule
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Conformer Properties…"));
  action->setData(PropertyType::ConformerType);
  action->setProperty("menu priority", 830);
  action->setEnabled(false); // changed by molecule
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);
}

PropertyTables::~PropertyTables() {}

QString PropertyTables::description() const
{
  return tr("Tables for displaying and editing atom, bond, angle and torsion "
            "properties.");
}

QList<QAction*> PropertyTables::actions() const
{
  return m_actions;
}

QStringList PropertyTables::menuPath(QAction*) const
{
  return QStringList() << tr("&Analyze") << tr("&Properties");
}

void PropertyTables::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  m_molecule = mol;

  updateActions();

  // update if the molecule changes
  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateActions()));
}

void PropertyTables::updateActions()
{
  if (m_molecule == nullptr)
    return;

  // check if we enable / disable the residue and conformer actions
  bool haveResidues = (m_molecule->residueCount() > 0);
  // technically coordinate sets
  bool haveConformers = (m_molecule->coordinate3dCount() > 1);
  for (const auto& action : m_actions) {
    if (action->data().toInt() == PropertyType::ResidueType)
      action->setEnabled(haveResidues);
    else if (action->data().toInt() == PropertyType::ConformerType)
      action->setEnabled(haveConformers);
  }
}

void PropertyTables::showDialog()
{
  auto* action = qobject_cast<QAction*>(sender());
  if (action == nullptr || m_molecule == nullptr)
    return;

  if (action->data().toInt() == PropertyType::ResidueType &&
      m_molecule->residueCount() == 0)
    return;

  if (action->data().toInt() == PropertyType::ConformerType &&
      m_molecule->coordinate3dCount() < 2)
    return;

  auto* dialog = new QDialog(qobject_cast<QWidget*>(parent()));
  auto* layout = new QVBoxLayout(dialog);
  dialog->setLayout(layout);
  // Don't show whitespace around the PropertiesView
  layout->setSpacing(0);
  layout->setContentsMargins(0, 0, 0, 0);

  PropertyType i = static_cast<PropertyType>(action->data().toInt());
  auto* model = new PropertyModel(i);
  model->setMolecule(m_molecule);
  // view will delete itself & model in PropertiesView::hideEvent using
  // deleteLater().
  auto* view = new PropertyView(i, dialog);

  auto* proxyModel = new QSortFilterProxyModel(this);
  proxyModel->setSourceModel(model);
  proxyModel->setDynamicSortFilter(true);
  proxyModel->setSortLocaleAware(true);
  // this role will received direct floating-point numbers from the model
  proxyModel->setSortRole(Qt::UserRole);

  view->setMolecule(m_molecule);
  view->setModel(proxyModel);
  view->setSourceModel(model);

  view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  view->horizontalHeader()->setStretchLastSection(true);
  view->resizeColumnsToContents();
  layout->addWidget(view);
  dialog->setWindowTitle(view->windowTitle());
  QSize dialogSize = dialog->size();
  double width =
    view->horizontalHeader()->length() + view->verticalHeader()->width() + 5;
  if (model->rowCount() < 13) { // no scrollbar
    dialogSize.setHeight(view->horizontalHeader()->height() +
                         model->rowCount() * 30 + 5);
    dialogSize.setWidth(width);
  } else { // scrollbar is needed
    dialogSize.setHeight(width / 1.618);
    dialogSize.setWidth(width + view->verticalScrollBar()->width());
  }
  dialog->resize(dialogSize);
  dialog->setWindowFlags(Qt::Window);
  dialog->show();
}

} // namespace Avogadro::QtPlugins
