/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertytables.h"
#include "propertymodel.h"
#include "propertyview.h"

#include <QtWidgets/QAction>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QStringList>

#include <avogadro/qtgui/molecule.h>

namespace Avogadro {
namespace QtPlugins {

PropertyTables::PropertyTables(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr)
{
  QAction* action = new QAction(this);
  action->setText(tr("Atom Properties..."));
  action->setData(PropertyType::AtomType);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Bond Properties..."));
  action->setData(PropertyType::BondType);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Angle Properties..."));
  action->setData(PropertyType::AngleType);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Torsion Properties..."));
  action->setData(PropertyType::TorsionType);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);

  action = new QAction(this);
  action->setText(tr("Residue Properties..."));
  action->setData(PropertyType::ResidueType);
  action->setEnabled(false); // changed by molecule
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.append(action);
}

PropertyTables::~PropertyTables() {}

QString PropertyTables::description() const
{
  return tr("Tables for displaying and editng atom, bond, angle and torsion "
            "properties.");
}

QList<QAction*> PropertyTables::actions() const
{
  return m_actions;
}

QStringList PropertyTables::menuPath(QAction*) const
{
  return QStringList() << tr("&Analysis") << tr("&Properties");
}

void PropertyTables::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  m_molecule = mol;

  // check if there are residues
  if (m_molecule->residueCount() > 0) {
    for (const auto& action : m_actions) {
      if (action->data().toInt() == PropertyType::ResidueType)
        action->setEnabled(true);
    }
  }
}

void PropertyTables::showDialog()
{
  QAction* action = qobject_cast<QAction*>(sender());
  if (action == nullptr || m_molecule == nullptr)
    return;

  if (action->data().toInt() == PropertyType::ResidueType &&
      m_molecule->residueCount() == 0)
    return;

  QDialog* dialog = new QDialog(qobject_cast<QWidget*>(parent()));
  QVBoxLayout* layout = new QVBoxLayout(dialog);
  dialog->setLayout(layout);
  // Don't show whitespace around the PropertiesView
  layout->setSpacing(0);
  layout->setContentsMargins(0, 0, 0, 0);

  PropertyType i = static_cast<PropertyType>(action->data().toInt());
  PropertyModel* model = new PropertyModel(i);
  model->setMolecule(m_molecule);
  // view will delete itself & model in PropertiesView::hideEvent using
  // deleteLater().
  PropertyView* view = new PropertyView(i, dialog);

  QSortFilterProxyModel* proxyModel = new QSortFilterProxyModel(this);
  proxyModel->setSourceModel(model);
  proxyModel->setDynamicSortFilter(true);
  proxyModel->setSortLocaleAware(true);
  // this role will received direct floating-point numbers from the model
  proxyModel->setSortRole(Qt::UserRole);

  view->setMolecule(m_molecule);
  view->setModel(proxyModel);
  view->setSourceModel(model);

  view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
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

} // namespace QtPlugins
} // namespace Avogadro
