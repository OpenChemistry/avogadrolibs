/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularproperties.h"
#include "molecularview.h"

#include <avogadro/qtgui/richtextdelegate.h>

#include <QAction>
#include <QStringList>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QVBoxLayout>

using Avogadro::QtGui::RichTextDelegate;

namespace Avogadro::QtPlugins {

MolecularProperties::MolecularProperties(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_action(new QAction(this)),
    m_molecule(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText(tr("&Molecular…"));
  m_action->setProperty("menu priority", 990);

  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
}

MolecularProperties::~MolecularProperties() {}

QString MolecularProperties::description() const
{
  return tr("View general properties of a molecule.");
}

QList<QAction*> MolecularProperties::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList MolecularProperties::menuPath(QAction*) const
{
  return QStringList() << tr("&Analyze") << tr("&Properties");
}

void MolecularProperties::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  m_molecule = mol;
}

void MolecularProperties::showDialog()
{
  // copied from the propeties dialog
  auto* dialog = new QDialog(qobject_cast<QWidget*>(parent()));
  auto* layout = new QVBoxLayout(dialog);
  dialog->setLayout(layout);
  // Don't show whitespace around the table view
  layout->setSpacing(0);
  layout->setContentsMargins(0, 0, 0, 0);

  auto* model = new MolecularModel();
  model->setMolecule(m_molecule);
  // view will delete itself & model using deleteLater()
  auto* view = new MolecularView(dialog);
  view->setMolecule(m_molecule);
  view->setSourceModel(model);
  view->setModel(model);

  // set the headers to true
  QFont font = view->horizontalHeader()->font();
  font.setBold(true);
  view->horizontalHeader()->setFont(font);
  view->verticalHeader()->setFont(font);

  view->setItemDelegateForColumn(0, new RichTextDelegate(view));

  view->horizontalHeader()->setStretchLastSection(true);
  view->resizeColumnsToContents();

  layout->addWidget(view);

  dialog->setWindowTitle(view->windowTitle());
  dialog->setWindowFlags(Qt::Window);
  dialog->show();
}

} // namespace Avogadro::QtPlugins
