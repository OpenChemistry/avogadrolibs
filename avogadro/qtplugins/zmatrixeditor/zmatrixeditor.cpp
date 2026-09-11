/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "zmatrixeditor.h"

#include "zmatrixmodel.h"
#include "zmatrixview.h"

#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QtWidgets/QDockWidget>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro::QtPlugins {

ZMatrixEditor::ZMatrixEditor(QObject* parent_) : QtGui::ExtensionPlugin(parent_)
{
  buildDock();
}

ZMatrixEditor::~ZMatrixEditor()
{
  // If the application never asked for the dock, nothing else owns it.
  if (!m_dock.isNull() && m_dock->parent() == nullptr)
    delete m_dock.data();
}

void ZMatrixEditor::buildDock()
{
  m_dock = new QDockWidget(tr("Z-Matrix Editor"));
  m_dock->setObjectName(QStringLiteral("zmatrixEditorDock"));

  auto* contents = new QWidget(m_dock);
  auto* layout = new QVBoxLayout(contents);

  m_model = new ZMatrixModel(this);
  m_view = new ZMatrixView(contents);
  m_view->setZMatrixModel(m_model);
  layout->addWidget(m_view);

  m_message = new QLabel(contents);
  m_message->setWordWrap(true);
  m_message->setTextFormat(Qt::PlainText);
  layout->addWidget(m_message);

  auto* buttons = new QHBoxLayout;
  m_reorderButton = new QPushButton(tr("Reorder Atoms"), contents);
  buttons->addWidget(m_reorderButton);

  m_rebuildButton = new QPushButton(tr("Rebuild Geometry"), contents);
  m_rebuildButton->setToolTip(
    tr("Rebuild every atom position from the table. The molecule is not "
       "moved or reoriented."));
  buttons->addWidget(m_rebuildButton);
  buttons->addStretch();
  layout->addLayout(buttons);

  m_dock->setWidget(contents);

  // The dock's own toggle is the menu entry, so the checkmark and the dock
  // cannot disagree about whether it is showing.
  m_action = m_dock->toggleViewAction();
  m_action->setText(tr("&Z-Matrix Editor…"));
  m_action->setProperty("menu priority", 890);

  connect(m_dock.data(), &QDockWidget::visibilityChanged, m_model,
          &ZMatrixModel::setActive);
  connect(m_reorderButton, &QPushButton::clicked, this,
          &ZMatrixEditor::reorderAtoms);
  connect(m_rebuildButton, &QPushButton::clicked, this,
          &ZMatrixEditor::rebuildGeometry);
  connect(m_model, &ZMatrixModel::referenceRejected, this,
          &ZMatrixEditor::showMessage);
  connect(m_model, &ZMatrixModel::modelReset, this,
          &ZMatrixEditor::updateButtons);
  connect(m_model, &ZMatrixModel::dataChanged, this,
          &ZMatrixEditor::updateButtons);

  updateButtons();
}

QList<QAction*> ZMatrixEditor::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList ZMatrixEditor::menuPath(QAction*) const
{
  return QStringList() << tr("&Build");
}

QList<QDockWidget*> ZMatrixEditor::dockWidgets() const
{
  QList<QDockWidget*> result;
  if (!m_dock.isNull())
    result << m_dock.data();
  return result;
}

void ZMatrixEditor::setMolecule(QtGui::Molecule* molecule)
{
  if (m_model != nullptr)
    m_model->setMolecule(molecule);
  if (m_view != nullptr)
    m_view->setMolecule(molecule);
  showMessage(QString());
  updateButtons();
}

void ZMatrixEditor::reorderAtoms()
{
  if (m_model == nullptr)
    return;

  if (m_model->reorderAtoms())
    showMessage(tr("Atoms renumbered into z-matrix order."));
  else
    showMessage(tr("The atoms are already in z-matrix order."));

  updateButtons();
}

void ZMatrixEditor::rebuildGeometry()
{
  if (m_model == nullptr)
    return;

  if (m_model->rebuildGeometry())
    showMessage(tr("Geometry rebuilt from the table."));
  else
    showMessage(tr("There is nothing to rebuild."));
}

void ZMatrixEditor::showMessage(const QString& message)
{
  if (m_message != nullptr)
    m_message->setText(message);
}

void ZMatrixEditor::updateButtons()
{
  const bool haveRows =
    m_model != nullptr && m_model->rowCount(QModelIndex()) > 0;

  if (m_reorderButton != nullptr) {
    const bool wanted = haveRows && m_model->needsReorder();
    m_reorderButton->setEnabled(wanted);

    // A greyed button with no explanation is a dead end. Most files are
    // already in a workable order, so say that rather than leaving the
    // person hunting for the control that would renumber them.
    if (!haveRows) {
      m_reorderButton->setToolTip(tr("There is nothing to renumber."));
    } else if (!wanted) {
      m_reorderButton->setToolTip(
        tr("The atoms are already in z-matrix order: every atom already "
           "follows the atoms it is measured against, so renumbering them "
           "would change nothing."));
    } else {
      m_reorderButton->setToolTip(
        tr("Renumber the atoms so that each one follows the atoms it is "
           "measured against. This changes the atom numbers the rest of the "
           "application uses."));
    }
  }

  if (m_rebuildButton != nullptr)
    m_rebuildButton->setEnabled(haveRows);
}

} // namespace Avogadro::QtPlugins
