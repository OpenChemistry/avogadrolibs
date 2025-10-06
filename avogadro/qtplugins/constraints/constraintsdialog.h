/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
#define AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H

#include "constraintsmodel.h"

#include <QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class ConstraintsDialog;
}

class ConstraintsDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ConstraintsDialog(QWidget* parent_ = 0,
                             Qt::WindowFlags f = Qt::WindowFlags());
  ~ConstraintsDialog() override;

  void setMolecule(QtGui::Molecule* molecule);

public slots:
  void acceptConstraints();
  void addConstraint();
  void deleteConstraint();
  void deleteAllConstraints();
  void highlightSelected(const QModelIndex& newIndex,
                         const QModelIndex& oldIndex);

  void changeType(int type);

  void updateConstraints();

private:
  Ui::ConstraintsDialog* ui;
  ConstraintsModel* m_model;
  QtGui::Molecule* m_molecule = nullptr;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
