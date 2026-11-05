/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
#define AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H

#include "constraintsmodel.h"

#include <QDialog>
#include <QtCore/QPointer>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class ConstraintsDialog;
}

class ConstraintsDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ConstraintsDialog(QWidget* parent_ = nullptr,
                             Qt::WindowFlags f = Qt::WindowFlags());
  ~ConstraintsDialog() override;

  /**
   * Show the constraints of @p molecule and follow its changes. A null
   * molecule empties the table and stops following the previous one.
   */
  void setMolecule(QtGui::Molecule* molecule);

public slots:
  void acceptConstraints();
  void addConstraint();
  void getConstraint();
  void deleteConstraint();
  void deleteAllConstraints();
  void highlightSelected(const QModelIndex& newIndex,
                         const QModelIndex& oldIndex);

  void changeType(int type);

  void updateConstraints();

private:
  Ui::ConstraintsDialog* ui;
  ConstraintsModel* m_model;
  // Guarded: the molecule can be closed while the dialog stays open.
  QPointer<QtGui::Molecule> m_molecule;
  QMetaObject::Connection m_changedConnection;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
