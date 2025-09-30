/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef CONSTRAINTSMODEL_H
#define CONSTRAINTSMODEL_H

#include <QtCore/QObject>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtCore/QAbstractTableModel>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/core/constraint.h>

namespace Avogadro {
namespace QtPlugins {

class ConstraintsModel : public QAbstractTableModel

{
  Q_OBJECT

public:
  ConstraintsModel() : QAbstractTableModel() {}

  int rowCount(const QModelIndex& parent = QModelIndex()) const;
  int columnCount(const QModelIndex& parent = QModelIndex()) const;
  QVariant data(const QModelIndex& index, int role) const;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role = Qt::DisplayRole) const;

  void clear();
  Core::Constraint constraint(int index);
  std::vector<Core::Constraint> constraints() { return m_constraints; }
  void addConstraint(int type, int a, int b, int c, int d, double value);
  void deleteConstraint(int index);
  void setConstraints(const std::vector<Core::Constraint>& constraints);

public slots:
  void emitDataChanged();

private:
  std::vector<Core::Constraint> m_constraints;

}; // ConstraintsModel

} // namespace QtPlugins
} // end namespace Avogadro

#endif
