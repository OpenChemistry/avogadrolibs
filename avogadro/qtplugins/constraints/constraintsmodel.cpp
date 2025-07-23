/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "constraintsmodel.h"

#include <QtCore/QDebug>
#include <QtCore/QString>

using namespace std;

namespace Avogadro {
using Core::Constraint;

namespace QtPlugins {

void ConstraintsModel::emitDataChanged()
{
  emit dataChanged(QModelIndex(), QModelIndex());
}

void ConstraintsModel::setConstraints(
  const std::vector<Core::Constraint>& constraints)
{
  beginResetModel();
  m_constraints = constraints;
  endResetModel();
}

int ConstraintsModel::rowCount(const QModelIndex&) const
{
  return m_constraints.size();
}

int ConstraintsModel::columnCount(const QModelIndex&) const
{
  // Type, value, atom 1, 2, 3, 4
  return 6;
}

QVariant ConstraintsModel::data(const QModelIndex& index, int role) const
{
  if (!index.isValid())
    return QVariant();

  if (index.row() >= m_constraints.size())
    return QVariant();

  Constraint currentConstraint = m_constraints[index.row()];
  Index aIndex = currentConstraint.aIndex();
  Index bIndex = currentConstraint.bIndex();
  Index cIndex = currentConstraint.cIndex();
  Index dIndex = currentConstraint.dIndex();

  if (role == Qt::DisplayRole || role == Qt::UserRole)
    switch (index.column()) {
      case 0:
        if (currentConstraint.type() == 1)
          return tr("Distance");
        else if (currentConstraint.type() == 2)
          return tr("Angle");
        else if (currentConstraint.type() == 3)
          return tr("Torsion Angle");
        // these aren't really implemented in the UI yet
        // but we're saving the strings for translation
        else if (currentConstraint.type() == 4)
          return tr("Freeze Atom", "fix / remain constant");
        else if (currentConstraint.type() == 5)
          return tr("Freeze X Axis", "fix / remain constant");
        else if (currentConstraint.type() == 6)
          return tr("Freeze Y Axis", "fix / remain constant");
        else if (currentConstraint.type() == 7)
          return tr("Freeze Z Axis", "fix / remain constant");
        break;
      case 1:
        // TODO handle fixed-length number and sorting
        if (role == Qt::UserRole)
          return currentConstraint.value();

        if (currentConstraint.type() == 1)
          return QString("%1 Å").arg(currentConstraint.value(), 0, 'f', 3);
        else if (currentConstraint.type() == 2 || currentConstraint.type() == 3)
          return QString("%1 °").arg(currentConstraint.value(), 0, 'f', 3);
        else
          return "--";
        break;
      case 2:
        if (aIndex != MaxIndex)
          return QVariant(static_cast<qulonglong>(aIndex));
        else
          return "--";
        break;
      case 3:
        if (bIndex != MaxIndex)
          return QVariant(static_cast<qulonglong>(bIndex));
        else
          return "--";
        break;
      case 4:
        if (cIndex != MaxIndex)
          return QVariant(static_cast<qulonglong>(cIndex));
        else
          return "--";
        break;
      case 5:
        if (dIndex != MaxIndex)
          return QVariant(static_cast<qulonglong>(dIndex));
        else
          return "--";
        break;
    }

  return QVariant();
}

QVariant ConstraintsModel::headerData(int section, Qt::Orientation orientation,
                                      int role) const
{
  if (role != Qt::DisplayRole)
    return QVariant();

  if (orientation == Qt::Horizontal) {
    switch (section) {
      case 0:
        return tr("Type");
        break;
      case 1:
        return tr("Value");
        break;
      case 2:
        return tr("Atom 1");
        break;
      case 3:
        return tr("Atom 2");
        break;
      case 4:
        return tr("Atom 3");
        break;
      case 5:
        return tr("Atom 4");
        break;
    }
  }

  return section + 1;
}

void ConstraintsModel::addConstraint(int type, int a, int b, int c, int d,
                                     double value)
{
  beginInsertRows(QModelIndex(), m_constraints.size(), m_constraints.size());
  m_constraints.push_back(Constraint(a, b, c, d, value));
  endInsertRows();
}

void ConstraintsModel::clear()
{
  if (m_constraints.size()) {
    beginRemoveRows(QModelIndex(), 0, m_constraints.size() - 1);
    m_constraints.clear();
    endRemoveRows();
  }
}

void ConstraintsModel::deleteConstraint(int index)
{
  if (m_constraints.size() && (index >= 0)) {
    beginRemoveRows(QModelIndex(), index, index);
    auto position = m_constraints.begin() + index;
    m_constraints.erase(position);
    endRemoveRows();
  }
}

Core::Constraint ConstraintsModel::constraint(int index)
{
  if (index < 0 || index >= m_constraints.size())
    return Constraint(MaxIndex, MaxIndex, MaxIndex, MaxIndex, 0.0);
  else
    return m_constraints[index];
}

} // namespace QtPlugins
} // end namespace Avogadro
