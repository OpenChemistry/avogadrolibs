/**********************************************************************
  constraintsmodel.cpp - Model to hold constraints

  Copyright (C) 2007 by Tim Vandermeersch

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.cc/>

  Some code is based on Open Babel
  For more information, see <http://openbabel.sourceforge.net/>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 ***********************************************************************/

#include "constraintsmodel.h"

/*
#include <avogadro/primitive.h>
#include <avogadro/atom.h>
#include <avogadro/color.h>
#include <avogadro/glwidget.h>
*/
#include <QtCore/QMutexLocker>
#include <QtCore/QDebug>

using namespace std;
//using namespace OpenBabel;

namespace Avogadro
{
  namespace QtPlugins{
    
    int ConstraintsModel::rowCount(const QModelIndex &) const
    {
      return m_constraints.size();
    }

    int ConstraintsModel::columnCount(const QModelIndex &) const
    {
      return 6;
    }

    QVariant ConstraintsModel::data(const QModelIndex &index, int role) const
    {
      if (!index.isValid())
        return QVariant();

      if (index.row() >= m_constraints.size())
        return QVariant();

      if (role == Qt::DisplayRole)
        switch (index.column()) {
        case 0:
          if (m_constraints[index.row()].GetConstraintType() == 0)
            return QString("Ignore Atom");
          else if (m_constraints[index.row()].GetConstraintType() == 1)
            return QString("Fix Atom");
          else if (m_constraints[index.row()].GetConstraintType() == 2)
            return QString("Fix Atom X");
          else if (m_constraints[index.row()].GetConstraintType() == 3)
            return QString("Fix Atom Y");
          else if (m_constraints[index.row()].GetConstraintType() == 4)
            return QString("Fix Atom Z");
          else if (m_constraints[index.row()].GetConstraintType() == 5)
            return QString("Distance");
          else if (m_constraints[index.row()].GetConstraintType() == 6)
            return QString("Angle");
          else if (m_constraints[index.row()].GetConstraintType() == 7)
            return QString("Torsion angle");
          break;
        case 1:
          return m_constraints[index.row()].GetConstraintValue();
          break;
        case 2:
          return m_constraints[index.row()].GetConstraintAtomA();
          break;
        case 3:
          return m_constraints[index.row()].GetConstraintAtomB();
          break;
        case 4:
          return m_constraints[index.row()].GetConstraintAtomC();
          break;
        case 5:
          return m_constraints[index.row()].GetConstraintAtomD();
          break;
        }

      return QVariant();
    }
  
    QVariant ConstraintsModel::headerData(int section, Qt::Orientation orientation, int role) const
    {
      if (role != Qt::DisplayRole)
        return QVariant();

      if (orientation == Qt::Horizontal) {
        switch (section) {
        case 0:
          return QString("Type");
          break;
        case 1:
          return QString("Value");
          break;
        case 2:
          return QString("Atom idx 1");
          break;
        case 3:
          return QString("Atom idx 2");
          break;
        case 4:
          return QString("Atom idx 3");
          break;
        case 5:
          return QString("Atom idx 4");
          break;
        }
      }
    
      return QString("Constraint %1").arg(section + 1);
    }

    void ConstraintsModel::addConstraint(int type, int a, int b, int c, int d, double value)
    {
      beginInsertRows(QModelIndex(), m_constraints.size(), m_constraints.size());
      m_constraints << Constraint(type, a, b, c, d, value);
      endInsertRows();
    }
    /*
      void ConstraintsModel::addIgnore(int index)
      {
      beginInsertRows(QModelIndex(), m_constraints.Size(), m_constraints.Size()); 
      m_constraints.AddIgnore(index);
      endInsertRows();
      }
  
      void ConstraintsModel::addAtomConstraint(int index)
      {
      beginInsertRows(QModelIndex(), m_constraints.Size(), m_constraints.Size()); 
      m_constraints.AddAtomConstraint(index);
      endInsertRows();
      }
  
      void ConstraintsModel::addAtomXConstraint(int index)
      {
      beginInsertRows(QModelIndex(), m_constraints.Size(), m_constraints.Size()); 
      m_constraints.AddAtomXConstraint(index);
      endInsertRows();
      }
  
      void ConstraintsModel::addAtomYConstraint(int index)
      {
      beginInsertRows(QModelIndex(), m_constraints.Size(), m_constraints.Size()); 
      m_constraints.AddAtomYConstraint(index);
      endInsertRows();
      }
  
      void ConstraintsModel::addAtomZConstraint(int index)
      {
      beginInsertRows(QModelIndex(), m_constraints.Size(), m_constraints.Size()); 
      m_constraints.AddAtomZConstraint(index);
      endInsertRows();
      }
  
      void ConstraintsModel::addDistanceConstraint(int a, int b, double length)
      {
      beginInsertRows(QModelIndex(), m_constraints.Size(), m_constraints.Size()); 
      m_constraints.AddDistanceConstraint(a, b, length);
      endInsertRows();
      }
  
      void ConstraintsModel::addAngleConstraint(int a, int b, int c, double angle)
      {
      beginInsertRows(QModelIndex(), m_constraints.Size(), m_constraints.Size()); 
      m_constraints.AddAngleConstraint(a, b, c, angle);
      endInsertRows();
      }
  
      void ConstraintsModel::addTorsionConstraint(int a, int b, int c, int d, double torsion)
      {
      beginInsertRows(QModelIndex(), m_constraints.Size(), m_constraints.Size()); 
      m_constraints.AddTorsionConstraint(a, b, c, d, torsion);
      endInsertRows();
      }
    */
    void ConstraintsModel::clear()
    {
      qDebug() << "ConstraintsModel::clear()" << endl;
      if (m_constraints.size()) {
        beginRemoveRows(QModelIndex(), 0, m_constraints.size() - 1); 
        m_constraints.clear();
        endRemoveRows();
      }
    }
  
    void ConstraintsModel::deleteConstraint(int index)
    { 
      qDebug() << "ConstraintsModel::deleteConstraint(" << index << ")" << endl;
      if (m_constraints.size() && (index >= 0)) {
        beginRemoveRows(QModelIndex(), index, index); 
        m_constraints.removeAt(index);
        endRemoveRows();
      }
    }
    /*
    // remove all constraints in which the atom occurs
    void ConstraintsModel::primitiveRemoved(Primitive *primitive)
    {
    qDebug() << "ConstraintsModel::primitiveRemoved(...)" << endl;
    if (primitive->type() == Primitive::AtomType) {
    int index = static_cast<Atom*>(primitive)->index() + 1;
    for (int i = 0; i < m_constraints.Size(); ++i) {
    if ( (m_constraints.GetConstraintAtomA(i) == index) || 
    (m_constraints.GetConstraintAtomB(i) == index) || 
    (m_constraints.GetConstraintAtomC(i) == index) || 
    (m_constraints.GetConstraintAtomD(i) == index) ) {

    beginRemoveRows(QModelIndex(), i, i);
    m_constraints.DeleteConstraint(i);
    endRemoveRows();
    i--; // this index will be replaced with a new, we want to check this aswell
    }
    }
    }
    }*/
  }
} // end namespace Avogadro

