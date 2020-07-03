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
#include <QString>

using namespace std;
//using namespace OpenBabel;

namespace Avogadro
{
  namespace QtPlugins{
    
    int ConstraintsModel::rowCount(const QModelIndex &) const
    {
      return ConstraintsList.size();
    }

    int ConstraintsModel::columnCount(const QModelIndex &) const
    {
      return 6;
    }

    QVariant ConstraintsModel::data(const QModelIndex &index, int role) const
    {
      if (!index.isValid())
        return QVariant();

      if (index.row() >= ConstraintsList.size())
        return QVariant();

      if (role == Qt::DisplayRole)
        switch (index.column()) {
        case 0:
          if (ConstraintsList[index.row()].GetConstraintType() == 0)
            return QString("Ignore Atom");
          else if (ConstraintsList[index.row()].GetConstraintType() == 1)
            return QString("Fix Atom");
          else if (ConstraintsList[index.row()].GetConstraintType() == 2)
            return QString("Fix Atom X");
          else if (ConstraintsList[index.row()].GetConstraintType() == 3)
            return QString("Fix Atom Y");
          else if (ConstraintsList[index.row()].GetConstraintType() == 4)
            return QString("Fix Atom Z");
          else if (ConstraintsList[index.row()].GetConstraintType() == 5)
            return QString("Distance");
          else if (ConstraintsList[index.row()].GetConstraintType() == 6)
            return QString("Angle");
          else if (ConstraintsList[index.row()].GetConstraintType() == 7)
            return QString("Torsion angle");
          break;
        case 1:
          return ConstraintsList[index.row()].GetConstraintValue();
          break;
        case 2:
          return ConstraintsList[index.row()].GetConstraintAtomA();
          break;
        case 3:
          return ConstraintsList[index.row()].GetConstraintAtomB();
          break;
        case 4:
          return ConstraintsList[index.row()].GetConstraintAtomC();
          break;
        case 5:
          return ConstraintsList[index.row()].GetConstraintAtomD();
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
      beginInsertRows(QModelIndex(), ConstraintsList.size(), ConstraintsList.size());
      ConstraintsList << Constraint(type, a, b, c, d, value);
      endInsertRows();
    }
 
    void ConstraintsModel::clear()
    {
      qDebug() << "ConstraintsModel::clear()" << endl;
      if (ConstraintsList.size()) {
        beginRemoveRows(QModelIndex(), 0, ConstraintsList.size() - 1); 
        ConstraintsList.clear();
        endRemoveRows();
      }
    }
  
    void ConstraintsModel::deleteConstraint(int index)
    { 
      qDebug() << "ConstraintsModel::deleteConstraint(" << index << ")" << endl;
      if (ConstraintsList.size() && (index >= 0)) {
        beginRemoveRows(QModelIndex(), index, index); 
        ConstraintsList.removeAt(index);
        endRemoveRows();
      }
    }

    QJsonObject ConstraintsModel::toJson()
    {
      QJsonObject ConstraintsMJ;
      ConstraintsMJ["total"] = ConstraintsList.size();
      if(ConstraintsList.size())
        {
        for(int i = 0; i < ConstraintsList.size(); i++)
          {
            ConstraintsMJ.insert(QString::number(i), ConstraintsList[i].toJson());
          }
        }
      

      QJsonDocument json_doc(ConstraintsMJ);
      QString json_string = json_doc.toJson();

      qDebug() << json_string << endl;

      return ConstraintsMJ;
    }
    /*
    // remove all constraints in which the atom occurs
    void ConstraintsModel::primitiveRemoved(Primitive *primitive)
    {
    qDebug() << "ConstraintsModel::primitiveRemoved(...)" << endl;
    if (primitive->type() == Primitive::AtomType) {
    int index = static_cast<Atom*>(primitive)->index() + 1;
    for (int i = 0; i < ConstraintsList.Size(); ++i) {
    if ( (ConstraintsList.GetConstraintAtomA(i) == index) || 
    (ConstraintsList.GetConstraintAtomB(i) == index) || 
    (ConstraintsList.GetConstraintAtomC(i) == index) || 
    (ConstraintsList.GetConstraintAtomD(i) == index) ) {

    beginRemoveRows(QModelIndex(), i, i);
    ConstraintsList.DeleteConstraint(i);
    endRemoveRows();
    i--; // this index will be replaced with a new, we want to check this aswell
    }
    }
    }
    }*/
  }
} // end namespace Avogadro

