/**********************************************************************
  constraintsmodel.h - Model to hold constraints

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

#ifndef CONSTRAINTSMODEL_H
#define CONSTRAINTSMODEL_H

#include <QtCore/QObject>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtCore/QAbstractTableModel>
#include "constraint.h"
#ifndef BUFF_SIZE
#define BUFF_SIZE 256
#endif

namespace Avogadro {
  namespace QtPlugins {
    class ConstraintsModel : public QAbstractTableModel

    {
      Q_OBJECT
      /* 
    public slots:
      void primitiveRemoved(Primitive *primitive);
      */
    public:
      ConstraintsModel() : QAbstractTableModel() {}

      int rowCount(const QModelIndex &parent = QModelIndex()) const;
      int columnCount(const QModelIndex &parent = QModelIndex()) const;
      QVariant data(const QModelIndex &index, int role) const;
      QVariant headerData(int section, Qt::Orientation orientation,
                          int role = Qt::DisplayRole) const;
       
      void clear();
      void addConstraint(int type, int a, int b, int c, int d, double value);
      void deleteConstraint(int index);

      /*
      void addIgnore(int index);
      void addAtomConstraint(int index);
      void addAtomXConstraint(int index);
      void addAtomYConstraint(int index);
      void addAtomZConstraint(int index);
      void addDistanceConstraint(int a, int b, double length);
      void addAngleConstraint(int a, int b, int c, double angle);
      void addTorsionConstraint(int a, int b, int c, int d, double torsion);
      */
      QList<Constraint> ConstraintsList;

    }; //ConstraintsModel
  } // QtPlugins
} // end namespace Avogadro

#endif
