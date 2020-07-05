#ifndef CONSTRAINTSMODEL_H
#define CONSTRAINTSMODEL_H

#include <QtCore/QObject>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtCore/QAbstractTableModel>
#include <QJsonObject>
#include <QJsonDocument>

#include <avogadro/qtgui/molecule.h>
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
      ConstraintsModel(QtGui::Molecule* molecule)
        : QAbstractTableModel()
        , c_molecule(molecule)
      {}

      int rowCount(const QModelIndex &parent = QModelIndex()) const;
      int columnCount(const QModelIndex &parent = QModelIndex()) const;
      QVariant data(const QModelIndex &index, int role) const;
      QVariant headerData(int section, Qt::Orientation orientation,
                          int role = Qt::DisplayRole) const;
       
      void clear();
      void addConstraint(int type, int a, int b, int c, int d, double value);
      void deleteConstraint(int index);

      QJsonObject toJson();

      QList<Constraint> ConstraintsList;
      // reference to associated molecule
      QtGui::Molecule* c_molecule = nullptr;

    }; //ConstraintsModel
  } // QtPlugins
} // end namespace Avogadro

#endif
