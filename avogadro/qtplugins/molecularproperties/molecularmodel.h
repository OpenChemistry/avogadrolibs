/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef MOLECULARMODEL_H
#define MOLECULARMODEL_H

#include <QtCore/QAbstractTableModel>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QString>

#include <avogadro/qtgui/rwmolecule.h>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

enum FixedRowType
{
  Name = 0,
  Mass,
  Formula,
  Atoms,
  Bonds
  // these are the fixed rows
};

class MolecularModel : public QAbstractTableModel
{
  Q_OBJECT

public slots:
  void updateTable(unsigned int flags);

public:
  explicit MolecularModel(QObject* parent = 0);

  int rowCount(const QModelIndex& parent = QModelIndex()) const;
  int columnCount(const QModelIndex& parent = QModelIndex()) const;
  QVariant data(const QModelIndex& index, int role) const;
  Qt::ItemFlags flags(const QModelIndex& index) const;
  bool setData(const QModelIndex& index, const QVariant& value,
               int role = Qt::EditRole);
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role = Qt::DisplayRole) const;

  void setMolecule(QtGui::Molecule* molecule);

private:
  QtGui::Molecule* m_molecule;
};

} // end namespace Avogadro

#endif
