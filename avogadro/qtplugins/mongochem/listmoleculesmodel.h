/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LISTMOLECULESMODEL_H
#define AVOGADRO_QTPLUGINS_LISTMOLECULESMODEL_H

#include <QAbstractTableModel>
#include <QList>
#include <QVariantMap>

namespace Avogadro {
namespace QtPlugins {

class ListMoleculesModel : public QAbstractTableModel
{
  Q_OBJECT

public:
  ListMoleculesModel(QObject* parent = nullptr);
  int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  int columnCount(const QModelIndex& parent = QModelIndex()) const override;
  QVariant data(const QModelIndex& index,
                int role = Qt::DisplayRole) const override;
  Qt::ItemFlags flags(const QModelIndex& index) const override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role) const override;

  QString moleculeId(int row);
  QString moleculeName(int row);
  void addMolecule(const QVariantMap& molecule);
  void deleteMolecule(const QModelIndex& index);
  void clear();

private:
  QList<QVariantMap> m_molecules;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif
