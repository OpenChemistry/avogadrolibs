/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VIBRATIONMODEL_H
#define AVOGADRO_QTPLUGINS_VIBRATIONMODEL_H

#include <QtCore/QAbstractItemModel>

namespace Avogadro {
namespace QtGui {
class Molecule;
}
namespace QtPlugins {

class VibrationModel : public QAbstractItemModel
{
public:
  explicit VibrationModel(QObject* p = nullptr);

  QModelIndex parent(const QModelIndex& child) const override;
  int rowCount(const QModelIndex& parent) const override;
  int columnCount(const QModelIndex& parent) const override;

  Qt::ItemFlags flags(const QModelIndex& index) const override;

  QVariant headerData(int section, Qt::Orientation orientation,
                      int role) const override;

  bool setData(const QModelIndex& index, const QVariant& value,
               int role) override;
  QVariant data(const QModelIndex& index, int role) const override;

  QModelIndex index(int row, int column,
                    const QModelIndex& parent = QModelIndex()) const override;

  void clear();

  void setMolecule(QtGui::Molecule* mol);

signals:

public slots:

private:
  QtGui::Molecule* m_molecule;
  bool m_hasRaman;
};
}
}

#endif // AVOGADRO_QTPLUGINS_VIBRATIONMODEL_H
