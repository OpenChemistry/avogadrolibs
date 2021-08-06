/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_LAYERMODEL_H
#define AVOGADRO_QTGUI_LAYERMODEL_H

#include "avogadroqtguiexport.h"
#include "rwlayermanager.h"

#include <Eigen/Geometry>
#include <QtCore/QAbstractItemModel>

namespace Avogadro {
namespace QtGui {

class Molecule;
class RWMolecule;

/**
 * @class LayerModel layermodel.h <avogadro/qtgui/layermodel.h>
 * @brief UI for the layer dock.
 */
class AVOGADROQTGUI_EXPORT LayerModel : public QAbstractItemModel,
                                        public QtGui::RWLayerManager
{
  Q_OBJECT
public:
  enum ColumnType
  {
    Name = 0,
    Menu = 1,
    Visible = 2,
    Lock = 3,
    Remove = 5
  };

  explicit LayerModel(QObject* p = 0);

  QModelIndex parent(const QModelIndex& child) const override;
  int rowCount(const QModelIndex& parent) const override;
  int columnCount(const QModelIndex& parent) const override;

  Qt::ItemFlags flags(const QModelIndex& index) const override;

  bool setData(const QModelIndex& index, const QVariant& value,
               int role) override;
  QVariant data(const QModelIndex& index, int role) const override;

  QModelIndex index(int row, int column,
                    const QModelIndex& parent = QModelIndex()) const override;

  void addItem();
  void addLayer(RWMolecule* rwmolecule);
  void addMolecule(const Molecule* mol);
  void setActiveLayer(int index, RWMolecule* rwmolecule);
  void removeItem(int row, RWMolecule* rwmolecule);

  size_t items() const;

  void flipVisible(size_t row);
  void flipLocked(size_t row);
  size_t layerCount() const;

public slots:
  void updateRows();

private:
  size_t m_item;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_LAYERMODEL_H
