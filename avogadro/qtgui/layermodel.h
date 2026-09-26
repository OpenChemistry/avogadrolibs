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
#include <QtGui/QIcon>

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

  explicit LayerModel(QObject* p = nullptr);

  void loadIcons(bool darkMode);

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

  /**
   * Translate a Layers dock row -- as this model lays them out: one header
   * row per layer, followed by a row for each scene plugin enabled only in
   * that layer, so a row and its layer id can diverge -- to the layer id it
   * belongs to.
   *
   * @return the layer id, or @a MaxIndex if @p row does not name a layer
   * (negative, the synthetic "+" row, or past it).
   */
  size_t layerForRow(int row) const;

  /** @return whether @p layer is visible. Out-of-range is harmless: it
   *  reads back the same default a fresh layer starts with. */
  bool layerVisible(size_t layer) const;
  /** @return whether @p layer is locked. Out-of-range is harmless: it
   *  reads back the same default a fresh layer starts with. */
  bool layerLocked(size_t layer) const;

  /** Show or hide @p layer. A no-op if it already matches @p visible, or if
   *  @p layer is out of range. */
  void setLayerVisible(size_t layer, bool visible);
  /** Lock or unlock @p layer against edits. A no-op if it already matches
   *  @p locked, or if @p layer is out of range. */
  void setLayerLocked(size_t layer, bool locked);

  /** Make @p layer the active layer. A no-op if @p layer is out of range. */
  void setActiveLayerId(size_t layer, RWMolecule* rwmolecule);
  /** Remove @p layer. A no-op if @p layer is out of range. */
  void removeLayerId(size_t layer, RWMolecule* rwmolecule);

public slots:
  void updateRows();

private:
  QString getTranslatedName(const std::string& name) const;
  size_t m_item;

  QIcon m_plusIcon;
  QIcon m_dotsIcon;
  QIcon m_previewIcon;
  QIcon m_previewDashedIcon;
  QIcon m_lockIcon;
  QIcon m_openLockIcon;
  QIcon m_removeIcon;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_LAYERMODEL_H
