/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layermodel.h"
#include "molecule.h"
#include "rwmolecule.h"

#include <QtCore/QFileInfo>
#include <QtGui/QColor>
#include <QtGui/QIcon>

namespace Avogadro {
namespace QtGui {

using Core::Layer;
using Core::LayerManager;

namespace {
const int QTTY_COLUMNS = 6;
}

LayerModel::LayerModel(QObject* p) : QAbstractItemModel(p), m_item(0) {}

QModelIndex LayerModel::parent(const QModelIndex&) const
{
  return QModelIndex();
}

int LayerModel::rowCount(const QModelIndex& p) const
{
  if (p.isValid())
    return 0;
  else
    return m_item;
}

int LayerModel::columnCount(const QModelIndex& p) const
{
  return QTTY_COLUMNS;
}

Qt::ItemFlags LayerModel::flags(const QModelIndex& idx) const
{
  return Qt::ItemIsEnabled;
}

bool LayerModel::setData(const QModelIndex& idx, const QVariant& value,
                         int role)
{
  return false;
}

QVariant LayerModel::data(const QModelIndex& idx, int role) const
{
  if (!idx.isValid() || idx.column() > QTTY_COLUMNS)
    return QVariant();
  auto names = activeMoleculeNames();
  if (idx.row() == names.size()) {
    if (idx.column() == 0) {
      switch (role) {
        case Qt::DecorationRole:
          return QIcon(":/icons/fallback/32x32/plus.png");
        default:
          return QVariant();
      }
    }
    return QVariant();
  }
  auto name = tr(names[idx.row()].second.c_str()).toStdString();
  auto layer = names[idx.row()].first;
  bool isLayer = name == tr("Layer").toStdString();
  if (isLayer) {
    if (idx.column() == ColumnType::Name) {
      switch (role) {
        case Qt::DisplayRole: {
          return QString("%1 %2").arg(name.c_str()).arg(layer + 1); // count starts at 0 internally
        }
        case Qt::ForegroundRole:
          if (layer == static_cast<int>(getMoleculeLayer().activeLayer()))
            return QVariant(QColor(Qt::red));
          else
            return QVariant(QColor(Qt::black));
        default:
          return QVariant();
      }
    } else if (idx.column() == ColumnType::Menu) {
      if (role == Qt::DecorationRole)
        return QIcon(":/icons/fallback/32x32/dots.png");
    } else if (idx.column() == ColumnType::Visible) {
      if (role == Qt::DecorationRole) {
        if (visible(layer))
          return QIcon(":/icons/fallback/32x32/preview.png");
        else
          return QIcon(":/icons/fallback/32x32/dashed-preview.png");
      }
    } else if (idx.column() == ColumnType::Lock) {
      if (role == Qt::DecorationRole) {
        if (locked(layer))
          return QIcon(":/icons/fallback/32x32/lock.png");
        else
          return QIcon(":/icons/fallback/32x32/lock-open.png");
      }
    } else if (idx.column() == ColumnType::Remove) {
      if (role == Qt::DecorationRole)
        return QIcon(":/icons/fallback/32x32/cross.png");
    }
  } else {
    if (idx.column() == ColumnType::Name) {
      switch (role) {
        case Qt::DisplayRole: {
          return ("  " + name).c_str();
        }
      }
    }
  }

  return QVariant();
}

QModelIndex LayerModel::index(int row, int column, const QModelIndex& p) const
{
  if (!p.isValid())
    if (row >= 0 && row <= m_item)
      return createIndex(row, column);
  return QModelIndex();
}

void LayerModel::addLayer(RWMolecule* rwmolecule)
{
  addItem();
  RWLayerManager::addLayer(rwmolecule);
}

void LayerModel::addItem()
{
  beginInsertRows(QModelIndex(), m_item, m_item);
  endInsertRows();
  ++m_item;
}

void LayerModel::updateRows()
{
  while (m_item > activeMoleculeNames().size()) {
    beginRemoveRows(QModelIndex(), m_item, m_item);
    endRemoveRows();
    --m_item;
  }
  while (m_item <= activeMoleculeNames().size()) {
    addItem();
  }
  emit dataChanged(createIndex(0, 0), createIndex(m_item, 0));
}

void LayerModel::addMolecule(const Molecule* mol)
{
  RWLayerManager::addMolecule(mol);
  m_item = 0;
  updateRows();
}

void LayerModel::setActiveLayer(int index, RWMolecule* rwmolecule)
{
  auto names = activeMoleculeNames();
  assert(index < names.size());
  RWLayerManager::setActiveLayer(names[index].first, rwmolecule);
  updateRows();
}
void LayerModel::removeItem(int row, RWMolecule* rwmolecule)
{
  if (row <= m_item) {
    auto names = activeMoleculeNames();
    removeLayer(static_cast<size_t>(names[row].first), rwmolecule);
    updateRows();
  }
}

size_t LayerModel::items() const
{
  return m_item;
}

void LayerModel::flipVisible(size_t row)
{
  auto names = activeMoleculeNames();
  auto layer = names[row].first;
  RWLayerManager::flipVisible(layer);
}
void LayerModel::flipLocked(size_t row)
{
  auto names = activeMoleculeNames();
  auto layer = names[row].first;
  RWLayerManager::flipLocked(layer);
}

size_t LayerModel::layerCount() const
{
  return LayerManager::layerCount();
}

} // namespace QtGui
} // namespace Avogadro
