/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "layermodel.h"
#include "molecule.h"
#include "rwmolecule.h"

#include <QtCore/QDebug>
#include <QtCore/QFileInfo>
#include <QtGui/QColor>
#include <QtGui/QIcon>
#include <QtGui/QPalette>

namespace Avogadro::QtGui {

using Core::LayerManager;

namespace {
const int QTTY_COLUMNS = 6;
}

LayerModel::LayerModel(QObject* p) : QAbstractItemModel(p), m_item(0)
{
  // determine if need dark mode or light mode icons
  // e.g. https://www.qt.io/blog/dark-mode-on-windows-11-with-qt-6.5
  const QPalette defaultPalette;
  // i.e., the text is lighter than the background
  bool darkMode = (defaultPalette.color(QPalette::WindowText).lightness() >
                   defaultPalette.color(QPalette::Window).lightness());
  loadIcons(darkMode);
}

void LayerModel::loadIcons(bool darkMode)
{
  QString iconPath = ":icons/fallback/32x32/";

  QString dashedPreviewIconPath = iconPath + "dashed-preview-light.png";
  QString dotsIconPath = iconPath + "dots-light.png";
  QString lockIconPath = iconPath + "lock-light.png";
  QString openLockIconPath = iconPath + "lock-open-light.png";
  QString plusIconPath = iconPath + "plus-light.png";
  QString previewIconPath = iconPath + "preview-light.png";

  if (darkMode) {
    dashedPreviewIconPath = iconPath + "dashed-preview-dark.png";
    dotsIconPath = iconPath + "dots-dark.png";
    lockIconPath = iconPath + "lock-dark.png";
    openLockIconPath = iconPath + "lock-open-dark.png";
    plusIconPath = iconPath + "plus-dark.png";
    previewIconPath = iconPath + "preview-dark.png";
  }

  m_plusIcon = QIcon::fromTheme("list-add", QIcon(plusIconPath));
  m_removeIcon = QIcon::fromTheme(
    "list-remove", QIcon(":/icons/fallback/32x32/edit-delete.png"));
  m_dotsIcon = QIcon::fromTheme("view-more", QIcon(dotsIconPath));
  m_previewIcon = QIcon::fromTheme("view-visible", QIcon(previewIconPath));
  m_previewDashedIcon =
    QIcon::fromTheme("view-hidden", QIcon(dashedPreviewIconPath));
  m_lockIcon = QIcon::fromTheme("lock", QIcon(lockIconPath));
  m_openLockIcon = QIcon::fromTheme("unlock", QIcon(openLockIconPath));
}

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

int LayerModel::columnCount(const QModelIndex&) const
{
  return QTTY_COLUMNS;
}

Qt::ItemFlags LayerModel::flags(const QModelIndex&) const
{
  return Qt::ItemIsEnabled;
}

bool LayerModel::setData(const QModelIndex&, const QVariant&, int)
{
  return false;
}

QVariant LayerModel::data(const QModelIndex& idx, int role) const
{
  if (!idx.isValid() || idx.column() > QTTY_COLUMNS)
    return QVariant();
  auto names = activeMoleculeNames();
  if (idx.row() == static_cast<int>(names.size())) {
    if (idx.column() == 0) {
      switch (role) {
        case Qt::DecorationRole:
          return m_plusIcon;
        default:
          return QVariant();
      }
    }
    return QVariant();
  }
  auto name = names[idx.row()].second;
  auto layer = names[idx.row()].first;
  bool isLayer = (name == "Layer");
  if (isLayer) {
    if (idx.column() == ColumnType::Name) {
      switch (role) {
        case Qt::DisplayRole: {
          return QString(tr("Layer %1"))
            .arg(layer + 1); // count starts at 0 internally
        }
        case Qt::ForegroundRole:
          if (layer == getMoleculeLayer().activeLayer())
            return QVariant(QColor(Qt::red));
          else {
            const QPalette defaultPalette;
            return QVariant(defaultPalette.color(QPalette::WindowText));
          }
        default:
          return QVariant();
      }
    } else if (idx.column() == ColumnType::Menu) {
      if (role == Qt::DecorationRole)
        return m_dotsIcon;
    } else if (idx.column() == ColumnType::Visible) {
      if (role == Qt::DecorationRole) {
        if (visible(layer))
          return m_previewIcon;
        else
          return m_previewDashedIcon;
      }
    } else if (idx.column() == ColumnType::Lock) {
      if (role == Qt::DecorationRole) {
        if (locked(layer))
          return m_lockIcon;
        else
          return m_openLockIcon;
      }
    } else if (idx.column() == ColumnType::Remove) {
      if (role == Qt::DecorationRole)
        return m_removeIcon;
    }
  } else {
    if (idx.column() == ColumnType::Name) {
      switch (role) {
        case Qt::DisplayRole: {
          return "  " + getTranslatedName(name); // should already be translated
        }
      }
    }
  }

  return QVariant();
}

QString LayerModel::getTranslatedName(const std::string& name) const
{
  // This is a bad hack, but whatever..
  // Put all the strings that show up as layer options

  if (name == "Ball and Stick")
    return tr("Ball and Stick");
  else if (name == "Cartoons")
    return tr("Cartoons", "protein ribbon / cartoon rendering");
  else if (name == "Close Contacts")
    return tr("Close Contacts", "rendering of non-covalent close contacts");
  else if (name == "Crystal Lattice")
    return tr("Crystal Lattice");
  else if (name == "Dipole Moment")
    return tr("Dipole Moment");
  else if (name == "Force")
    return tr("Force");
  else if (name == "Labels")
    return tr("Labels");
  else if (name == "Licorice")
    return tr("Licorice", "stick / licorice rendering");
  else if (name == "Surfaces")
    return tr("Surfaces");
  else if (name == "Non-Covalent")
    return tr("Non-Covalent");
  else if (name == "QTAIM")
    return tr("QTAIM", "quantum theory of atoms in molecules");
  else if (name == "Symmetry Elements")
    return tr("Symmetry Elements");
  else if (name == "Van der Waals")
    return tr("Van der Waals");
  else if (name == "Wireframe")
    return tr("Wireframe");

  qDebug() << "LayerModel: name didn't match: " << name.c_str();

  return QString(name.c_str());
}

QModelIndex LayerModel::index(int row, int column, const QModelIndex& p) const
{
  if (!p.isValid())
    if (row >= 0 && row <= static_cast<int>(m_item))
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

  connect(mol, &Molecule::changed, this, &LayerModel::updateRows);
}

void LayerModel::setActiveLayer(int index, RWMolecule* rwmolecule)
{
  auto names = activeMoleculeNames();
  assert(index < static_cast<int>(names.size()));
  RWLayerManager::setActiveLayer(names[index].first, rwmolecule);
  updateRows();
}
void LayerModel::removeItem(int row, RWMolecule* rwmolecule)
{
  if (row <= static_cast<int>(m_item)) {
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

} // namespace Avogadro::QtGui
