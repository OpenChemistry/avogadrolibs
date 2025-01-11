/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scenepluginmodel.h"

#include "sceneplugin.h"

namespace Avogadro::QtGui {

ScenePluginModel::ScenePluginModel(QObject* parent_)
  : QAbstractItemModel(parent_)
{
}

QModelIndex ScenePluginModel::parent(const QModelIndex&) const
{
  return QModelIndex();
}

int ScenePluginModel::rowCount(const QModelIndex& parent_) const
{
  if (parent_.isValid())
    return 0;
  else
    return m_scenePlugins.size();
}

int ScenePluginModel::columnCount(const QModelIndex&) const
{
  return 2;
}

Qt::ItemFlags ScenePluginModel::flags(const QModelIndex& index_) const
{
  if (index_.column() == 0)
    return Qt::ItemIsEditable | Qt::ItemIsUserCheckable | Qt::ItemIsEnabled;
  else
    return Qt::ItemIsEnabled;
}

bool ScenePluginModel::setData(const QModelIndex& index_, const QVariant& value,
                               int role)
{
  if (!index_.isValid() || index_.column() > 1)
    return false;

  auto* item =
    qobject_cast<ScenePlugin*>(static_cast<QObject*>(index_.internalPointer()));
  if (!item)
    return false;

  switch (role) {
    case Qt::CheckStateRole:
      if (value == Qt::Checked && !item->isActiveLayerEnabled()) {
        item->setEnabled(true);
        emit pluginStateChanged(item);
      } else if (value == Qt::Unchecked && item->isActiveLayerEnabled()) {
        item->setEnabled(false);
        emit pluginStateChanged(item);
      }
      emit dataChanged(index_, index_);
      return true;
  }
  return false;
}

QVariant ScenePluginModel::data(const QModelIndex& index_, int role) const
{
  if (!index_.isValid() || index_.column() > 2)
    return QVariant();

  auto* object = static_cast<QObject*>(index_.internalPointer());
  auto* item = qobject_cast<ScenePlugin*>(object);
  if (!item)
    return QVariant();

  // Simple lambda to convert QFlags to variant as in Qt 6 this needs help.
  auto toVariant = [&](auto flags) {
    return static_cast<Qt::Alignment::Int>(flags);
  };

  // check if setupWidget() returns something
  if (index_.column() == 1) {
    switch (role) {
      case Qt::DisplayRole:
      case Qt::EditRole:
        return (item->hasSetupWidget()) ? "•••" : " ";
      case Qt::ToolTipRole:
      case Qt::WhatsThisRole:
        return tr("Settings");
      case Qt::TextAlignmentRole:
        return toVariant(Qt::AlignLeft | Qt::AlignVCenter);
      default:
        return QVariant();
    }
  }

  if (index_.column() == 0) {
    switch (role) {
      case Qt::DisplayRole:
      case Qt::EditRole:
        return item->name();
      case Qt::CheckStateRole:
        if (item->isActiveLayerEnabled())
          return Qt::Checked;
        else
          return Qt::Unchecked;
      case Qt::ToolTipRole:
      case Qt::WhatsThisRole:
        return item->description();
      case Qt::TextAlignmentRole:
        return toVariant(Qt::AlignLeft);
      default:
        return QVariant();
    }
  }
  return QVariant();
}

QModelIndex ScenePluginModel::index(int row, int column,
                                    const QModelIndex& parent_) const
{
  if (!parent_.isValid() && row >= 0 && row < m_scenePlugins.size())
    return createIndex(row, column, m_scenePlugins[row]);
  else
    return QModelIndex();
}

void ScenePluginModel::clear()
{
  m_scenePlugins.clear();
}

QList<ScenePlugin*> ScenePluginModel::scenePlugins() const
{
  return m_scenePlugins;
}

QList<ScenePlugin*> ScenePluginModel::activeScenePlugins() const
{
  QList<ScenePlugin*> result;
  foreach (ScenePlugin* plugin, m_scenePlugins) {
    if (plugin->isEnabled())
      result << plugin;
  }
  return result;
}

void ScenePluginModel::addItem(ScenePlugin* item)
{
  if (!m_scenePlugins.contains(item)) {
    m_scenePlugins.append(item);
    item->setParent(this);
    connect(item, SIGNAL(drawablesChanged()), SIGNAL(pluginConfigChanged()));
  }
}

void ScenePluginModel::removeItem(ScenePlugin* item)
{
  m_scenePlugins.removeAll(item);
}

void ScenePluginModel::itemChanged()
{
  auto* item = qobject_cast<ScenePlugin*>(sender());
  if (item) {
    int row = m_scenePlugins.indexOf(item);
    if (row >= 0)
      emit dataChanged(createIndex(row, 0), createIndex(row, 0));
  }
}

} // namespace Avogadro::QtGui
