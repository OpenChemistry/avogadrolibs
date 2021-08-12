/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "scenepluginmodel.h"

#include "sceneplugin.h"

namespace Avogadro {
namespace QtGui {

ScenePluginModel::ScenePluginModel(QObject* parent_)
  : QAbstractItemModel(parent_)
{}

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
  return 1;
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

  ScenePlugin* item =
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
  if (!index_.isValid() || index_.column() > 1)
    return QVariant();

  QObject* object = static_cast<QObject*>(index_.internalPointer());
  ScenePlugin* item = qobject_cast<ScenePlugin*>(object);
  if (!item)
    return QVariant();

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
  ScenePlugin* item = qobject_cast<ScenePlugin*>(sender());
  if (item) {
    int row = m_scenePlugins.indexOf(item);
    if (row >= 0)
      emit dataChanged(createIndex(row, 0), createIndex(row, 0));
  }
}

} // namespace QtGui
} // namespace Avogadro
