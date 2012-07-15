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

#ifndef AVOGADRO_QTGUI_SCENEPLUGINMODEL_H
#define AVOGADRO_QTGUI_SCENEPLUGINMODEL_H

#include "avogadroqtguiexport.h"

#include <QtCore/QAbstractItemModel>

namespace Avogadro {
namespace QtGui {

class ScenePlugin;

/*!
 * \class ScenePluginModel scenepluginmodel.h <avogadro/qtgui/scenepluginmodel.h>
 * \brief A model containing scene plugins that will build up the scene.
 * \author Marcus D. Hanwell
 */

class AVOGADROQTGUI_EXPORT ScenePluginModel : public QAbstractItemModel
{
  Q_OBJECT

public:
  explicit ScenePluginModel(QObject *parent = 0);

  QModelIndex parent(const QModelIndex &child) const;
  int rowCount(const QModelIndex &parent) const;
  int columnCount(const QModelIndex &parent) const;

  Qt::ItemFlags flags(const QModelIndex &index) const;

  bool setData(const QModelIndex &index, const QVariant &value, int role);
  QVariant data(const QModelIndex &index, int role) const;

  QModelIndex index(int row, int column,
                    const QModelIndex &parent = QModelIndex()) const;

  void clear();


public slots:
  void addItem(ScenePlugin *item);
  void removeItem(ScenePlugin *item);
  void itemChanged();

private:
  QList<ScenePlugin *> m_scenePlugins;
};

} // End QtGui namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTGUI_SCENEPLUGINMODEL_H
