/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 University of Pittsburgh

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SPACEGROUPMODEL_H
#define AVOGADRO_QTPLUGINS_SPACEGROUPMODEL_H

#include <QAbstractItemModel>

#include <avogadro/core/avogadrocore.h>

#include <QList>
#include <QVariant>
#include <QString>
#include <QObject>
#include <QAbstractItemModel>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class SpaceGroupItem;
class SpaceGroupModel;
}

class SpaceGroupItem
{
  public:
    SpaceGroupItem(const QList<QVariant> &data, SpaceGroupItem *parent = 0);
    ~SpaceGroupItem();

    void appendChild(SpaceGroupItem *item);
    SpaceGroupItem *child(int row);
    int childCount() const;
    int columnCount() const;
    QVariant data(int column) const;
    int row() const;
    SpaceGroupItem *parent();

  private:
    QList<SpaceGroupItem*> childItems;
    QList<QVariant> itemData;
    SpaceGroupItem *parentItem;

};

class SpaceGroupModel : public QAbstractItemModel
{
  Q_OBJECT
  public:
    explicit SpaceGroupModel(const QString &data, QObject *parent = 0);
    ~SpaceGroupModel();

    QVariant data(const QModelIndex &index, int role) const Q_DECL_OVERRIDE;
    Qt::ItemFlags flags(const QModelIndex &index) const Q_DECL_OVERRIDE;
    QVariant headerData(int section, Qt::Orientation orientation,
        int role = Qt::DisplayRole) const Q_DECL_OVERRIDE;
    QModelIndex index(int row, int column,
        const QModelIndex &parent = QModelIndex()) const Q_DECL_OVERRIDE;
    QModelIndex parent(const QModelIndex &index) const Q_DECL_OVERRIDE;
    int rowCount(const QModelIndex &parent = QModelIndex()) const Q_DECL_OVERRIDE;
    int columnCount(const QModelIndex &parent = QModelIndex()) const Q_DECL_OVERRIDE;

  private:
    void setupModelData(const QStringList &lines, SpaceGroupItem *parent);

    SpaceGroupItem *rootItem;
};

#endif //AVOGADRO_QTPLUGINS_SPACEGROUPMODEL_H
