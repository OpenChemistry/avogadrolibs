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

#include "spacegroupmodel.h"

#include <string>
#include <avogadro/core/spacegroups.h>
#include <QDebug>

using Avogadro::Core::SpaceGroups;

namespace Avogadro {
namespace QtPlugins {

  SpaceGroupItem::SpaceGroupItem(const QList<QVariant> &data, class SpaceGroupItem *parent)
  {
    m_parentItem=parent;
    itemData = data;
  }

  SpaceGroupItem::~SpaceGroupItem()
  {
    qDeleteAll(childItems);
  }

  void SpaceGroupItem::appendChild(SpaceGroupItem *item)
  {
    childItems.append(item);
  }

  SpaceGroupItem *SpaceGroupItem::child(int row)
  {
    return childItems.value(row);
  }

  int SpaceGroupItem::childCount() const
  {
    return childItems.count();
  }

  int SpaceGroupItem::row() const
  {
    if (m_parentItem)
      return m_parentItem->childItems.indexOf(const_cast<SpaceGroupItem*>(this));

    return 0;
  }

  int SpaceGroupItem::columnCount() const
  {
    return itemData.count();
  }

  QVariant SpaceGroupItem::data(int column) const
  {
    return itemData.value(column);
  }

  SpaceGroupItem *SpaceGroupItem::parentItem()
  {
    return m_parentItem;
  }

  QVariant SpaceGroupItem::getHallNumber()
  {
    //qDebug() << columnCount();
    return QVariant();
  }


  SpaceGroupModel::SpaceGroupModel(QObject *parent)
    : QAbstractItemModel(parent)
  {
    QList<QVariant> rootData;
    rootData << "Space Group" << "Hall Number";
    rootItem = new SpaceGroupItem(rootData);
    setupModelData(rootItem);
  }

  SpaceGroupModel::~SpaceGroupModel()
  {
    delete rootItem;
  }

  QModelIndex SpaceGroupModel::index(int row, int column, const QModelIndex &parent)
    const
    {
      if (!hasIndex(row, column, parent))
        return QModelIndex();

      SpaceGroupItem *parentItem;

      if (!parent.isValid())
        parentItem = rootItem;
      else
        parentItem = static_cast<SpaceGroupItem*>(parent.internalPointer());

      SpaceGroupItem *childItem = parentItem->child(row);
      if (childItem)
        return createIndex(row, column, childItem);
      else
        return QModelIndex();
    }

  QModelIndex SpaceGroupModel::parent(const QModelIndex &index) const
  {
    if (!index.isValid())
      return QModelIndex();

    SpaceGroupItem *childItem = static_cast<SpaceGroupItem*>(index.internalPointer());
    SpaceGroupItem *parentItem = childItem->parentItem();

    if (parentItem == rootItem)
      return QModelIndex();

    return createIndex(parentItem->row(), 0, parentItem);
  }

  int SpaceGroupModel::rowCount(const QModelIndex &parent) const
  {
    SpaceGroupItem *parentItem;
    if (parent.column() > 0)
      return 0;

    if (!parent.isValid())
      parentItem = rootItem;
    else
      parentItem = static_cast<SpaceGroupItem*>(parent.internalPointer());

    return parentItem->childCount();
  }

  int SpaceGroupModel::columnCount(const QModelIndex &parent) const
  {
    if (parent.isValid())
      return static_cast<SpaceGroupItem*>(parent.internalPointer())->columnCount();
    else
      return rootItem->columnCount();
  }

  QVariant SpaceGroupModel::data(const QModelIndex &index, int role) const
  {
    if (!index.isValid())
      return QVariant();


    SpaceGroupItem *item = static_cast<SpaceGroupItem*>(index.internalPointer());

    if (role == 20) {
      //qDebug() << item->columnCount();//item->data(index.column());
      //return item->data(index.column());//getHallNumber();
      return QVariant(spaceGroupHallNumber(item,index));
    }

    if (role == 200) {
        return QVariant(spaceGroupInfo(item,index));
    }

    if (role != Qt::DisplayRole)
      return QVariant();

    return item->data(index.column());
  }

  QString SpaceGroupModel::spaceGroupInfo(SpaceGroupItem *item, const QModelIndex &index) const
  {
    QString display;
    int nChildren = item->childCount();
    SpaceGroupItem *parentItem = item->parentItem();
    if(nChildren==0)
    {
      if(item->columnCount() > 1)
      {
        std::string spg=SpaceGroups::describeSpaceGroup(item->data(1).toInt());
        display=QString(spg.c_str());
      }
      else
        display="";

      /*while(parentItem != rootItem) {
        QString nextLine = QString("%1\n").arg(parentItem->data(index.column()).toString());
        display.prepend(nextLine);
        parentItem = parentItem->parentItem();
      }*/
    }
    return display;
  }

  int SpaceGroupModel::spaceGroupHallNumber(SpaceGroupItem *item, const QModelIndex &index) const
  {
    int nChildren = item->childCount();
    SpaceGroupItem *parentItem = item->parentItem();
    if(nChildren==0)
    {
      if(item->columnCount() > 1)
        return item->data(1).toInt();
      else
        return 0;
    }
    else
      return 0;
  }


  Qt::ItemFlags SpaceGroupModel::flags(const QModelIndex &index) const
  {
    if (!index.isValid())
      return 0;

    return QAbstractItemModel::flags(index);
  }

  QVariant SpaceGroupModel::headerData(int section, Qt::Orientation orientation,
      int role) const
  {
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
      return rootItem->data(section);

    return QVariant();
  }

  void SpaceGroupModel::setupModelData(SpaceGroupItem *parent)
  {
    QList<SpaceGroupItem*> parents;
    parents << parent;

    std::vector<SpaceGroups::crystalSystem> crystals = SpaceGroups::getCrystalArray();

    //There are 7 crystal systems
    for (int i=0;i<crystals.size();i++)
    {
      QString crystal = QString::fromStdString(SpaceGroups::getCrystalString(crystals.at(i)));
      QList<QVariant> crystalData;
      crystalData << crystal << "";
      SpaceGroupItem *iCrystal = new SpaceGroupItem(crystalData,parent);
      //each crystal is also a parent
      //parents << parents.last()->child(parents.last()->childCount()-1);

      //multiple bravais lattices
      std::vector<std::string> bravais = SpaceGroups::getBravaisArray(crystals.at(i));
      for (int j=0;j<bravais.size();j++)
      {
        QString bravaisStr = QString::fromStdString(bravais.at(j));
        QList<QVariant> bravaisData;
        bravaisData << bravaisStr << "";
        SpaceGroupItem *jBravais = new SpaceGroupItem(bravaisData,iCrystal);

        //now we finally have the space group symbol
        std::vector<std::string> intSymbol = SpaceGroups::getIntSymbolArray(crystals.at(i),bravais.at(j));
        for (int k=0;k<intSymbol.size();k++)
        {
          QString intString = QString::fromStdString(intSymbol.at(k));
          QList<QVariant> symbolData;
          symbolData << intString;
          //jBravais.appendChild(kSymbol);

          //but, there may be more than one setting
          std::vector<std::string> settings = SpaceGroups::getSettingArray(crystals.at(i),bravais.at(j),intSymbol.at(k));
          SpaceGroupItem *kSymbol;

          if(settings.at(0) == "     ")
          {
            int hall = SpaceGroups::getHallNumber(crystals.at(i),bravais.at(j),intSymbol.at(k),settings.at(0));
            //int spgNumber = SpaceGroups::getNumber(hall);
            //add the hall number column
            symbolData << hall;
            kSymbol = new SpaceGroupItem(symbolData,jBravais);
            //kSymbol = new SpaceGroupItem(symbolData,jBravais);
          }

          else
          {
            kSymbol = new SpaceGroupItem(symbolData,jBravais);
            for (int l=0;l<settings.size();l++)
            {
              int hall = SpaceGroups::getHallNumber(crystals.at(i),bravais.at(j),intSymbol.at(k),settings.at(l));
              //int spgNumber = SpaceGroup::getNumber(hall);
              //QList<QVariant> hallData;
              //allData << hall << QString("---");

             // if(settings.at(l) != "     ")
              //{
              QString settingString = QString::fromStdString(settings.at(l));
              QList<QVariant> settingData;
              settingData << settingString << hall;
              SpaceGroupItem *lSetting = new SpaceGroupItem(settingData,kSymbol);
              //all settings are children of symbols
              kSymbol->appendChild(lSetting);

              //SpaceGroupItem *hallNumber = new SpaceGroupItem(hallData,lSetting);
              //lSetting->appendChild(hallNumber);
              //}
              //else
              //{
               // SpaceGroupItem *hallNumber = new SpaceGroupItem(hallData,kSymbol);
                //kSymbol->appendChild(hallNumber);
              //}
            }
          }
          //all symbols are children of bravais
          jBravais->appendChild(kSymbol);
        }
        //all bravais are children of crystals
        iCrystal->appendChild(jBravais);
      }
      //each crystal is a child of root
      parent->appendChild(iCrystal);

    }
  }


}
}
