/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013-2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "moleculemodel.h"
#include "molecule.h"

namespace Avogadro {
namespace QtGui {

MoleculeModel::MoleculeModel(QObject *parent_)
  : QAbstractItemModel(parent_)
{
}

QModelIndex MoleculeModel::parent(const QModelIndex &) const
{
  return QModelIndex();
}

int MoleculeModel::rowCount(const QModelIndex &parent_) const
{
  if (parent_.isValid())
    return 0;
  else
    return m_molecules.size();
}

int MoleculeModel::columnCount(const QModelIndex &) const
{
  return 1;
}

Qt::ItemFlags MoleculeModel::flags(const QModelIndex &idx) const
{
    if (idx.column() == 0) {
      return static_cast<Qt::ItemFlags>(Qt::ItemIsEditable | Qt::ItemIsEnabled);
    }
    else {
      return Qt::ItemIsEnabled;
    }
}

bool MoleculeModel::setData(const QModelIndex &index_, const QVariant &value,
                            int role)
{
  if (!index_.isValid() || index_.column() > 1)
    return false;

  Molecule *item =
    qobject_cast<Molecule *>(static_cast<QObject *>(index_.internalPointer()));
  if (!item)
    return false;

  switch (role) {
  case Qt::CheckStateRole:
    if (value == Qt::Checked /*&& !item->isEnabled()*/) {
      //item->setEnabled(true);
      emit moleculeStateChanged(item);
    }
    else if (value == Qt::Unchecked /*&& item->isEnabled()*/) {
      //item->setEnabled(false);
      emit moleculeStateChanged(item);
    }
    emit dataChanged(index_, index_);
    return true;
  case Qt::EditRole:
    item->setData("name", std::string(value.toString().toLatin1()));
    emit dataChanged(index_, index_);
    return true;
  }
  return false;
}

QVariant MoleculeModel::data(const QModelIndex &index_, int role) const
{
  if (!index_.isValid() || index_.column() > 1)
    return QVariant();

  QObject *object = static_cast<QObject *>(index_.internalPointer());
  Molecule *item = qobject_cast<Molecule *>(object);
  if (!item)
    return QVariant();

  if (index_.column() == 0) {
    switch (role) {
    case Qt::DisplayRole: {
      std::string name = "Untitled";
      if (item->hasData("name"))
        name = item->data("name").toString();
      return (name + " (" + item->formula() + ")").c_str();
    }
    case Qt::EditRole:
      return item->data("name").toString().c_str();
    case Qt::ToolTipRole:
      if (item->hasData("fileName"))
        return item->data("fileName").toString().c_str();
      return "Not saved";
    case Qt::WhatsThisRole:
      return item->formula().c_str();
    default:
      return QVariant();
    }
  }
  return QVariant();
}

QModelIndex MoleculeModel::index(int row, int column,
                                 const QModelIndex &parent_) const
{
  if (!parent_.isValid() && row >= 0 && row < m_molecules.size())
    return createIndex(row, column, m_molecules[row]);
  else
    return QModelIndex();
}

void MoleculeModel::clear()
{
  m_molecules.clear();
}

QList<Molecule *> MoleculeModel::molecules() const
{
  return m_molecules;
}

QList<Molecule *> MoleculeModel::activeMolecules() const
{
  QList<Molecule *> result;
  foreach (Molecule *mol, m_molecules) {
    if (true)
      result << mol;
  }
  return result;
}

void MoleculeModel::addItem(Molecule *item)
{
  if (!m_molecules.contains(item)) {
    int row = m_molecules.size();
    beginInsertRows(QModelIndex(), row, row);
    m_molecules.append(item);
    item->setParent(this);
    endInsertRows();
  }
}

void MoleculeModel::removeItem(Molecule *item)
{
  if (m_molecules.contains(item)) {
    int row = m_molecules.indexOf(item);
    beginRemoveRows(QModelIndex(), row, row);
    m_molecules.removeAt(row);
    // Do we want strong ownership of molecules?
    item->deleteLater();
    endRemoveRows();
  }
}

void MoleculeModel::itemChanged()
{
  Molecule *item = qobject_cast<Molecule *>(sender());
  if (item) {
    int row = m_molecules.indexOf(item);
    if (row >= 0)
      emit dataChanged(createIndex(row, 0), createIndex(row, 0));
  }
}

} // End QtGui namespace
} // End Avogadro namespace
