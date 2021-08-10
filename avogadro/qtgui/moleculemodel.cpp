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

#include "molecule.h"
#include "moleculemodel.h"

#include <QtCore/QFileInfo>
#include <QtGui/QColor>
#include <QtGui/QIcon>

namespace Avogadro {
namespace QtGui {

MoleculeModel::MoleculeModel(QObject* p)
  : QAbstractItemModel(p), m_activeMolecule(nullptr)
{}

QModelIndex MoleculeModel::parent(const QModelIndex&) const
{
  return QModelIndex();
}

int MoleculeModel::rowCount(const QModelIndex& p) const
{
  if (p.isValid())
    return 0;
  else
    return m_molecules.size();
}

int MoleculeModel::columnCount(const QModelIndex&) const
{
  return 2;
}

Qt::ItemFlags MoleculeModel::flags(const QModelIndex& idx) const
{
  if (idx.column() == 0)
    return static_cast<Qt::ItemFlags>(Qt::ItemIsEditable | Qt::ItemIsEnabled);
  else
    return Qt::ItemIsEnabled;
}

bool MoleculeModel::setData(const QModelIndex& idx, const QVariant& value,
                            int role)
{
  if (!idx.isValid() || idx.column() > 2)
    return false;

  QObject* object = static_cast<QObject*>(idx.internalPointer());
  Molecule* mol = qobject_cast<Molecule*>(object);
  if (!mol)
    return false;

  switch (role) {
    case Qt::CheckStateRole:
      m_activeMolecule = mol;
      if (value == Qt::Checked /*&& !item->isEnabled()*/) {
        // item->setEnabled(true);
        emit moleculeStateChanged(mol);
      } else if (value == Qt::Unchecked /*&& item->isEnabled()*/) {
        // item->setEnabled(false);
        emit moleculeStateChanged(mol);
      }
      emit dataChanged(idx, idx);
      return true;
    case Qt::EditRole:
      if (!value.toString().isEmpty()) {
        // don't set an empty name
        mol->setData("name", std::string(value.toString().toLatin1()));
        emit dataChanged(idx, idx);
      }
      return true;
  }
  return false;
}

QVariant MoleculeModel::data(const QModelIndex& idx, int role) const
{
  if (!idx.isValid() || idx.column() > 2)
    return QVariant();

  QObject* object = static_cast<QObject*>(idx.internalPointer());
  Molecule* mol = qobject_cast<Molecule*>(object);
  if (!mol)
    return QVariant();

  if (idx.column() == 0) {
    switch (role) {
      case Qt::DisplayRole: {
        std::string name = tr("Untitled").toStdString();
        if (mol && mol->hasData("name") &&
            !(mol->data("name").toString().empty())) {
          // don't set an empty name
          name = mol->data("name").toString();
        } else if (mol && mol->hasData("fileName")) {
          name = QFileInfo(mol->data("fileName").toString().c_str())
                   .fileName()
                   .toStdString();
        }
        if (mol)
          return (name + " (" + mol->formula() + ")").c_str();
        else
          return "Edit molecule";
      }
      case Qt::EditRole:
        return mol->data("name").toString().c_str();
      case Qt::ToolTipRole:
        if (mol->hasData("fileName"))
          return mol->data("fileName").toString().c_str();
        return "Not saved";
      case Qt::WhatsThisRole:
        return mol->formula().c_str();
      case Qt::ForegroundRole:
        if (mol == m_activeMolecule)
          return QVariant(QColor(Qt::red));
        else
          return QVariant(QColor(Qt::black));
      default:
        return QVariant();
    }
  } else if (idx.column() == 1) {
    if (role == Qt::DecorationRole)
      return QIcon(":/icons/fallback/32x32/edit-delete.png");
  }
  return QVariant();
}

QModelIndex MoleculeModel::index(int row, int column,
                                 const QModelIndex& p) const
{
  if (!p.isValid())
    if (row >= 0 && row < m_molecules.size())
      return createIndex(row, column, m_molecules[row]);
  return QModelIndex();
}

void MoleculeModel::clear()
{
  m_molecules.clear();
}

QList<Molecule*> MoleculeModel::molecules() const
{
  return m_molecules;
}

QList<Molecule*> MoleculeModel::activeMolecules() const
{
  QList<Molecule*> result;
  foreach (Molecule* mol, m_molecules) {
    if (true)
      result << mol;
  }
  return result;
}

void MoleculeModel::setActiveMolecule(QObject* active)
{
  if (m_activeMolecule == active)
    return;
  m_activeMolecule = active;
  emit dataChanged(createIndex(0, 0), createIndex(m_molecules.size(), 0));
}

void MoleculeModel::addItem(Molecule* item)
{
  if (!m_molecules.contains(item)) {
    int row = m_molecules.size();
    beginInsertRows(QModelIndex(), row, row);
    m_molecules.append(item);
    item->setParent(this);
    endInsertRows();
  }
}

void MoleculeModel::removeItem(Molecule* item)
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
  Molecule* item = qobject_cast<Molecule*>(sender());
  if (item) {
    int row = m_molecules.indexOf(item);
    if (row >= 0)
      emit dataChanged(createIndex(row, 0), createIndex(row, 0));
  }
}

} // namespace QtGui
} // namespace Avogadro
