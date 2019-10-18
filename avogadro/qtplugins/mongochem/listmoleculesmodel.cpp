/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "listmoleculesmodel.h"

namespace Avogadro {
namespace QtPlugins {

ListMoleculesModel::ListMoleculesModel(QObject* parent)
  : QAbstractTableModel(parent)
{}

int ListMoleculesModel::rowCount(const QModelIndex& id) const
{
  Q_UNUSED(id)
  return m_molecules.size();
}

int ListMoleculesModel::columnCount(const QModelIndex& /*parent*/) const
{
  return 3;
}

QVariant ListMoleculesModel::data(const QModelIndex& index, int role) const
{
  if (!index.isValid())
    return QVariant();

  switch (role) {
    case Qt::DisplayRole: {
      const auto& mol = m_molecules[index.row()];
      int column = index.column();
      switch (column) {
        case 0:
          return mol.value("properties").toMap().value("formula");
        case 1:
          return mol.value("smiles");
        case 2:
          return mol.value("inchikey");
        default:
          return QVariant();
      }
    }
  }

  return QVariant();
}

Qt::ItemFlags ListMoleculesModel::flags(const QModelIndex& index) const
{
  return QAbstractTableModel::flags(index);
}

QVariant ListMoleculesModel::headerData(int section,
                                        Qt::Orientation orientation,
                                        int role) const
{
  if (role != Qt::DisplayRole)
    return QVariant();

  if (orientation == Qt::Vertical)
    return section + 1;

  if (orientation == Qt::Horizontal) {
    switch (section) {
      case 0:
        return tr("Formula");

      case 1:
        return tr("SMILES");

      case 2:
        return tr("InChIKey");
    }
  }

  return QVariant();
}

QString ListMoleculesModel::moleculeId(int row)
{
  return m_molecules[row]["_id"].toString();
}

QString ListMoleculesModel::moleculeName(int row)
{
  auto name = m_molecules[row]["name"].toString();

  // If there is no name, use the formula instead
  if (name.isEmpty())
    name = m_molecules[row]["properties"].toMap()["formula"].toString();

  return name;
}

void ListMoleculesModel::addMolecule(const QVariantMap& mol)
{
  beginInsertRows(QModelIndex(), m_molecules.size(), m_molecules.size());
  m_molecules.append(mol);
  endInsertRows();
}

void ListMoleculesModel::deleteMolecule(const QModelIndex& index)
{
  if (!index.isValid())
    return;

  int row = index.row();
  if (row < m_molecules.size()) {
    beginRemoveRows(QModelIndex(), row, row);
    m_molecules.removeAt(row);
    endRemoveRows();
  }
}

void ListMoleculesModel::clear()
{
  int lastRow = m_molecules.isEmpty() ? 0 : m_molecules.size() - 1;
  beginRemoveRows(QModelIndex(), 0, lastRow);
  m_molecules.clear();
  endRemoveRows();
}

} // namespace QtPlugins
} // namespace Avogadro
