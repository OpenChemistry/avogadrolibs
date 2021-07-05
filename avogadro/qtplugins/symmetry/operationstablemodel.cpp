/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Marcus Johansson <mcodev31@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "operationstablemodel.h"
#include "symmetryutil.h"

using namespace Avogadro::QtPlugins::SymmetryUtil;

namespace Avogadro {
namespace QtPlugins {

OperationsTableModel::OperationsTableModel(QObject* parent)
  : QAbstractTableModel(parent)
{
  m_operations = nullptr;
  m_operations_size = 0;
}

OperationsTableModel::~OperationsTableModel()
{
}

void OperationsTableModel::setOperations(
  int operations_size, const msym::msym_symmetry_operation_t* operations)
{
  beginResetModel();
  m_operations_size = operations_size;
  m_operations = operations;
  endResetModel();
}

/* Qt */

QVariant OperationsTableModel::headerData(int section,
                                          Qt::Orientation orientation,
                                          int role) const
{

  if (role != Qt::DisplayRole)
    return QVariant();

  QString name;

  if (orientation == Qt::Horizontal) {
    switch (Column(section)) {
      case ColumnType:
        return tr("Type");
      case ColumnClass:
        return tr("Class");
      case ColumnVector:
        return tr("Element");
      default:
        return QVariant();
    }
  } else {
    return QString::number(section + 1);
  }
}

QVariant OperationsTableModel::data(const QModelIndex& index, int role) const
{
  if (role != Qt::DisplayRole || !index.isValid())
    return QVariant();

  const msym::msym_symmetry_operation_t* operation = &m_operations[index.row()];

  switch (Column(index.column())) {
    case ColumnType:
      return operationSymbol(operation);
    case ColumnClass:
      return operation->cla;
    case ColumnVector:
      return QString("NA");
    default:
      return QVariant();
  }
}
}
}
