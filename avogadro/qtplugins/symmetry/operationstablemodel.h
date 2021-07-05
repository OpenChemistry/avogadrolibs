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

#ifndef AVOGADRO_QTPLUGINS_OPERATIONSTABLEMODEL_H
#define AVOGADRO_QTPLUGINS_OPERATIONSTABLEMODEL_H

namespace msym {
extern "C"
{
#include <libmsym/msym.h>
}
}

#include <QAbstractTableModel>
#include <QStyledItemDelegate>
#include <QTextDocument>

#define OPERATIONSTABLEMODEL_COLUMN_COUNT 3

namespace Avogadro {
namespace QtPlugins {

class OperationsTableModel : public QAbstractTableModel
{
  Q_OBJECT

public:
  enum Column
  {
    ColumnType = 0,
    ColumnClass = 1,
    ColumnVector = 2
  };

  explicit OperationsTableModel(QObject* parent = nullptr);
  ~OperationsTableModel() override;

  int rowCount(const QModelIndex&) const override { return m_operations_size; };
  int columnCount(const QModelIndex&) const override
  {
    return OPERATIONSTABLEMODEL_COLUMN_COUNT;
  };

  QVariant data(const QModelIndex& index,
                int role = Qt::DisplayRole) const override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role) const override;

  void setOperations(int operations_size,
                     const msym::msym_symmetry_operation_t* operations);
  void clearOperations();

private:
  const msym::msym_symmetry_operation_t* m_operations;
  int m_operations_size;
};
}
}
#endif // AVOGADRO_QTPLUGINS_OPERATIONSTABLEMODEL_H
