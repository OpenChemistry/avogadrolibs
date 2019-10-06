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

#ifndef AVOGADRO_QTPLUGINS_LISTMOLECULESMODEL_H
#define AVOGADRO_QTPLUGINS_LISTMOLECULESMODEL_H

#include <QAbstractTableModel>
#include <QList>
#include <QVariantMap>

namespace Avogadro {
namespace QtPlugins {

class ListMoleculesModel : public QAbstractTableModel
{
  Q_OBJECT

public:
  ListMoleculesModel(QObject* parent = nullptr);
  int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  int columnCount(const QModelIndex& parent = QModelIndex()) const override;
  QVariant data(const QModelIndex& index,
                int role = Qt::DisplayRole) const override;
  Qt::ItemFlags flags(const QModelIndex& index) const override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role) const override;

  QString moleculeId(int row);
  QString moleculeName(int row);
  void addMolecule(const QVariantMap& molecule);
  void deleteMolecule(const QModelIndex& index);
  void clear();

private:
  QList<QVariantMap> m_molecules;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif
