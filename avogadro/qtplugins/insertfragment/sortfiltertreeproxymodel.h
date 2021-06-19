/**********************************************************************
  SortFilterTreeProxyModel - Sorting / Filter proxy which works on trees

  This source file is part of the Avogadro project.
  See http://stackoverflow.com/questions/3212392/qtreeview-qfilesystemmodel-setrootpath-and-qsortfilterproxymodel-with-regexp-fo

  Copyright 2020 Geoffrey R. Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 ***********************************************************************/

#ifndef SORTFILTERTREEPROXYMODEL_H
#define SORTFILTERTREEPROXYMODEL_H

#include <QSortFilterProxyModel>

namespace Avogadro {

  class SortFilterTreeProxyModel: public QSortFilterProxyModel
  {
    Q_OBJECT
  public:
    SortFilterTreeProxyModel(QObject* parent = nullptr)
      : QSortFilterProxyModel(parent), m_sourceRoot()
    {}
    // From http://kodeclutz.blogspot.com/2008/12/filtering-qtreeview.html
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const;

    // This is a hack to prevent us from becoming root-less
    // See http://stackoverflow.com/questions/3212392/qtreeview-qfilesystemmodel-setrootpath-and-qsortfilterproxymodel-with-regexp-fo
    void setSourceRoot(const QModelIndex &sourceRoot)
    { m_sourceRoot = sourceRoot; }

  private:
    QModelIndex m_sourceRoot;
  };

}

#endif
