/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

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
