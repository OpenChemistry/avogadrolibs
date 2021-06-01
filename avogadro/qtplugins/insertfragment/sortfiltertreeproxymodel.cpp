/**********************************************************************
  SortFilterTreeProxyModel - Sorting / Filter proxy which works on trees

  Based on code from http://kodeclutz.blogspot.com/2008/12/filtering-qtreeview.html

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.openmolecules.net/>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 ***********************************************************************/

#include "sortfiltertreeproxymodel.h"

#include <QDebug>

namespace Avogadro {

  // Custom class for Avogadro to handle filtering files
  // Directories are at most 2 levels deep until we get to files
  bool SortFilterTreeProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
  {
    // First we see if we're the source root node
    QModelIndex sourceIndex = sourceModel()->index(sourceRow, 0, sourceParent);
    if (!sourceIndex.isValid() || !sourceParent.isValid())
      return true; // viewer will handle filtering
    // Make sure the root is always accepted, or we become rootless
    // See http://stackoverflow.com/questions/3212392/qtreeview-qfilesystemmodel-setrootpath-and-qsortfilterproxymodel-with-regexp-fo
    if (m_sourceRoot.isValid() && sourceIndex == m_sourceRoot) {
      return true; // true root, always accept
    }

    // Now we see if we're a child of the root
    // If not, we accept -- only filter under *our* tree
    // Along the way, we'll see if a parent matches the filter
    if (sourceParent != m_sourceRoot) {
      bool childOfRoot = false;
      QModelIndex parent = sourceParent;
      for (int depth = 3; depth > 0; depth--) {
        if (sourceModel()->data(parent).toString().contains(filterRegExp()))
          return true; // a parent matches the pattern

        parent = parent.parent();
        if (!parent.isValid())
          return true; // tree view handles filtering, and we ascended too far
        if (parent == m_sourceRoot) {
          childOfRoot = true;
          break;
        }
      }
      // OK, we've gone up the tree, did we find our root?
      if (!childOfRoot)
        return true;
    }
    // else, sourceParent is a root, so we're good to filter

    // Check if the data for this row matches. If so, the default is to accept
    QString data = sourceModel()->data(sourceIndex).toString();
    if (data.contains(filterRegExp()))
      return true;

    // Now we have to check the child nodes
    // We'll show the row if any child is accepted
    // (i.e., if a file matches, we'll show the directory path to it)
    // Try to fetchMore() first
    sourceModel()->fetchMore(sourceIndex);
    for(int i = 0; i < sourceModel()->rowCount(sourceIndex); ++i) {
      QModelIndex subRow = sourceModel()->index(i, 0, sourceIndex);
      if (!subRow.isValid())
        continue;

      QString rowData = sourceModel()->data(subRow).toString();
      if (rowData.contains(filterRegExp()))
        return true;
    }
    return false; // nothing matched
  }

}
