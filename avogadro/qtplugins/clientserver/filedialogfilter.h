/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_FILEDIALOGFILTER_H
#define AVOGADRO_QTPLUGINS_FILEDIALOGFILTER_H

#include <QRegExp>
#include <QSortFilterProxyModel>
class FileDialogModel;

/**
 * @class FileDialogFilter filedialogfilter.h
 * <avogadro/qtplugins/clientserver/filedialogfilter.h>
 * @brief Filter used to filter data in file dialog model
 */
class FileDialogFilter : public QSortFilterProxyModel
{
  Q_OBJECT

public:
  FileDialogFilter(FileDialogModel* sourceModel, QObject* Parent = nullptr);
  ~FileDialogFilter();

public slots:
  void setFilter(const QString& filter);
  void setShowHidden(const bool& hidden);
  bool getShowHidden() { return m_showHidden; };

protected:
  bool filterAcceptsRow(int row_source, const QModelIndex& source_parent) const;

  FileDialogModel* m_model;
  QRegExp m_wildcards;
  bool m_showHidden;
};

#endif
