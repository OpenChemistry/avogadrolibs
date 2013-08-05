/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/


#ifndef AVOGADRO_QTPLUGINS_FILEDIALOGFILTER_H
#define AVOGADRO_QTPLUGINS_FILEDIALOGFILTER_H

#include <QSortFilterProxyModel>
#include <QRegExp>
class FileDialogModel;

class FileDialogFilter :
  public QSortFilterProxyModel
{
  Q_OBJECT

public:
  FileDialogFilter(FileDialogModel* sourceModel, QObject* Parent = NULL);
  ~FileDialogFilter();

public slots:
  void setFilter(const QString& filter);
  void setShowHidden( const bool &hidden);
  bool getShowHidden(){return m_showHidden;};

protected:
  bool filterAcceptsRow(int row_source, const QModelIndex& source_parent) const;

  FileDialogModel* m_model;
  QRegExp m_wildcards;
  bool m_showHidden;
};

#endif
