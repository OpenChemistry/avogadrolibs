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

#include "filedialogfilter.h"

#include <QFileIconProvider>
#include <QIcon>
#include <QStringBuilder>

#include "filedialogmodel.h"

FileDialogFilter::FileDialogFilter(FileDialogModel* model, QObject* Parent)
  : QSortFilterProxyModel(Parent), m_model(model), m_showHidden(false)
{
  setSourceModel(model);
  m_wildcards.setPatternSyntax(QRegExp::RegExp2);
  m_wildcards.setCaseSensitivity(Qt::CaseSensitive);
}

FileDialogFilter::~FileDialogFilter()
{
}

#include <stdio.h>

void FileDialogFilter::setFilter(const QString& filter)
{
  QString f(filter);
  // if we have (...) in our filter, strip everything out but the contents of ()
  int start, end;
  end = filter.lastIndexOf(')');
  start = filter.lastIndexOf('(', end);
  if (start != -1 && end != -1)
    f = f.mid(start + 1, end - start - 1);

  QString pattern = ".*";
  if (f != "*") {
    f = f.trimmed();

    // convert all spaces into |
    f.replace(QRegExp("[\\s+;]+"), "|");

    QStringList strings = f.split("|");
    QStringList extensions_list, filepatterns_list;
    foreach (QString string, strings) {
      if (string.startsWith("*."))
        extensions_list.push_back(string.remove(0, 2));
      else
        filepatterns_list.push_back(string);
    }

    QString extensions = extensions_list.join("|");
    QString filepatterns = filepatterns_list.join("|");

    extensions.replace(".", "\\.");
    extensions.replace("*", ".*");

    filepatterns.replace(".", "\\.");
    filepatterns.replace("*", ".*");

    // use non capturing(?:) for speed
    // name.ext or ext.001 or name.ext001 (for bug #10101)
    QString postExtFileSeries("(\\.?\\d+)?$"); // match the .0001 component
    QString extGroup = ".*\\.(?:" % extensions % ")" % postExtFileSeries;
    QString fileGroup = "(?:" % filepatterns % ")" % postExtFileSeries;
    if (extensions_list.size() > 0 && filepatterns_list.size() > 0)
      pattern = "(?:" % fileGroup % "|" % extGroup % ")";
    else if (extensions_list.size() > 0)
      pattern = extGroup;
    else
      pattern = fileGroup;
  }

  m_wildcards.setPattern(pattern);
  invalidateFilter();
}

void FileDialogFilter::setShowHidden(const bool& hidden)
{
  if (m_showHidden != hidden) {
    m_showHidden = hidden;
    invalidateFilter();
  }
}

bool FileDialogFilter::filterAcceptsRow(int row_source,
                                        const QModelIndex& source_parent) const
{
  QModelIndex idx = m_model->index(row_source, 0, source_parent);

  // hidden flag supersedes anything else
  if (m_model->isHidden(idx) && !m_showHidden)
    return false;

  if (m_model->isDir(idx)) {
    QString str = sourceModel()->data(idx).toString();
    return true;
  }

  if (source_parent.isValid()) {
    // if source_parent is valid, then the item is an element in a file-group.
    // For file-groups, we use pass any file in a group, if the group's label
    // passes the test (BUG #13179).
    QString str = sourceModel()->data(source_parent).toString();
    return m_wildcards.exactMatch(str);
  } else {
    QString str = sourceModel()->data(idx).toString();
    return m_wildcards.exactMatch(str);
  }
}
