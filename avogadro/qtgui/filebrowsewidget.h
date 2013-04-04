/******************************************************************************

  This source file is part of the MoleQueue project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTGUI_FILEBROWSEWIDGET_H
#define AVOGADRO_QTGUI_FILEBROWSEWIDGET_H

#include "avogadroqtguiexport.h"

#include <QtGui/QWidget>

class QLineEdit;
class QPushButton;

namespace Avogadro {
namespace QtGui {

class AVOGADROQTGUI_EXPORT FileBrowseWidget : public QWidget
{
  Q_OBJECT

public:
  explicit FileBrowseWidget(QWidget *theParent = 0);
  ~FileBrowseWidget();

  QString fileName() const;

  QPushButton *browseButton() const;
  QLineEdit *lineEdit() const;

public slots:
  void setFileName(const QString &fname);

private slots:
  void browse();
  void testFileName();
  void fileNameMatch();
  void fileNameNoMatch();

private:
  QPushButton *m_button;
  QLineEdit *m_edit;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_FILEBROWSEWIDGET_H
