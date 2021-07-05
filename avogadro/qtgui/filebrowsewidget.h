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

#ifndef AVOGADRO_QTGUI_FILEBROWSEWIDGET_H
#define AVOGADRO_QTGUI_FILEBROWSEWIDGET_H

#include "avogadroqtguiexport.h"

#include <QtWidgets/QWidget>

class QFileSystemModel;
class QLineEdit;
class QPushButton;

namespace Avogadro {
namespace QtGui {

class AVOGADROQTGUI_EXPORT FileBrowseWidget : public QWidget
{
  Q_OBJECT

public:
  enum Mode
  {
    ExistingFile = 0,
    ExecutableFile
  };

  explicit FileBrowseWidget(QWidget* theParent = nullptr);
  ~FileBrowseWidget() override;

  QString fileName() const;

  bool validFileName() const { return m_valid; }

  QPushButton* browseButton() const;
  QLineEdit* lineEdit() const;

  void setMode(Mode m);
  Mode mode() const;

signals:
  void fileNameChanged(const QString& filename);

public slots:
  void setFileName(const QString& fname);

private slots:
  void browse();
  void testFileName();
  void fileNameMatch();
  void fileNameNoMatch();

private:
  /**
   * @brief Search the environment variable PATH for a file with the specified
   * name.
   * @param exec The name of the file.
   * @return The absolute path to the file on the system, or a null QString if
   * not found.
   */
  static QString searchSystemPathForFile(const QString& exec);

  Mode m_mode;
  bool m_valid;
  QFileSystemModel* m_fileSystemModel;
  QPushButton* m_button;
  QLineEdit* m_edit;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_FILEBROWSEWIDGET_H
