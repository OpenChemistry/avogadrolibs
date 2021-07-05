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

#ifndef AVOGADRO_QTPLUGINS_INSERTFRAGMENTDIALOG_H
#define AVOGADRO_QTPLUGINS_INSERTFRAGMENTDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class InsertFragmentDialog;
}

/**
 * @brief Dialog to prompt a format and descriptor string.
 */
class InsertFragmentDialog : public QDialog
{
  Q_OBJECT

public:
  explicit InsertFragmentDialog(QWidget* parent = nullptr,
                                QString directory = "molecules",
                                Qt::WindowFlags f = 0);
  ~InsertFragmentDialog() override;

  const QString fileName();

public Q_SLOTS:
  void refresh();

  void filterTextChanged(const QString &);

  void activated();

Q_SIGNALS:
  void performInsert(const QString &fileName);

private:
  Ui::InsertFragmentDialog* m_ui;

  class Private;
  Private *m_implementation;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_InsertFragmentDIALOG_H
