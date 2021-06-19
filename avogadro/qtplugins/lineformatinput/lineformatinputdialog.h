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

#ifndef AVOGADRO_QTPLUGINS_LINEFORMATINPUTDIALOG_H
#define AVOGADRO_QTPLUGINS_LINEFORMATINPUTDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class LineFormatInputDialog;
}

/**
 * @brief Dialog to prompt a format and descriptor string.
 */
class LineFormatInputDialog : public QDialog
{
  Q_OBJECT

public:
  explicit LineFormatInputDialog(QWidget* parent = nullptr);
  ~LineFormatInputDialog() override;

  void setFormats(const QStringList& indents);
  QString format() const;

  void setCurrentFormat(const QString& format);

  QString descriptor() const;

protected slots:
  void accept() override;

private:
  Ui::LineFormatInputDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_LINEFORMATINPUTDIALOG_H
