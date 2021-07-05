/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PDFOPTIONSDIALOG_H
#define AVOGADRO_QTPLUGINS_PDFOPTIONSDIALOG_H

#include <QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class PdfOptionsDialog;
}

/**
 * @brief Dialog to set options for PDF curve plotting.
 */
class PdfOptionsDialog : public QDialog
{
  Q_OBJECT

public:
  explicit PdfOptionsDialog(QWidget* parent = nullptr);
  ~PdfOptionsDialog();

  double maxRadius() const;
  double step() const;

protected slots:
  void accept();

private:
  QScopedPointer<Ui::PdfOptionsDialog> m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_PDFOPTIONSDIALOG_H
