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

#ifndef AVOGADRO_QTPLUGINS_XRDOPTIONSDIALOG_H
#define AVOGADRO_QTPLUGINS_XRDOPTIONSDIALOG_H

#include <memory>

#include <QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class XrdOptionsDialog;
}

/**
 * @brief Dialog to set options for a theoretical XRD pattern calculation.
 */
class XrdOptionsDialog : public QDialog
{
  Q_OBJECT

public:
  explicit XrdOptionsDialog(QWidget* parent = nullptr);
  ~XrdOptionsDialog();

  double wavelength() const;
  double peakWidth() const;
  size_t numDataPoints() const;
  double max2Theta() const;

protected slots:
  void accept();

private:
  std::unique_ptr<Ui::XrdOptionsDialog> m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_XRDOPTIONSDIALOG_H
