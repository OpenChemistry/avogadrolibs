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

#ifndef AVOGADRO_QTPLUGINS_YAEHMOPBANDDIALOG_H
#define AVOGADRO_QTPLUGINS_YAEHMOPBANDDIALOG_H

#include <memory>

#include <QDialog>

#include "yaehmopsettings.h"

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class BandDialog;
}

/**
 * @brief Dialog to perform a band structure calculation with yaehmop.
 */
class BandDialog : public QDialog
{
  Q_OBJECT

public:
  explicit BandDialog(QWidget* parent, YaehmopSettings& yaehmopSettings);
  ~BandDialog();

public slots:
  int exec() override;

protected slots:
  void accept() override;

private:
  std::unique_ptr<Ui::BandDialog> m_ui;
  YaehmopSettings& m_yaehmopSettings;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_YAEHMOPBANDDIALOG_H
