/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SUBMITCALCULATIONDIALOG_H
#define AVOGADRO_QTPLUGINS_SUBMITCALCULATIONDIALOG_H

#include <QDialog>

namespace Ui {
class SubmitCalculationDialog;
}

namespace Avogadro {
namespace QtPlugins {

class SubmitCalculationDialog : public QDialog
{
  Q_OBJECT

public:
  explicit SubmitCalculationDialog(QWidget* parent = nullptr);
  ~SubmitCalculationDialog();

  int exec() override;

  QString containerName() const;
  QString imageName() const;
  QVariantMap inputParameters() const;

private:
  QScopedPointer<Ui::SubmitCalculationDialog> m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SUBMITCALCULATIONDIALOG_H
