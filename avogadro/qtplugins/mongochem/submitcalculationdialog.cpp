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

#include "submitcalculationdialog.h"
#include "ui_submitcalculationdialog.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>

namespace Avogadro {
namespace QtPlugins {

SubmitCalculationDialog::SubmitCalculationDialog(QWidget* parent)
  : QDialog(parent), m_ui(new Ui::SubmitCalculationDialog)
{
  m_ui->setupUi(this);
}

SubmitCalculationDialog::~SubmitCalculationDialog() = default;

int SubmitCalculationDialog::exec()
{
  // Loop until validation succeeds, or the user cancels
  while (true) {
    if (!QDialog::exec())
      return QDialog::Rejected;

    QVariantMap inputParams = inputParameters();
    if (inputParams.isEmpty()) {
      QString message = "Failed to parse input parameters";
      QMessageBox::critical(this, "MongoChem", message);
      continue;
    }

    break;
  }

  return QDialog::Accepted;
}

QString SubmitCalculationDialog::containerName() const
{
  return m_ui->container->currentText().toLower();
}

QString SubmitCalculationDialog::imageName() const
{
  return m_ui->image->text();
}

QVariantMap SubmitCalculationDialog::inputParameters() const
{
  QByteArray jsonData = m_ui->inputParameters->toPlainText().toUtf8();
  auto jsonDoc = QJsonDocument::fromJson(jsonData);
  return jsonDoc.object().toVariantMap();
}

} // namespace QtPlugins
} // namespace Avogadro
