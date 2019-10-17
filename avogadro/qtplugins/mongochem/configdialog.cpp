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

#include "configdialog.h"
#include "ui_configdialog.h"

namespace Avogadro {
namespace QtPlugins {

ConfigDialog::ConfigDialog(QWidget* parent)
  : QDialog(parent), m_ui(new Ui::ConfigDialog)
{
  m_ui->setupUi(this);
}

ConfigDialog::~ConfigDialog() = default;

void ConfigDialog::setGirderUrl(const QString& girderUrl)
{
  m_ui->girderUrl->setText(girderUrl);
}

void ConfigDialog::setApiKey(const QString& apiKey)
{
  m_ui->apiKey->setText(apiKey);
}

QString ConfigDialog::girderUrl() const
{
  QString url = m_ui->girderUrl->text();
  if (!url.endsWith("/api/v1")) {
    // Append this automatically...
    url += "/api/v1";
  }
  return url;
}

QString ConfigDialog::apiKey() const
{
  return m_ui->apiKey->text();
}

} // namespace QtPlugins
} // namespace Avogadro
