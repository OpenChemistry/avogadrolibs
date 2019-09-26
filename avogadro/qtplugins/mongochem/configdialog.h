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

#ifndef AVOGADRO_QTPLUGINS_CONFIGDIALOG_H
#define AVOGADRO_QTPLUGINS_CONFIGDIALOG_H

#include <QDialog>
#include <QScopedPointer>

namespace Ui {
class ConfigDialog;
}

namespace Avogadro {
namespace QtPlugins {

class ConfigDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ConfigDialog(QWidget* parent = nullptr);
  ~ConfigDialog();

  void setGirderUrl(const QString& url);
  void setApiKey(const QString& apiKey);

  QString girderUrl() const;
  QString apiKey() const;

private:
  QScopedPointer<Ui::ConfigDialog> m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CONFIGDIALOG_H
