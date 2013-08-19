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

#ifndef AVOGADRO_QTPLUGINS_CONNECTIONSETTINGSDIALOG_H
#define AVOGADRO_QTPLUGINS_CONNECTIONSETTINGSDIALOG_H

#include <QtGui/QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class ConnectionSettingsDialog;
}

class ConnectionSettingsDialog : public QDialog
{
  Q_OBJECT
public:
  explicit ConnectionSettingsDialog(QWidget *parent_ = 0);
  virtual ~ConnectionSettingsDialog();

private slots:
  void testConnection();
  void updateSettings();

private:
  Ui::ConnectionSettingsDialog *m_ui;
};

} /* namespace QtPlugins */
} /* namespace Avogadro */

#endif /* AVOGADRO_QTPLUGINS_CONNECTIONSETTINGSDIALOG_H */
