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

#ifndef AVOGADRO_QTPLUGINS_OBFORCEFIELDDIALOG_H
#define AVOGADRO_QTPLUGINS_OBFORCEFIELDDIALOG_H

#include <QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class OBForceFieldDialog;
}

/// @todo Document this.
class OBForceFieldDialog : public QDialog
{
  Q_OBJECT

public:
  explicit OBForceFieldDialog(const QStringList &forceFields,
                              QWidget *parent_ = 0);
  ~OBForceFieldDialog();

  static QStringList prompt(QWidget *parent_,  const QStringList &forceFields,
                            const QStringList &startingOptions);

  QStringList options() const;

  void setOptions(const QStringList &opts);

private:
  Ui::OBForceFieldDialog *ui;
};


} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_OBFORCEFIELDDIALOG_H
