/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H
#define AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H

#include <avogadro/core/avogadrocore.h>

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class SupercellDialog;
}

/**
 * @brief The SupercellDialog class provides a dialog for
 * building a supercell from a crystal.
 */

class SupercellDialog : public QDialog
{
  Q_OBJECT
public:
  SupercellDialog(QWidget* p = nullptr);
  ~SupercellDialog() override;

  bool buildSupercell(Avogadro::QtGui::Molecule& mol);

  void displayInvalidFormatMessage();

private:
  AVO_DISABLE_COPY(SupercellDialog)

  Ui::SupercellDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H
