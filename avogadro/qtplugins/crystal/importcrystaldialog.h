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

#ifndef AVOGADRO_QTPLUGINS_IMPORTCRYSTALDIALOG_H
#define AVOGADRO_QTPLUGINS_IMPORTCRYSTALDIALOG_H

#include <avogadro/core/avogadrocore.h>

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class ImportCrystalDialog;
}

/**
 * @brief The ImportCrystalDialog class provides a dialog for importing
 * a crystal from the clipboard.
 */

class ImportCrystalDialog : public QDialog
{
  Q_OBJECT
public:
  ImportCrystalDialog(QWidget* p = nullptr);
  ~ImportCrystalDialog() override;

  // Avogadro::Core::Molecule is required for the format function
  bool importCrystalClipboard(Avogadro::Core::Molecule& mol);

  void displayInvalidFormatMessage();

private:
  AVO_DISABLE_COPY(ImportCrystalDialog)

  Ui::ImportCrystalDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_IMPORTCRYSTALDIALOG_H
