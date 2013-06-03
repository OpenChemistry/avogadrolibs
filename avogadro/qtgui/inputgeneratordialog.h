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

#ifndef AVOGADRO_QTGUI_INPUTGENERATORDIALOG_H
#define AVOGADRO_QTGUI_INPUTGENERATORDIALOG_H

#include <QtGui/QDialog>

#include <avogadro/core/avogadrocore.h>

#include <avogadro/qtgui/avogadroqtguiexport.h>

namespace Avogadro {
namespace QtGui {
class Molecule;

namespace Ui {
class InputGeneratorDialog;
}

class AVOGADROQTGUI_EXPORT InputGeneratorDialog : public QDialog
{
  Q_OBJECT

public:
  explicit InputGeneratorDialog(QWidget *parent_ = 0);
  explicit InputGeneratorDialog(const QString &scriptFileName,
                                QWidget *parent_ = 0);
  ~InputGeneratorDialog() AVO_OVERRIDE;

  /**
   * Use the input generator script pointed to by scriptFilePath.
   * @param scriptFilePath Absolute path to generator script.
   */
  void setInputGeneratorScript(const QString &scriptFilePath);

public slots:
  /**
   * Set the molecule used in the simulation.
   */
  void setMolecule(QtGui::Molecule *mol);

private:
  Ui::InputGeneratorDialog *ui;
};


} // namespace QtGui
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_INPUTGENERATORDIALOG_H
