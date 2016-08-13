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

#ifndef AVOGADRO_QTGUI_GENERALPROPERTIESDIALOG_H
#define AVOGADRO_QTGUI_GENERALPROPERTIESDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class GeneralPropertiesDialog;
}

/**
 * @class GeneralPropertiesDialog generalpropertiesdialog.h <avogadrolibs/qtgui/generalpropertiesdialog.h>
 * @brief The GeneralPropertiesDialog class provides a dialog which displays
 * basic molecular properties.
 * @author David C. Lonie
 *
 * @todo IUPAC name fetch (need inchi key).
 */
class GeneralPropertiesDialog : public QDialog
{
  Q_OBJECT

public:
  explicit GeneralPropertiesDialog(QtGui::Molecule *mol, QWidget *parent_ = 0);
  ~GeneralPropertiesDialog();

  QtGui::Molecule* molecule() { return m_molecule; }

public slots:
  void setMolecule(QtGui::Molecule *mol);

private slots:
  void updateLabels();
  void updateMassLabel();
  void updateFormulaLabel();
  void moleculeDestroyed();

private:
  QtGui::Molecule *m_molecule;
  Ui::GeneralPropertiesDialog *m_ui;
};


} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_GENERALPROPERTIESDIALOG_H
