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

#ifndef AVOGADRO_QTGUI_ENERGYPROPERTIESDIALOG_H
#define AVOGADRO_QTGUI_ENERGYPROPERTIESDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class EnergyPropertiesDialog;
}

/**
 * @class EnergyPropertiesDialog energypropertiesdialog.h <avogadrolibs/qtgui/energypropertiesdialog.h>
 * @brief The EnergyPropertiesDialog class provides a dialog which displays
 * basic molecular properties.
 * @author David C. Lonie
 *
 * @todo IUPAC name fetch (need inchi key).
 */
class EnergyPropertiesDialog : public QDialog
{
  Q_OBJECT

public:
  explicit EnergyPropertiesDialog(QtGui::Molecule *mol, QWidget *parent_ = 0);
  ~EnergyPropertiesDialog();

  QtGui::Molecule* molecule() { return m_molecule; }

public slots:
  void setMolecule(QtGui::Molecule *mol);

private slots:
  void updateLabels();
  void moleculeDestroyed();

private:
  QtGui::Molecule *m_molecule;
  Ui::EnergyPropertiesDialog *m_ui;
};


} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_ENERGYPROPERTIESDIALOG_H
