/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTGUI_MOLECULARPROPERTIESDIALOG_H
#define AVOGADRO_QTGUI_MOLECULARPROPERTIESDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class MolecularPropertiesDialog;
}

/**
 * @class MolecularPropertiesDialog molecularpropertiesdialog.h
 * <avogadrolibs/qtgui/molecularpropertiesdialog.h>
 * @brief The MolecularPropertiesDialog class provides a dialog which displays
 * basic molecular properties.
 * @author Allison Vacanti
 *
 * @todo IUPAC name fetch (need inchi key).
 */
class MolecularPropertiesDialog : public QDialog
{
  Q_OBJECT

public:
  explicit MolecularPropertiesDialog(QtGui::Molecule* mol,
                                     QWidget* parent_ = nullptr);
  ~MolecularPropertiesDialog() override;

  QtGui::Molecule* molecule() { return m_molecule; }

public slots:
  void setMolecule(QtGui::Molecule* mol);

private slots:
  void updateLabels();
  void updateMassLabel();
  void updateFormulaLabel();
  void moleculeDestroyed();

private:
  QtGui::Molecule* m_molecule;
  Ui::MolecularPropertiesDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_MOLECULARPROPERTIESDIALOG_H
