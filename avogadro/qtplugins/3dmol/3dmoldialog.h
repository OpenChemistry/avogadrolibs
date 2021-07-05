/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Barry E Moore II

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTGUI_ThreeDMOLDIALOG_H
#define AVOGADRO_QTGUI_ThreeDMOLDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class ThreeDMolDialog;
}

/**
 * @class ThreeDMolDialog 3dmoldialog.h <avogadrolibs/qtgui/3dmoldialog.h>
 * @brief The ThreeDMolDialog class provides a dialog which displays
 * basic molecular properties.
 * @author Barry E. Moore II
 *
 * @todo IUPAC name fetch (need inchi key).
 */
class ThreeDMolDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ThreeDMolDialog(QtGui::Molecule* mol, QWidget* parent_ = nullptr);
  ~ThreeDMolDialog() override;

  QtGui::Molecule* molecule() { return m_molecule; }

public slots:
  void setMolecule(QtGui::Molecule* mol);

private slots:
  void updateLabels();
  void updateTextBrowser();
  void moleculeDestroyed();
  void copyToClipboard();

private:
  QtGui::Molecule* m_molecule;
  Ui::ThreeDMolDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_ThreeDMOLDIALOG_H
