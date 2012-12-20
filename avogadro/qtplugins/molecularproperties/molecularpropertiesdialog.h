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

#include <QtGui/QDialog>

#include "avogadroqtguiexport.h"

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class MolecularPropertiesDialog;
}

/**
 * @class MolecularPropertiesDialog molecularpropertiesdialog.h <avogadrolibs/qtgui/molecularpropertiesdialog.h>
 * @brief The MolecularPropertiesDialog class provides a dialog which displays
 * basic molecular properties.
 * @author David C. Lonie
 *
 * @todo This class will need to be updated with the QObject molecule: connect
 * destroyed() to moleculeDestroyed(), and moleculeChanged() to updateLabels().
 * @todo IUPAC name fetch (need inchi key).
 */
class AVOGADROQTGUI_EXPORT MolecularPropertiesDialog : public QDialog
{
  Q_OBJECT

public:
  explicit MolecularPropertiesDialog(Core::Molecule *mol, QWidget *parent_ = 0);
  ~MolecularPropertiesDialog();

  Core::Molecule* molecule() { return m_molecule; }

public slots:
  void setMolecule(Core::Molecule *mol);

private slots:
  void updateLabels();
  void moleculeDestroyed();

private:
  Core::Molecule *m_molecule;
  Ui::MolecularPropertiesDialog *m_ui;
};


} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_MOLECULARPROPERTIESDIALOG_H
