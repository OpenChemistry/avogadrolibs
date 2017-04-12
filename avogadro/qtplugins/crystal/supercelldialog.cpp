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

#include "supercelldialog.h"
#include "ui_supercelldialog.h"

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/molecule.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

using Avogadro::Core::CrystalTools;

namespace Avogadro {
namespace QtPlugins {

SupercellDialog::SupercellDialog(QWidget* p)
  : QDialog(p), m_ui(new Ui::SupercellDialog)
{
  m_ui->setupUi(this);
}

SupercellDialog::~SupercellDialog()
{
  delete m_ui;
}

bool SupercellDialog::buildSupercell(Avogadro::QtGui::Molecule& mol)
{
  // If the user rejected, just return false
  if (this->exec() == QDialog::Rejected)
    return false;

  // Read the values
  unsigned int a = m_ui->aCellSpinBox->value();
  unsigned int b = m_ui->bCellSpinBox->value();
  unsigned int c = m_ui->cCellSpinBox->value();

  // No need to do anything if all the values are one
  if (a == 1 && b == 1 && c == 1)
    return true;

  // Run the supercell-building tool
  mol.undoMolecule()->buildSupercell(a, b, c);
  return true;
}

} // namespace QtPlugins
} // namespace Avogadro
