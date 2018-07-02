/******************************************************************************

  This source file is part of the MoleQueue project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "moleculeinfodialog.h"
#include "ui_moleculeinfodialog.h"

#include "molecule.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <iomanip>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>

using std::endl;
using std::getline;
using std::map;
using std::string;
using std::to_string;
using std::vector;

namespace Avogadro {
namespace QtGui {

using Core::Array;
using Core::Atom;
using Core::Elements;
using Core::lexicalCast;
using Core::split;
using Core::trimmed;
using Core::UnitCell;

using QtGui::Molecule;

MoleculeInfoDialog::MoleculeInfoDialog(QWidget* p)
  : QDialog(p)
  , m_ui(new Ui::MoleculeInfoDialog)
  , m_currentVolume(0.)
{
  m_ui->setupUi(this);
}

MoleculeInfoDialog::~MoleculeInfoDialog()
{
  delete m_ui;
}

int MoleculeInfoDialog::atomCount() const
{
  return m_ui->numAtoms->value();
}

bool MoleculeInfoDialog::hasBoxCoordinates() const
{
  return m_ui->boxCheck->isChecked();
}

void MoleculeInfoDialog::resolve(QWidget* p, Molecule& mol, QString fname)
{
  if (fname.toStdString() == "mdcrd") {
    MoleculeInfoDialog dlg(p);
    int reply = dlg.exec();
    if (reply != QDialog::Accepted)
      return;

    typedef map<string, unsigned char> AtomTypeMap;
    AtomTypeMap atomTypes;
    unsigned char customElementCounter = CustomElementMin;
    int coordSet = 0;

    int natoms = dlg.atomCount();

    Array<Vector3> positions;
    positions.reserve(natoms);

    mol.setCoordinate3d(0);
    Array<Vector3> molData = mol.atomPositions3d();

    int j = 0;

    while (j < molData.size()) {
      for (int i = 0; i < natoms; ++i, ++j) {
        if (coordSet == 0) {
          Vector3 pos(molData[j][0], molData[j][1], molData[j][2]);

          AtomTypeMap::const_iterator it;
          atomTypes.insert(
            std::make_pair(to_string(i), customElementCounter++));
          it = atomTypes.find(to_string(i));
          // if (customElementCounter > CustomElementMax) {
          //   appendError("Custom element type limit exceeded.");
          //   return false;
          // }
          Atom newAtom = mol.addAtom(it->second);
          newAtom.setPosition3d(pos);
        } else {
          Vector3 pos(molData[j][0], molData[j][1], molData[j][2]);
          positions.push_back(pos);
        }
      }

      if (coordSet == 0) {
        // Set the custom element map if needed
        if (!atomTypes.empty()) {
          Molecule::CustomElementMap elementMap;
          for (AtomTypeMap::const_iterator it = atomTypes.begin(),
                                           itEnd = atomTypes.end();
               it != itEnd; ++it) {
            elementMap.insert(std::make_pair(it->second, "Atom " + it->first));
          }
          mol.setCustomElementMap(elementMap);
        }
        mol.setCoordinate3d(mol.atomPositions3d(), coordSet++);
      } else {
        mol.setCoordinate3d(positions, coordSet++);
        positions.clear();
      }

      if (dlg.hasBoxCoordinates()) {
        mol.setUnitCell(new UnitCell(Vector3(molData[j][0], 0, 0),
                                     Vector3(0, molData[j][1], 0),
                                     Vector3(0, 0, molData[j][2])));
        ++j;
      }
    }

    mol.emitChanged(Molecule::Atoms | Molecule::Modified);
  }
}

} // namespace QtPlugins
} // namespace Avogadro
