/*******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/

#include <QDebug>
#include <QStringList>

#include <avogadro/core/avospglib.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include "specialkpoints.h"
#include "specialkpointsdata.h"

using Avogadro::Vector3;
using Avogadro::Core::AvoSpglib;
using Avogadro::Core::Molecule;
using Avogadro::Core::SpaceGroups;
using Avogadro::Core::UnitCell;

namespace Avogadro {
namespace QtPlugins {

QString SpecialKPoints::getSpecialKPoints(Molecule& mol)
{
  UnitCell* cell = mol.unitCell();
  if (cell) {
    // Check to see if the space group is set.
    unsigned short hallNumber = mol.hallNumber();
    // Try to find the space group if it is not set
    if (!hallNumber) {
      hallNumber = AvoSpglib::getHallNumber(mol);
      // If we still can't find the hall number, just return
      if (!hallNumber)
        return QString();
    }

    unsigned short spgNum = SpaceGroups::internationalNumber(hallNumber);
    if (spgNum != 0 && spgNum < 231) {
      QString specialKPoints = special_k_points[spgNum];
      if (specialKPoints.contains("#"))
        processConditionKPoints(specialKPoints, mol, spgNum);
      return specialKPoints.replace(',', '\n');
    }
  }

  // If we made it here, we failed
  return QString();
}

void SpecialKPoints::processConditionKPoints(QString& specialKPoints,
                                             Molecule& mol,
                                             unsigned short spgNum)
{
  // Check to see if the space group is set.
  UnitCell* cell = mol.unitCell();

  if (!cell) {
    qDebug() << "Error in " << __FUNCTION__ << ": cell is NULL!";
    specialKPoints = "";
    return;
  }

  // Ensure the space group number is valid
  if (spgNum == 0 || spgNum > 230) {
    qDebug() << "Error in " << __FUNCTION__ << ": spg is invalid!";
    specialKPoints = "";
    return;
  }

  QStringList stringSplit = specialKPoints.split("#");

  switch (spgNum) {
    // a > b or a < b
    case 20:
    case 21:
    case 35:
    case 36:
    case 37:
    case 38:
    case 39:
    case 40:
    case 41:
    case 63:
    case 64:
    case 65:
    case 66:
    case 67:
    case 68: {
      if (stringSplit.size() != 2) {
        qDebug() << "Error in " << __FUNCTION__ << ": for spgNum "
                 << QString::number(spgNum) << ", size is not correct!";
        specialKPoints = "";
      } else {
        unsigned short ind = 0;
        // a > b?
        if (cell->a() >= cell->b())
          ind = 0;
        else
          ind = 1;
        specialKPoints = stringSplit[ind];
      }
      return;
    }
    // a^-2 > b^-2 + c^-2, c^-2 > a^-2 + b^-2, or other
    case 22:
    case 42:
    case 43:
    case 69:
    case 70: {
      if (stringSplit.size() != 3) {
        qDebug() << "Error in " << __FUNCTION__ << ": for spgNum "
                 << QString::number(spgNum) << ", size is not correct!";
        specialKPoints = "";
      } else {
        unsigned short ind = 0;
        double a = cell->a();
        double b = cell->b();
        double c = cell->c();
        if (pow(a, -2.0) >= pow(b, -2.0) + pow(c, -2.0))
          ind = 0;
        else if (pow(c, -2.0) >= pow(a, -2.0) + pow(b, -2.0))
          ind = 1;
        else
          ind = 2;
        specialKPoints = stringSplit[ind];
      }
      return;
    }
    // (b > a > c or b > c > a) or other
    case 23:
    case 24:
    case 44:
    case 45:
    case 46:
    case 71:
    case 72:
    case 73:
    case 74: {
      if (stringSplit.size() != 2) {
        qDebug() << "Error in " << __FUNCTION__ << ": for spgNum "
                 << QString::number(spgNum) << ", size is not correct!";
        specialKPoints = "";
      } else {
        unsigned short ind = 0;
        double a = cell->a();
        double b = cell->b();
        double c = cell->c();
        if ((b >= a && a >= c) || (b >= c && c >= a))
          ind = 0;
        else
          ind = 1;
        specialKPoints = stringSplit[ind];
      }
      return;
    }
    // c/a > 1 or other
    case 79:
    case 80:
    case 82:
    case 87:
    case 88:
    case 97:
    case 98:
    case 107:
    case 108:
    case 109:
    case 110:
    case 119:
    case 120:
    case 121:
    case 122:
    case 139:
    case 140:
    case 141:
    case 142: {
      if (stringSplit.size() != 2) {
        qDebug() << "Error in " << __FUNCTION__ << ": for spgNum "
                 << QString::number(spgNum) << ", size is not correct!";
        specialKPoints = "";
      } else {
        unsigned short ind = 0;
        if (cell->c() / cell->a() >= 1)
          ind = 0;
        else
          ind = 1;
        specialKPoints = stringSplit[ind];
      }
      return;
    }
    // sqrt3a > sqrt2c or other
    case 146:
    case 148:
    case 155:
    case 160:
    case 161:
    case 166:
    case 167: {
      if (stringSplit.size() != 2) {
        qDebug() << "Error in " << __FUNCTION__ << ": for spgNum "
                 << QString::number(spgNum) << ", size is not correct!";
        specialKPoints = "";
      } else {
        unsigned short ind = 0;
        if (sqrt(3.0 * cell->a()) >= sqrt(2.0 * cell->c()))
          ind = 0;
        else
          ind = 1;
        specialKPoints = stringSplit[ind];
      }
      return;
    }
    // This shouldn't happen
    default: {
      qDebug() << "Error in" << __FUNCTION__ << ": failed to process spg "
               << QString::number(spgNum);
      specialKPoints = "";
      return;
    }
  }
}

} // namespace QtPlugins
} // namespace Avogadro
