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

#include "coordinateblockgenerator.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <iomanip>

namespace Avogadro {
namespace Core {

CoordinateBlockGenerator::CoordinateBlockGenerator()
  : m_molecule(nullptr), m_distanceUnit(Angstrom)
{
}

std::string CoordinateBlockGenerator::generateCoordinateBlock()
{
  if (!m_molecule)
    return "";

  // Reset stream.
  m_stream.str("");
  m_stream.clear();

  // Create/cache some iterators for the specification string.
  std::string::const_iterator it;
  const std::string::const_iterator begin = m_specification.begin();
  const std::string::const_iterator end = m_specification.end();

  // Check the spec to see if certain items are needed.
  bool needElementSymbol(false);
  bool needElementName(false);
  bool needPosition(false);
  bool needFractionalPosition(false);
  for (it = begin; it != end; ++it) {
    switch (*it) {
      case 'S':
        needElementSymbol = true;
        break;
      case 'N':
        needElementName = true;
        break;
      case 'x':
      case 'y':
      case 'z':
        needPosition = true;
        break;
      case 'a':
      case 'b':
      case 'c':
        needFractionalPosition = true;
        break;
    }
  }

  // Variables for loops below
  const Index numAtoms = m_molecule->atomCount();
  Atom atom;
  unsigned char atomicNumber;
  const char* symbol;
  const char* name;
  Vector3 pos3d;
  Vector3 fpos3d;
  const UnitCell* cell =
    needFractionalPosition ? molecule()->unitCell() : nullptr;

  // widths/precisions
  enum
  {
    atomicNumberPrecision = 0,
    atomicNumberWidth = 3,
    coordinatePrecision = 6,
    coordinateWidth = 11,
    elementNameWidth = 13, // Currently the longest element name
    elementSymbolWidth = 3,
    gamessAtomicNumberPrecision = 1,
    gamessAtomicNumberWidth = 5
  };
  const int indexWidth(
    static_cast<int>(std::log10(static_cast<float>(numAtoms))) + 1);

  // Use fixed number format.
  m_stream << std::fixed;

  // Iterate through the atoms
  for (Index atomI = 0; atomI < numAtoms; ++atomI) {
    atom = m_molecule->atom(atomI);
    atomicNumber = atom.atomicNumber();
    if (needElementSymbol)
      symbol = Core::Elements::symbol(atomicNumber);
    if (needElementName)
      name = Core::Elements::name(atomicNumber);
    if (needPosition)
      pos3d = atom.position3d();
    if (needFractionalPosition)
      fpos3d = cell ? cell->toFractional(atom.position3d()) : Vector3::Zero();

    switch (m_distanceUnit) {
      case Bohr:
        pos3d *= ANGSTROM_TO_BOHR_F;
        break;
      default:
      case Angstrom:
        break;
    }

    for (it = begin; it != end; ++it) {
      switch (*it) {
        case '_':
          // Space character. If we are not at the end of the spec, a space will
          // be added by default after the switch clause. If we are at the end,
          // add a space before the newline that will be added.
          if (it + 1 == end)
            m_stream << std::setw(1) << " ";
          break;
        case '#':
          m_stream << std::left << std::setw(indexWidth)
                   << static_cast<int>(atomI + 1);
          break;
        case 'Z':
          m_stream << std::left << std::setw(atomicNumberWidth)
                   << std::setprecision(atomicNumberPrecision)
                   << static_cast<int>(atomicNumber);
          break;
        case 'G':
          m_stream << std::right << std::setw(gamessAtomicNumberWidth)
                   << std::setprecision(gamessAtomicNumberPrecision)
                   << static_cast<float>(atomicNumber);
          break;
        case 'S':
          m_stream << std::left << std::setw(elementSymbolWidth) << symbol;
          break;
        case 'N':
          m_stream << std::left << std::setw(elementNameWidth) << name;
          break;
        case 'x':
          m_stream << std::right << std::setw(coordinateWidth)
                   << std::setprecision(coordinatePrecision) << pos3d.x();
          break;
        case 'y':
          m_stream << std::right << std::setw(coordinateWidth)
                   << std::setprecision(coordinatePrecision) << pos3d.y();
          break;
        case 'z':
          m_stream << std::right << std::setw(coordinateWidth)
                   << std::setprecision(coordinatePrecision) << pos3d.z();
          break;
        case '0':
          m_stream << std::left << std::setw(1) << 0;
          break;
        case '1':
          m_stream << std::left << std::setw(1) << 1;
          break;
        case 'a':
          if (cell) {
            m_stream << std::right << std::setw(coordinateWidth)
                     << std::setprecision(coordinatePrecision) << fpos3d.x();
          } else {
            m_stream << std::right << std::setw(coordinateWidth) << "N/A";
          }
          break;
        case 'b':
          if (cell) {
            m_stream << std::right << std::setw(coordinateWidth)
                     << std::setprecision(coordinatePrecision) << fpos3d.y();
          } else {
            m_stream << std::right << std::setw(coordinateWidth) << "N/A";
          }
          break;
        case 'c':
          if (cell) {
            m_stream << std::right << std::setw(coordinateWidth)
                     << std::setprecision(coordinatePrecision) << fpos3d.z();
          } else {
            m_stream << std::right << std::setw(coordinateWidth) << "N/A";
          }
          break;
      } // end switch

      // Prepare for next value. Push a space into the output stream if we are
      // not at the end of the line, or a newline if we are.
      m_stream << std::setw(1) << (it + 1 != end ? ' ' : '\n');
    } // end spec char
  }   // end for atom

  return m_stream.str();
}

} // namespace Core
} // namespace Avogadro
