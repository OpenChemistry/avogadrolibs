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

namespace {
// Auxiliary struct used for DALTON inputfile conversion.
struct atom_data
{
  std::string name, charge, X, Y, Z;
};
// Another auxiliary struct used for DALTON inputfile conversion.
struct types_header
{
  int index;
  std::string charge;
  int number;
};

// Additional function for DALTON inputfile conversion.
size_t countEndls(const std::string s);
// Function used for string dividing
atom_data* divide_text(std::string s, int ile);
std::string DaltonFormat(std::string& s);
}

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
  bool daltonInputGenerator(false);
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
      case 'D':
        daltonInputGenerator = true;
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

  if (daltonInputGenerator) {
    std::string test1 = m_stream.str();
    test1 = DaltonFormat(test1);
    return test1;
  }

  return m_stream.str();
}

namespace {

size_t countEndls(const std::string s)
{
  int ile = 0;
  for (size_t i = 0; i < s.length(); ++i) {
    if (s[i] == '\n')
      ++ile;
  }
  return ile;
}

atom_data* divide_text(std::string s, int ile)
{
  atom_data* tab = new atom_data[ile];
  size_t beg_i, end_i, it = 0;
  size_t beg_i1, end_i1, it1 = 0;
  const std::string ogr = "\n";
  const std::string ogr1 = " ";
  // Finds beggining of first word.
  beg_i = s.find_first_not_of(ogr);
  // Division of the word by the string "\n"
  while (beg_i != std::string::npos) {
  // If the beginning of the word is found.
    end_i = s.find_first_of(ogr, beg_i);
    // Find the end of the word.
    if (end_i == std::string::npos)
      end_i = s.length();

    std::string temp = s.substr(beg_i, end_i - beg_i);
    beg_i1 = temp.find_first_not_of(ogr1);
    // Division of the word by the string " "
    while (beg_i1 != std::string::npos) {
      end_i1 = temp.find_first_of(ogr1, beg_i1);
      if (end_i1 == std::string::npos)
        end_i1 = temp.length();
      std::string temp2 = temp.substr(beg_i1, end_i1 - beg_i1);
      switch (it1 % 5) {
        case 0:
          tab[it].name = temp2;
          break;
        case 1:
          tab[it].charge = temp2;
          break;
        case 2:
          tab[it].X = temp2;
          break;
        case 3:
          tab[it].Y = temp2;
          break;
        case 4:
          tab[it].Z = temp2;
          break;
      } // switch
      beg_i1 = temp.find_first_not_of(ogr1, end_i1);
      ++it1;
    } // while2
    beg_i = s.find_first_not_of(ogr, end_i);
    // Beginning of the next word.
    ++it;
  }
  return tab;
}

std::string DaltonFormat(std::string& s)
{
  size_t ile = countEndls(s);
  if (ile == 0)
    return " ";
  atom_data* tab = divide_text(s, ile);
  int atom_types = 1;
  std::string temp = tab[0].charge;
  for (size_t i = 1; i < ile; ++i) {
    if (temp != tab[i].charge) {
      ++atom_types;
      temp = tab[i].charge;
    }
  }
  types_header* typesHeads = new types_header[atom_types];
  typesHeads[0].index = 0;
  typesHeads[0].charge = tab[0].charge;

  temp = tab[0].charge;
  size_t k = 1, i = 1, j = 1;
  for (; i < ile; ++i) {
    if (temp != tab[i].charge) {
      typesHeads[k].charge = tab[i].charge;
      typesHeads[k].index = i;
      typesHeads[k - 1].number = j;
      k++;
      temp = tab[i].charge;
      j = 0;
    }
    ++j;
  }

  typesHeads[k - 1].number = j;
  std::stringstream stream;
  stream.str("");
  stream.clear();

  enum
  {
    coordinateWidth = 11,
    elementSymbolWidth = 3,
  };
  stream << "Atomtypes=" << atom_types << std::endl;
  for (size_t l = 0, m = 0; m < ile; ++m) {
    if (static_cast<int>(m) == typesHeads[l].index) {
      stream << "Charge=" << typesHeads[l].charge
               << " Atoms=" << typesHeads[l].number << '\n';
      ++l;
    }
    stream << std::left << std::setw(elementSymbolWidth) << tab[m].name
             << ' ';

    stream << std::right << std::setw(coordinateWidth) << tab[m].X << ' ';

    stream << std::right << std::setw(coordinateWidth) << tab[m].Y << ' ';

    stream << std::right << std::setw(coordinateWidth) << tab[m].Z << '\n';
  }
  std::string res = stream.str();
  delete[] tab;
  delete[] typesHeads;
  return res;
}

}

} // namespace Core
} // namespace Avogadro
