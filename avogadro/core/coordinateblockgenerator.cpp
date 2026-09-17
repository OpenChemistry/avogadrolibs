/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "coordinateblockgenerator.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/internalcoordinates.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <vector>

namespace Avogadro::Core {

namespace {

// widths/precisions shared by both kinds of block
enum
{
  atomicNumberPrecision = 0,
  atomicNumberWidth = 3,
  atomicLabelWidth = 8, // 3 element symbol + 5 index
  coordinatePrecision = 6,
  coordinateWidth = 11,
  elementNameWidth = 13, // Currently the longest element name
  elementSymbolWidth = 3,
  gamessAtomicNumberPrecision = 1,
  gamessAtomicNumberWidth = 5,
  // Wide enough for a signed dihedral: "-180.000000" is eleven characters.
  anglePrecision = 6,
  angleWidth = 11
};

// The number of columns the one-based index of an atom or row needs.
int indexWidthFor(Index count)
{
  return count > 0 ? static_cast<int>(std::log10(static_cast<float>(count))) + 1
                   : 1;
}

/**
 * The separator that follows the character at @p current.
 *
 * A comma is a delimiter in its own right, so no space is added on either
 * side of one: a spec of "S,I,R" gives "C,1,1.234" rather than "C , 1 , 1.234".
 */
void writeSeparator(std::ostream& stream, char current, bool haveNext,
                    char next)
{
  if (!haveNext)
    stream << '\n';
  else if (current != ',' && next != ',')
    stream << std::setw(1) << ' ';
}

} // namespace

std::string CoordinateBlockGenerator::generateCoordinateBlock()
{
  m_atomsReordered = false;
  m_linearRows.clear();

  if (!m_molecule)
    return {};

  if (m_mode != Mode::Cartesian)
    return generateZMatrixBlock();

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
      case 'L':
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
  const char* symbol = "\0";
  const char* name = "\0";
  Vector3 pos3d = Vector3::Zero();
  Vector3 fpos3d = Vector3::Zero();
  const UnitCell* cell =
    needFractionalPosition ? molecule()->unitCell() : nullptr;

  const int indexWidth(indexWidthFor(numAtoms));

  // Use fixed number format.
  m_stream << std::fixed;

  // Count the number for each element. Atomic numbers are not limited to the
  // real elements: files can supply custom elements (128-254) or unrecognized
  // symbols (InvalidElement), so index the full unsigned char range.
  std::vector<unsigned int> elementCounts(
    std::numeric_limits<unsigned char>::max() + 1, 0);

  // Iterate through the atoms
  for (Index atomI = 0; atomI < numAtoms; ++atomI) {
    atom = m_molecule->atom(atomI);
    atomicNumber = atom.atomicNumber();
    elementCounts[atomicNumber]++;
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
        case ',':
          m_stream << std::setw(1) << ',';
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
        case 'L':
          m_stream << std::left << symbol << elementCounts[atomicNumber] << " ";
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
      const bool haveNext = (it + 1 != end);
      writeSeparator(m_stream, *it, haveNext, haveNext ? *(it + 1) : '\0');
    } // end spec char
  }   // end for atom

  return m_stream.str();
}

std::string CoordinateBlockGenerator::generateZMatrixBlock()
{
  // Reset stream.
  m_stream.str("");
  m_stream.clear();

  const Index numAtoms = m_molecule->atomCount();
  if (numAtoms == 0)
    return {};

  Array<Index> rowToAtom;
  const Array<InternalCoordinate> rows =
    cartesianToInternal(*m_molecule, rowToAtom, ZMatrixOrder::PreferAtomOrder);
  m_linearRows = linearReferenceRows(*m_molecule, rows);

  // The reference fields name rows rather than atoms, so that a z-matrix
  // that had to be reordered still refers to its own lines. The two
  // numberings agree whenever the molecule's own atom order was kept.
  std::vector<Index> atomToRow(numAtoms, MaxIndex);
  for (Index row = 0; row < rows.size(); ++row) {
    const Index atomIndex = rowToAtom[row];
    if (atomIndex < numAtoms)
      atomToRow[atomIndex] = row;
    if (atomIndex != row)
      m_atomsReordered = true;
  }

  // Check the spec to see if certain items are needed.
  bool needElementSymbol(false);
  bool needElementName(false);
  bool needPosition(false);
  bool needFractionalPosition(false);
  for (char specChar : m_specification) {
    switch (specChar) {
      case 'S':
      case 'L':
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

  const UnitCell* cell =
    needFractionalPosition ? molecule()->unitCell() : nullptr;
  const int indexWidth(indexWidthFor(numAtoms));
  const bool padded = (m_mode == Mode::ZMatrixPadded);
  const Real distanceScale =
    (m_distanceUnit == Bohr) ? ANGSTROM_TO_BOHR_F : 1.0;

  // Use fixed number format.
  m_stream << std::fixed;

  // Element counts run in row order, so that the labels number the lines of
  // the z-matrix as the reader sees them.
  std::vector<unsigned int> elementCounts(
    std::numeric_limits<unsigned char>::max() + 1, 0);

  // Which fields a row cannot carry, because the atom it would be measured
  // against does not exist. Only the opening rows of a z-matrix are short,
  // but a linear fragment can leave a later row without a dihedral too.
  const auto fieldMissing = [](char specChar,
                               const InternalCoordinate& coord) -> bool {
    switch (specChar) {
      case 'I':
      case 'R':
        return coord.a == MaxIndex;
      case 'J':
      case 'A':
        return coord.b == MaxIndex;
      case 'K':
      case 'T':
        return coord.c == MaxIndex;
      default:
        return false;
    }
  };

  // The row a reference atom is written on, one-based, or 0 for a reference
  // this row does not have.
  const auto referenceRow = [&](Index atomIndex) -> int {
    if (atomIndex >= numAtoms)
      return 0;
    const Index row = atomToRow[atomIndex];
    return row == MaxIndex ? 0 : static_cast<int>(row + 1);
  };

  const size_t specSize = m_specification.size();
  std::vector<bool> keep(specSize, true);

  for (Index row = 0; row < rows.size(); ++row) {
    const InternalCoordinate& coord = rows[row];
    const Index atomIndex = rowToAtom[row];
    const unsigned char atomicNumber = m_molecule->atomicNumber(atomIndex);
    elementCounts[atomicNumber]++;

    const char* symbol =
      needElementSymbol ? Core::Elements::symbol(atomicNumber) : "\0";
    const char* name =
      needElementName ? Core::Elements::name(atomicNumber) : "\0";
    Vector3 pos3d =
      needPosition ? m_molecule->atomPosition3d(atomIndex) : Vector3::Zero();
    pos3d *= distanceScale;
    const Vector3 fpos3d =
      cell ? cell->toFractional(m_molecule->atomPosition3d(atomIndex))
           : Vector3::Zero();

    // Work out which characters this row prints. In the padded mode every
    // field is printed, with a zero standing in for one the row does not
    // have; otherwise a missing field is dropped, and so is the delimiter
    // written immediately before it, which would otherwise leave the line
    // with a ragged tail of blanks or, worse for a comma-delimited format,
    // a tail of empty fields.
    keep.assign(specSize, true);
    if (!padded) {
      for (size_t i = 0; i < specSize; ++i)
        keep[i] = !fieldMissing(m_specification[i], coord);
      for (size_t i = specSize; i-- > 1;) {
        if (keep[i] || !fieldMissing(m_specification[i], coord))
          continue;
        const char previous = m_specification[i - 1];
        if (previous == '_' || previous == ',')
          keep[i - 1] = false;
      }
    }

    for (size_t i = 0; i < specSize; ++i) {
      if (!keep[i])
        continue;

      // Where the next printed character is, so the separator after this one
      // knows whether it ends the line and what it abuts.
      size_t next = i + 1;
      while (next < specSize && !keep[next])
        ++next;
      const bool haveNext = (next < specSize);

      const char specChar = m_specification[i];
      switch (specChar) {
        case '_':
          // Space character. A space is added by default after the switch
          // clause unless this ends the line, in which case add it here,
          // before the newline.
          if (!haveNext)
            m_stream << std::setw(1) << " ";
          break;
        case ',':
          m_stream << std::setw(1) << ',';
          break;
        case '#':
          m_stream << std::left << std::setw(indexWidth)
                   << static_cast<int>(row + 1);
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
        case 'L':
          m_stream << std::left << symbol << elementCounts[atomicNumber] << " ";
          break;
        case 'N':
          m_stream << std::left << std::setw(elementNameWidth) << name;
          break;
        case 'I':
          m_stream << std::right << std::setw(indexWidth)
                   << referenceRow(coord.a);
          break;
        case 'J':
          m_stream << std::right << std::setw(indexWidth)
                   << referenceRow(coord.b);
          break;
        case 'K':
          m_stream << std::right << std::setw(indexWidth)
                   << referenceRow(coord.c);
          break;
        case 'R':
          m_stream << std::right << std::setw(coordinateWidth)
                   << std::setprecision(coordinatePrecision)
                   << (coord.a == MaxIndex ? 0.0
                                           : coord.length * distanceScale);
          break;
        case 'A':
          m_stream << std::right << std::setw(angleWidth)
                   << std::setprecision(anglePrecision)
                   << (coord.b == MaxIndex ? 0.0 : coord.angle);
          break;
        case 'T':
          m_stream << std::right << std::setw(angleWidth)
                   << std::setprecision(anglePrecision)
                   << (coord.c == MaxIndex ? 0.0 : coord.dihedral);
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

      writeSeparator(m_stream, specChar, haveNext,
                     haveNext ? m_specification[next] : '\0');
    } // end spec char

    // A row whose every character was dropped still occupies a line: the
    // first row of a ragged z-matrix that asks only for reference fields
    // would otherwise vanish and take its atom with it.
    if (specSize > 0 &&
        std::none_of(keep.begin(), keep.end(), [](bool k) { return k; }))
      m_stream << '\n';
  } // end for row

  return m_stream.str();
}

} // namespace Avogadro::Core
