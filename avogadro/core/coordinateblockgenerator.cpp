/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "coordinateblockgenerator.h"

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
  anglePrecision = 6,
  // Wide enough for a signed dihedral: "-180.000000" is eleven characters.
  angleWidth = 11
};

// Right-aligned fixed-point number in a field of @p width.
void writeReal(std::ostream& stream, int width, int precision, Real value)
{
  stream << std::right << std::setw(width) << std::setprecision(precision)
         << value;
}

// The factor that converts angstrom to the requested output unit.
Real distanceScaleFor(CoordinateBlockGenerator::DistanceUnit unit)
{
  return (unit == CoordinateBlockGenerator::Bohr) ? ANGSTROM_TO_BOHR_F : 1.0;
}

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

// Which pieces of per-atom data a specification needs, so that the lookups
// are only done when something will print them.
struct SpecNeeds
{
  bool elementSymbol = false;
  bool elementName = false;
  bool position = false;
  bool fractionalPosition = false;
};

SpecNeeds scanSpecification(const std::string& specification)
{
  SpecNeeds needs;
  for (char specChar : specification) {
    switch (specChar) {
      case 'S':
      case 'L':
        needs.elementSymbol = true;
        break;
      case 'N':
        needs.elementName = true;
        break;
      case 'x':
      case 'y':
      case 'z':
        needs.position = true;
        break;
      case 'a':
      case 'b':
      case 'c':
        needs.fractionalPosition = true;
        break;
    }
  }
  return needs;
}

// What one line of either kind of block can print about its atom.
struct AtomFields
{
  int number = 0;                 // one-based atom or row number, for '#'
  unsigned char atomicNumber = 0; // 'Z' and 'G'
  unsigned int elementCount = 0;  // running count of this element, for 'L'
  const char* symbol = "\0";
  const char* name = "\0";
  Vector3 pos3d = Vector3::Zero(); // already scaled to the output unit
  Vector3 fpos3d = Vector3::Zero();
  const UnitCell* cell = nullptr; // null prints "N/A" for 'a', 'b' and 'c'
};

/**
 * Gather what a line prints about the atom at @p position, looking up only
 * what @p needs asks for. @p cell is null unless a fractional field is
 * wanted and the molecule has a unit cell.
 */
AtomFields makeAtomFields(const SpecNeeds& needs, int number,
                          unsigned char atomicNumber, unsigned int elementCount,
                          const Vector3& position, const UnitCell* cell,
                          Real distanceScale)
{
  AtomFields fields;
  fields.number = number;
  fields.atomicNumber = atomicNumber;
  fields.elementCount = elementCount;
  if (needs.elementSymbol)
    fields.symbol = Core::Elements::symbol(atomicNumber);
  if (needs.elementName)
    fields.name = Core::Elements::name(atomicNumber);
  if (needs.position)
    fields.pos3d = position * distanceScale;
  fields.cell = cell;
  if (cell)
    fields.fpos3d = cell->toFractional(position);
  return fields;
}

/**
 * Write the field for @p specChar if it is one both kinds of block share,
 * and nothing for any other character. The separator that follows the
 * field is the caller's to write.
 */
void writeAtomField(std::ostream& stream, char specChar,
                    const AtomFields& fields, int indexWidth, bool haveNext)
{
  const auto writeFractional = [&](Real value) {
    if (fields.cell)
      writeReal(stream, coordinateWidth, coordinatePrecision, value);
    else
      stream << std::right << std::setw(coordinateWidth) << "N/A";
  };

  switch (specChar) {
    case '_':
      // Space character. A space is added by default after the field unless
      // this ends the line, in which case add it here, before the newline.
      if (!haveNext)
        stream << std::setw(1) << " ";
      break;
    case ',':
      stream << std::setw(1) << ',';
      break;
    case '#':
      stream << std::left << std::setw(indexWidth) << fields.number;
      break;
    case 'Z':
      stream << std::left << std::setw(atomicNumberWidth)
             << std::setprecision(atomicNumberPrecision)
             << static_cast<int>(fields.atomicNumber);
      break;
    case 'G':
      stream << std::right << std::setw(gamessAtomicNumberWidth)
             << std::setprecision(gamessAtomicNumberPrecision)
             << static_cast<float>(fields.atomicNumber);
      break;
    case 'S':
      stream << std::left << std::setw(elementSymbolWidth) << fields.symbol;
      break;
    case 'L':
      stream << std::left << fields.symbol << fields.elementCount << " ";
      break;
    case 'N':
      stream << std::left << std::setw(elementNameWidth) << fields.name;
      break;
    case 'x':
      writeReal(stream, coordinateWidth, coordinatePrecision, fields.pos3d.x());
      break;
    case 'y':
      writeReal(stream, coordinateWidth, coordinatePrecision, fields.pos3d.y());
      break;
    case 'z':
      writeReal(stream, coordinateWidth, coordinatePrecision, fields.pos3d.z());
      break;
    case '0':
      stream << std::left << std::setw(1) << 0;
      break;
    case '1':
      stream << std::left << std::setw(1) << 1;
      break;
    case 'a':
      writeFractional(fields.fpos3d.x());
      break;
    case 'b':
      writeFractional(fields.fpos3d.y());
      break;
    case 'c':
      writeFractional(fields.fpos3d.z());
      break;
    default:
      break;
  }
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

  const SpecNeeds needs = scanSpecification(m_specification);

  // Variables for loops below
  const Index numAtoms = m_molecule->atomCount();
  const UnitCell* cell =
    needs.fractionalPosition ? molecule()->unitCell() : nullptr;
  const Real distanceScale = distanceScaleFor(m_distanceUnit);

  const int indexWidth(indexWidthFor(numAtoms));

  // Use fixed number format.
  m_stream << std::fixed;

  // Count the number for each element. Atomic numbers are not limited to the
  // real elements: files can supply custom elements (128-254) or unrecognized
  // symbols (InvalidElement), so index the full unsigned char range.
  std::vector<unsigned int> elementCounts(
    std::numeric_limits<unsigned char>::max() + 1, 0);

  const size_t specSize = m_specification.size();

  // Iterate through the atoms
  for (Index atomI = 0; atomI < numAtoms; ++atomI) {
    const unsigned char atomicNumber = m_molecule->atomicNumber(atomI);
    elementCounts[atomicNumber]++;
    const AtomFields fields =
      makeAtomFields(needs, static_cast<int>(atomI + 1), atomicNumber,
                     elementCounts[atomicNumber],
                     m_molecule->atomPosition3d(atomI), cell, distanceScale);

    for (size_t i = 0; i < specSize; ++i) {
      const char specChar = m_specification[i];
      const bool haveNext = (i + 1 != specSize);
      writeAtomField(m_stream, specChar, fields, indexWidth, haveNext);

      // Prepare for next value. Push a space into the output stream if we are
      // not at the end of the line, or a newline if we are.
      writeSeparator(m_stream, specChar, haveNext,
                     haveNext ? m_specification[i + 1] : '\0');
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

  const SpecNeeds needs = scanSpecification(m_specification);

  const UnitCell* cell =
    needs.fractionalPosition ? molecule()->unitCell() : nullptr;
  const int indexWidth(indexWidthFor(numAtoms));
  const bool padded = (m_mode == Mode::ZMatrixPadded);
  const Real distanceScale = distanceScaleFor(m_distanceUnit);

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
    const AtomFields fields = makeAtomFields(
      needs, static_cast<int>(row + 1), atomicNumber,
      elementCounts[atomicNumber], m_molecule->atomPosition3d(atomIndex), cell,
      distanceScale);

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
          writeReal(m_stream, coordinateWidth, coordinatePrecision,
                    coord.a == MaxIndex ? 0.0 : coord.length * distanceScale);
          break;
        case 'A':
          writeReal(m_stream, angleWidth, anglePrecision,
                    coord.b == MaxIndex ? 0.0 : coord.angle);
          break;
        case 'T':
          writeReal(m_stream, angleWidth, anglePrecision,
                    coord.c == MaxIndex ? 0.0 : coord.dihedral);
          break;
        default:
          writeAtomField(m_stream, specChar, fields, indexWidth, haveNext);
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
