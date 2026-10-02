/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gaussiancube.h"

#include <avogadro/core/cube.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iomanip>
#include <iostream>
#include <limits>
#include <string>

namespace Avogadro::QuantumIO {

namespace {
constexpr int kMaxCubeDim = 1024;
constexpr int kMaxAtomCount = 1000000;
constexpr unsigned int kMaxCubeCount = 128;
constexpr size_t kMaxCubeValues = 64ull * 1024 * 1024;       // 64M values
constexpr size_t kMaxTotalCubeValues = 128ull * 1024 * 1024; // 128M values

bool hasMinimumRemainingBytes(std::istream& in, size_t minBytes)
{
  auto pos = in.tellg();
  if (pos == std::streampos(-1))
    return true;

  in.clear();
  in.seekg(0, std::ios::end);
  auto end = in.tellg();
  in.seekg(pos);
  if (end == std::streampos(-1))
    return true;

  const size_t remaining = static_cast<size_t>(end - pos);
  return remaining >= minBytes;
}

/**
 * Reads the grid values of a cube file one at a time.
 *
 * Extracting straight into a float discards valid files: strtof reports an
 * underflow to subnormal as ERANGE, and the extractor turns that into failbit
 * even though the value parsed correctly. Codes such as Q-Chem write the
 * decaying tail of a density with exponents past FLT_MIN ("1.505124610E-39"),
 * which would abort the read a handful of values from the end.
 *
 * Parse each token with Core::parseFloat instead. It is the parser behind
 * Core::lexicalCast<float>, so a range error is handled the same way here --
 * underflow gives zero or a subnormal, overflow is clamped -- but it works
 * on the token in place, which matters for a loop that runs once per grid
 * point. It is also independent of the C locale: strtod is not, and Qt sets
 * that locale from the environment, so under a comma-decimal locale every
 * cube file failed to read.
 *
 * CP2K writes the grid with Fortran E13.5 edit descriptors, which leave no
 * separator in front of a negative number and use three digit exponents:
 * " 0.26189E-002-0.85098E-002-0.14043E-001". A whitespace token can therefore
 * hold several values. When a number stops short at a '+' or '-' that follows
 * a digit or '.', the rest of the token is kept for the next call. A sign
 * after an exponent letter never gets here (parseFloat consumes the exponent),
 * so this cannot split a valid number.
 */
class CubeValueReader
{
public:
  explicit CubeValueReader(std::istream& stream) : m_in(stream) {}

  bool read(float& value)
  {
    if (m_pos == m_end) {
      if (!(m_in >> m_token))
        return false;
      m_pos = m_token.data();
      m_end = m_pos + m_token.size();
    }

    // Reject anything that is not a number, or that stopped short of the end
    // of the token other than at a run-together sign ("1.5abc", the "*******"
    // some codes emit on overflow). The literals "nan" and "inf" have no
    // meaning on a grid and are refused by the parser.
    const char* stop = Core::parseFloat(m_pos, m_end, value);
    if (stop == nullptr)
      return false;
    if (stop != m_end) {
      const char next = *stop;
      const char prev = *(stop - 1);
      const bool prevEndsMantissa = (prev >= '0' && prev <= '9') || prev == '.';
      if ((next != '+' && next != '-') || !prevEndsMantissa)
        return false;
    }
    m_pos = stop;
    return true;
  }

private:
  std::istream& m_in;
  std::string m_token;
  const char* m_pos = nullptr;
  const char* m_end = nullptr;
};
} // namespace

GaussianCube::GaussianCube() {}

GaussianCube::~GaussianCube() {}

std::vector<std::string> GaussianCube::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("cube");
  return extensions;
}

std::vector<std::string> GaussianCube::mimeTypes() const
{
  return std::vector<std::string>();
}

bool GaussianCube::read(std::istream& in, Core::Molecule& molecule)
{
  // Variables we will need
  std::string line;
  std::vector<std::string> list;

  int nAtoms;
  Vector3 min;
  Vector3 spacing;
  Vector3i dim;

  // Gaussian Cube format is very specific

  // Read and set name
  if (!Core::getLine(in, line)) {
    appendError("Invalid cube header.");
    return false;
  }
  molecule.setData("name", line);

  // Read and skip field title (we may be able to use this to setCubeType in the
  // future)
  if (!Core::getLine(in, line)) {
    appendError("Invalid cube header.");
    return false;
  }

  // Next line contains nAtoms and m_min
  if (!(in >> nAtoms)) {
    appendError("Invalid cube header.");
    return false;
  }
  for (unsigned int i = 0; i < 3; ++i)
    if (!(in >> min(i))) {
      appendError("Invalid cube header.");
      return false;
    }
  if (!Core::getLine(in, line)) { // capture newline before continuing
    appendError("Invalid cube header.");
    return false;
  }

  if (nAtoms == std::numeric_limits<int>::min()) {
    appendError("Invalid atom count in cube file.");
    return false;
  }
  const int atomCount = nAtoms < 0 ? -nAtoms : nAtoms;
  if (atomCount > kMaxAtomCount) {
    appendError("Invalid atom count in cube file.");
    return false;
  }

  // Next 3 lines contains spacing and dim
  for (unsigned int i = 0; i < 3; ++i) {
    if (!Core::getLine(in, line)) {
      appendError("Invalid cube header.");
      return false;
    }
    line = Core::trimmed(line);
    if (line.empty()) {
      appendError("Invalid cube header.");
      return false;
    }
    list = Core::split(line, ' ');
    if (list.size() < 4) {
      appendError("Invalid cube grid specification.");
      return false;
    }
    dim(i) = Core::lexicalCast<int>(list[0]).value_or(0);
    spacing(i) = Core::lexicalCast<double>(list[i + 1]).value_or(0.0);
    if (dim(i) <= 0 || dim(i) > kMaxCubeDim) {
      appendError("Invalid cube grid dimension.");
      return false;
    }
  }

  const size_t d0 = static_cast<size_t>(dim(0));
  const size_t d1 = static_cast<size_t>(dim(1));
  const size_t d2 = static_cast<size_t>(dim(2));
  const size_t maxSize = std::numeric_limits<size_t>::max();
  if (d0 == 0 || d1 == 0 || d2 == 0 || d0 > maxSize / d1 ||
      d0 * d1 > maxSize / d2) {
    appendError("Invalid cube data dimensions.");
    return false;
  }
  const size_t valueCount = d0 * d1 * d2;
  if (valueCount > kMaxCubeValues) {
    appendError("Cube data exceeds supported size.");
    return false;
  }

  // Geometry block
  Vector3 pos;
  for (int i = 0; i < atomCount; ++i) {
    if (!Core::getLine(in, line)) {
      appendError("Invalid cube atom data.");
      return false;
    }
    line = Core::trimmed(line);
    if (line.empty()) {
      appendError("Invalid cube atom data.");
      return false;
    }
    list = Core::split(line, ' ');
    if (list.size() < 5) {
      appendError("Invalid cube atom data.");
      return false;
    }
    auto atomNum = Core::lexicalCast<short int>(list[0]).value_or(0);
    Core::Atom a = molecule.addAtom(static_cast<unsigned char>(atomNum));
    for (unsigned int j = 2; j < 5; ++j)
      pos(j - 2) = Core::lexicalCast<double>(list[j]).value_or(0.0);
    pos = pos * BOHR_TO_ANGSTROM;
    a.setPosition3d(pos);
  }

  // If the nAtoms were negative there is another line before
  // the data which is necessary, maybe contain 1 or more cubes
  unsigned int nCubes = 1;
  if (nAtoms < 0) {
    if (!(in >> nCubes) || nCubes == 0) {
      appendError("Invalid cube count.");
      return false;
    }
    if (nCubes > kMaxCubeCount) {
      appendError("Invalid cube count.");
      return false;
    }
    if (valueCount > 0 && nCubes > kMaxTotalCubeValues / valueCount) {
      appendError("Cube data exceeds supported size.");
      return false;
    }
    std::vector<unsigned int> moList(nCubes);
    for (unsigned int i = 0; i < nCubes; ++i)
      if (!(in >> moList[i])) {
        appendError("Invalid cube MO list.");
        return false;
      }
    // clear buffer
    if (!Core::getLine(in, line)) {
      appendError("Invalid cube header.");
      return false;
    }
  }

  // Render molecule
  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();

  // Cube block, set limits and populate data
  // min and spacing are in bohr units, convert to ANGSTROM
  min *= BOHR_TO_ANGSTROM;
  spacing *= BOHR_TO_ANGSTROM;

  const size_t cubeCount = static_cast<size_t>(nCubes);
  if (valueCount > 0 && cubeCount > maxSize / valueCount) {
    appendError("Cube data exceeds supported size.");
    return false;
  }
  if (!hasMinimumRemainingBytes(in, valueCount * cubeCount)) {
    appendError("Invalid cube data.");
    return false;
  }

  for (unsigned int i = 0; i < nCubes; ++i) {
    // Get a cube object from molecule
    Core::Cube* cube = molecule.addCube();
    cube->setCubeType(Core::Cube::Type::FromFile);

    cube->setLimits(min, dim, spacing);
    auto* values = cube->data();
    if (!values) {
      appendError("Invalid cube data.");
      return false;
    }
    if (values->size() != valueCount)
      values->resize(valueCount);
    CubeValueReader reader(in);
    for (size_t index = 0; index < valueCount; ++index) {
      if (!reader.read((*values)[index])) {
        appendError("Invalid cube data.");
        return false;
      }
    }
    if (!cube->setData(*values)) {
      appendError("Invalid cube data.");
      return false;
    }
    // clear buffer, if more than one cube
    if (!Core::getLine(in, line) && i + 1 < nCubes) {
      appendError("Invalid cube data.");
      return false;
    }
  }

  return true;
}

void writeFixedFloat(std::ostream& outStream, Real number)
{
  outStream << std::setw(12) << std::fixed << std::right << std::setprecision(6)
            << number;
}

void writeFixedInt(std::ostream& outStream, unsigned int number)
{
  outStream << std::setw(5) << std::fixed << std::right << number;
}

bool GaussianCube::write(std::ostream& outStream, const Core::Molecule& mol)
{
  if (mol.cubeCount() == 0)
    return false; // no cubes to write

  const Core::Cube* cube =
    mol.cube(0); // eventually need to write all the cubes
  Vector3 min = cube->min() * ANGSTROM_TO_BOHR;
  Vector3 spacing = cube->spacing() * ANGSTROM_TO_BOHR;
  Vector3i dim = cube->dimensions(); // number of points in each direction

  // might be useful to use the 2nd line, but it's just a comment
  // e.g. write out the cube type
  outStream << "Gaussian Cube file generated by Avogadro.\n";
  if (mol.data("name").toString().length())
    outStream << mol.data("name").toString() << "\n";
  else
    outStream << "\n";

  // Write out the number of atoms and the minimum coordinates
  size_t numAtoms = mol.atomCount();
  writeFixedInt(outStream, numAtoms);
  writeFixedFloat(outStream, min[0]);
  writeFixedFloat(outStream, min[1]);
  writeFixedFloat(outStream, min[2]);
  writeFixedInt(outStream, 1); // one value per point (i.e., not vector)
  outStream << "\n";

  // now write the size and spacing of the cube
  writeFixedInt(outStream, dim[0]);
  writeFixedFloat(outStream, spacing[0]);
  writeFixedFloat(outStream, 0.0);
  writeFixedFloat(outStream, 0.0);
  outStream << "\n";

  writeFixedInt(outStream, dim[1]);
  writeFixedFloat(outStream, 0.0);
  writeFixedFloat(outStream, spacing[1]);
  writeFixedFloat(outStream, 0.0);
  outStream << "\n";

  writeFixedInt(outStream, dim[2]);
  writeFixedFloat(outStream, 0.0);
  writeFixedFloat(outStream, 0.0);
  writeFixedFloat(outStream, spacing[2]);
  outStream << "\n";

  for (size_t i = 0; i < numAtoms; ++i) {
    Core::Atom atom = mol.atom(i);
    if (!atom.isValid()) {
      appendError("Internal error: Atom invalid.");
      return false;
    }

    writeFixedInt(outStream, static_cast<int>(atom.atomicNumber()));
    writeFixedFloat(outStream, 0.0); // charge
    writeFixedFloat(outStream, atom.position3d()[0] * ANGSTROM_TO_BOHR);
    writeFixedFloat(outStream, atom.position3d()[1] * ANGSTROM_TO_BOHR);
    writeFixedFloat(outStream, atom.position3d()[2] * ANGSTROM_TO_BOHR);
    outStream << "\n";
  }

  // write the raw cube values
  const std::vector<float>* values = cube->data();
  for (unsigned int i = 0; i < values->size(); ++i) {
    outStream << std::setw(13) << std::right << std::scientific
              << std::setprecision(5) << (*values)[i];
    if (i % 6 == 5)
      outStream << "\n";
  }

  return true;
}

} // namespace Avogadro::QuantumIO
