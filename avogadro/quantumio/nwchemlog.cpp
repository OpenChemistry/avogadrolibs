/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "nwchemlog.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iostream>

using std::vector;
using std::string;
using std::cout;
using std::endl;

namespace Avogadro {
namespace QuantumIO {

using Core::Atom;
using Core::BasisSet;
using Core::GaussianSet;

NWChemLog::NWChemLog()
{
}

NWChemLog::~NWChemLog()
{
}

std::vector<std::string> NWChemLog::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.push_back("log");
  extensions.push_back("out");
  extensions.push_back("nwchem");
  return extensions;
}

std::vector<std::string> NWChemLog::mimeTypes() const
{
  return std::vector<std::string>();
}

bool NWChemLog::read(std::istream& in, Core::Molecule& molecule)
{
  // Read the log file line by line, most sections are terminated by an empty
  // line, so they should be retained.
  while (!in.eof())
    processLine(in, molecule);

  if (m_frequencies.size() > 0 && m_frequencies.size() == m_Lx.size() &&
      m_frequencies.size() == m_intensities.size()) {
    molecule.setVibrationFrequencies(m_frequencies);
    molecule.setVibrationIntensities(m_intensities);
    molecule.setVibrationLx(m_Lx);
  }

  // GaussianSet *basis = new GaussianSet;

  // Do simple bond perception.
  molecule.perceiveBondsSimple();

  return true;
}

void NWChemLog::processLine(std::istream& in, Core::Molecule& mol)
{
  // First truncate the line, remove trailing white space and check
  string line;
  if (!getline(in, line) || Core::trimmed(line).empty())
    return;

  string key = Core::trimmed(line);

  // Big switch statement checking for various things we are interested in
  if (Core::contains(key, "Output coordinates")) {
    if (mol.atomCount())
      mol.clearAtoms();
    readAtoms(in, mol);
  } else if (Core::contains(key, "P.Frequency")) {
    readFrequencies(line, in, mol);
  } else if (Core::contains(key, "Projected Infra")) {
    readIntensities(in, mol);
  }
}

void NWChemLog::readAtoms(std::istream& in, Core::Molecule& mol)
{
  string line;
  // Skip the next three lines, headers, blanks...
  for (int i = 0; i < 3; ++i)
    if (!getline(in, line))
      return;

  while (true) {
    if (!getline(in, line))
      return;
    vector<string> parts = Core::split(line, ' ');
    // Keep going until the expected number of components is not seen.
    if (parts.size() != 6)
      break;
    unsigned char element = Core::Elements::atomicNumberFromSymbol(parts[1]);
    if (element == Avogadro::InvalidElement) {
      appendError("Invalid element encountered: " + parts[1]);
      return;
    }
    Vector3 p;
    for (int i = 0; i < 3; ++i) {
      bool ok = false;
      p[i] = Core::lexicalCast<double>(parts[i + 3], ok);
      if (!ok) {
        appendError("Couldn't convert coordinate component to double: " +
                    parts[i + 3]);
        return;
      }
    }
    Core::Atom a = mol.addAtom(element);
    a.setPosition3d(p);
  }
}

void NWChemLog::readFrequencies(const std::string& firstLine, std::istream& in,
                                Core::Molecule&)
{
  string line = firstLine;
  bool ok = false;
  vector<string> parts = Core::split(firstLine, ' ');
  if (parts.size() < 2)
    return;

  vector<double> frequencies;

  for (size_t i = 1; i < parts.size(); ++i)
    frequencies.push_back(Core::lexicalCast<double>(parts[i], ok));
  if (!ok) {
    appendError("Error reading frequencies: " + firstLine);
    return;
  }

  // Skip the blank line after the frequencies.
  if (!getline(in, line))
    return;
  if (!getline(in, line))
    return;
  parts = Core::split(line, ' ');
  if (parts.size() < 2)
    return;

  vector<vector<double>> cols;
  cols.resize(parts.size() - 1);

  // Main block of numbers.
  while (parts.size() >= 2) {
    for (size_t i = 1; i < parts.size(); ++i) {
      cols[i - 1].push_back(Core::lexicalCast<double>(parts[i], ok));
      if (!ok) {
        appendError("Couldn't convert " + parts[i] + " to double.");
        return;
      }
    }
    if (!getline(in, line))
      return;
    parts = Core::split(line, ' ');
  }
  for (size_t i = 0; i < frequencies.size(); ++i) {
    m_frequencies.push_back(frequencies[i]);
    Core::Array<Vector3> Lx;
    for (size_t j = 0; j < cols[i].size(); j += 3) {
      Lx.push_back(Vector3(cols[i][j + 0], cols[i][j + 1], cols[i][j + 2]));
    }
    m_Lx.push_back(Lx);
  }
}

void NWChemLog::readIntensities(std::istream& in, Core::Molecule& mol)
{
  string line;
  bool ok = false;
  // Skip the next two lines, headers, blanks...
  for (int i = 0; i < 2; ++i)
    if (!getline(in, line))
      return;

  while (true) {
    if (!getline(in, line))
      return;
    vector<string> parts = Core::split(line, ' ');
    // Keep going until the expected number of components is not seen.
    if (parts.size() != 7)
      break;
    m_intensities.push_back(Core::lexicalCast<double>(parts[5], ok));
    if (!ok) {
      appendError("Couldn't convert " + parts[5] + " to double.");
      return;
    }
  }
}
}
}
