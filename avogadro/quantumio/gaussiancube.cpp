/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Barry E. Moore II

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gaussiancube.h"

#include <avogadro/core/cube.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iostream>

namespace Avogadro {
namespace QuantumIO {

GaussianCube::GaussianCube()
{
}

GaussianCube::~GaussianCube()
{
}

std::vector<std::string> GaussianCube::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.push_back("cube");
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
  getline(in, line);
  molecule.setData("name", line);

  // Read and skip field title (we may be able to use this to setCubeType in the
  // future)
  getline(in, line);

  // Next line contains nAtoms and m_min
  in >> nAtoms;
  for (unsigned int i = 0; i < 3; ++i)
    in >> min(i);
  getline(in, line); // capture newline before continuing

  // Next 3 lines contains spacing and dim
  for (unsigned int i = 0; i < 3; ++i) {
    getline(in, line);
    line = Core::trimmed(line);
    list = Core::split(line, ' ');
    dim(i) = Core::lexicalCast<int>(list[0]);
    spacing(i) = Core::lexicalCast<double>(list[i + 1]);
  }

  // Geometry block
  Vector3 pos;
  for (int i = 0; i < abs(nAtoms); ++i) {
    getline(in, line);
    line = Core::trimmed(line);
    list = Core::split(line, ' ');
    short int atomNum = Core::lexicalCast<short int>(list[0]);
    Core::Atom a = molecule.addAtom(static_cast<unsigned char>(atomNum));
    for (unsigned int j = 2; j < 5; ++j)
      pos(j - 2) = Core::lexicalCast<double>(list[j]);
    pos = pos * BOHR_TO_ANGSTROM;
    a.setPosition3d(pos);
  }

  // If the nAtoms were negative there is another line before
  // the data which is necessary, maybe contain 1 or more cubes
  unsigned int nCubes = 1;
  if (nAtoms < 0) {
    in >> nCubes;
    std::vector<unsigned int> moList(nCubes);
    for (unsigned int i = 0; i < nCubes; ++i)
      in >> moList[i];
    // clear buffer
    getline(in, line);
  }

  // Render molecule
  molecule.perceiveBondsSimple();

  // Cube block, set limits and populate data
  // min and spacing are in bohr units, convert to ANGSTROM
  for (unsigned int j = 0; j < 3; ++j) {
    min[j] *= BOHR_TO_ANGSTROM;
    spacing[j] *= BOHR_TO_ANGSTROM;
  }

  for (unsigned int i = 0; i < nCubes; ++i) {
    // Get a cube object from molecule
    Core::Cube* cube = molecule.addCube();

    cube->setLimits(min, dim, spacing);
    std::vector<double> values;
    // push_back is slow for this, resize vector first
    values.resize(dim(0) * dim(1) * dim(2));
    for (unsigned int j = 0; j < values.size(); ++j)
      in >> values[j];
    // clear buffer, if more than one cube
    getline(in, line);
    cube->setData(values);
  }

  return true;
}

bool GaussianCube::write(std::ostream&, const Core::Molecule&)
{
  // Not implemented yet
  return false;
}

} // End QuantumIO namespace
} // End Avogadro namespace
