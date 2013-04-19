/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008-2009 Marcus D. Hanwell
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "slaterset.h"

using std::vector;
using Eigen::Vector3d;
using Eigen::Vector3i;
using Eigen::MatrixXd;

namespace Avogadro {
namespace Core {

using std::vector;

static const double BOHR_TO_ANGSTROM = 0.529177249;
static const double ANGSTROM_TO_BOHR = 1.0 / 0.529177249;

SlaterSet::SlaterSet() : m_initialized(false)
{
}

SlaterSet::~SlaterSet()
{

}

bool SlaterSet::addAtoms(const std::vector<Eigen::Vector3d> &pos)
{
  m_atomPos = pos;
  return true;
}

bool SlaterSet::addSlaterIndices(const std::vector<int> &i)
{
  m_slaterIndices = i;
  return true;
}

bool SlaterSet::addSlaterTypes(const std::vector<int> &t)
{
  m_slaterTypes = t;
  return true;
}

bool SlaterSet::addZetas(const std::vector<double> &zetas)
{
  m_zetas = zetas;
  return true;
}

bool SlaterSet::addPQNs(const std::vector<int> &pqns)
{
  m_pqns = pqns;
  return true;
}

bool SlaterSet::addOverlapMatrix(const Eigen::MatrixXd &m)
{
  m_overlap.resize(m.rows(), m.cols());
  m_overlap = m;
  return true;
}

bool SlaterSet::addEigenVectors(const Eigen::MatrixXd &e)
{
  m_eigenVectors.resize(e.rows(), e.cols());
  m_eigenVectors = e;
  return true;
}

bool SlaterSet::addDensityMatrix(const Eigen::MatrixXd &d)
{
  m_density.resize(d.rows(), d.cols());
  m_density = d;
  return true;
}

unsigned int SlaterSet::molecularOrbitalCount(ElectronType)
{
  return static_cast<unsigned int>(m_overlap.cols());
}

void SlaterSet::outputAll()
{

}

} // End namespace Core
} // End namespace Avogadro
