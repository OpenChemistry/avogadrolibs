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

#include "cube.h"

#include "molecule.h"
#include "mutex.h"

namespace Avogadro {
namespace Core {

Cube::Cube()
  : m_data(0), m_min(0.0, 0.0, 0.0), m_max(0.0, 0.0, 0.0),
    m_spacing(0.0, 0.0, 0.0), m_points(0, 0, 0), m_minValue(0.0),
    m_maxValue(0.0), m_lock(new Mutex)
{
}

Cube::~Cube()
{
  delete m_lock;
  m_lock = nullptr;
}

bool Cube::setLimits(const Vector3& min_, const Vector3& max_,
                     const Vector3i& points)
{
  // We can calculate all necessary properties and initialise our data
  Vector3 delta = max_ - min_;
  m_spacing =
    Vector3(delta.x() / (points.x() - 1), delta.y() / (points.y() - 1),
            delta.z() / (points.z() - 1));
  m_min = min_;
  m_max = max_;
  m_points = points;
  m_data.resize(m_points.x() * m_points.y() * m_points.z());
  return true;
}

bool Cube::setLimits(const Vector3& min_, const Vector3& max_, double spacing_)
{
  Vector3 delta = max_ - min_;
  delta = delta / spacing_;
  return setLimits(min_, max_, delta.cast<int>());
}

bool Cube::setLimits(const Vector3& min_, const Vector3i& dim, double spacing_)
{
  return setLimits(min_, dim, Vector3(spacing_, spacing_, spacing_));
}

bool Cube::setLimits(const Vector3& min_, const Vector3i& dim,
                     const Vector3& spacing_)
{
  Vector3 max_ = Vector3(min_.x() + (dim.x() - 1) * spacing_[0],
                         min_.y() + (dim.y() - 1) * spacing_[1],
                         min_.z() + (dim.z() - 1) * spacing_[2]);
  m_min = min_;
  m_max = max_;
  m_points = dim;
  m_spacing = spacing_;
  m_data.resize(m_points.x() * m_points.y() * m_points.z());
  return true;
}

bool Cube::setLimits(const Cube& cube)
{
  m_min = cube.m_min;
  m_max = cube.m_max;
  m_points = cube.m_points;
  m_spacing = cube.m_spacing;
  m_data.resize(m_points.x() * m_points.y() * m_points.z());
  return true;
}

bool Cube::setLimits(const Molecule& mol, double spacing_, double padding)
{
  Index numAtoms = mol.atomCount();
  Vector3 min_, max_;
  if (numAtoms) {
    Vector3 curPos = min_ = max_ = mol.atomPositions3d()[0];
    for (Index i = 1; i < numAtoms; ++i) {
      curPos = mol.atomPositions3d()[i];
      if (curPos.x() < min_.x())
        min_.x() = curPos.x();
      if (curPos.x() > max_.x())
        max_.x() = curPos.x();
      if (curPos.y() < min_.y())
        min_.y() = curPos.y();
      if (curPos.y() > max_.y())
        max_.y() = curPos.y();
      if (curPos.z() < min_.z())
        min_.z() = curPos.z();
      if (curPos.z() > max_.z())
        max_.z() = curPos.z();
    }
  } else {
    min_ = max_ = Vector3::Zero();
  }

  // Now to take care of the padding term
  min_ += Vector3(-padding, -padding, -padding);
  max_ += Vector3(padding, padding, padding);

  return setLimits(min_, max_, spacing_);
}

std::vector<double>* Cube::data()
{
  return &m_data;
}

const std::vector<double>* Cube::data() const
{
  return &m_data;
}

bool Cube::setData(const std::vector<double>& values)
{
  if (!values.size())
    return false;

  if (static_cast<int>(values.size()) ==
      m_points.x() * m_points.y() * m_points.z()) {
    m_data = values;
    // Now to update the minimum and maximum values
    m_minValue = m_maxValue = m_data[0];
    for (std::vector<double>::const_iterator it = values.begin();
         it != values.end(); ++it) {
      if (*it < m_minValue)
        m_minValue = *it;
      else if (*it > m_maxValue)
        m_maxValue = *it;
    }
    return true;
  } else {
    return false;
  }
}

bool Cube::addData(const std::vector<double>& values)
{
  // Initialise the cube to zero if necessary
  if (!m_data.size())
    m_data.resize(m_points.x() * m_points.y() * m_points.z());
  if (values.size() != m_data.size() || !values.size())
    return false;
  for (unsigned int i = 0; i < m_data.size(); i++) {
    m_data[i] += values[i];
    if (m_data[i] < m_minValue)
      m_minValue = m_data[i];
    else if (m_data[i] > m_maxValue)
      m_maxValue = m_data[i];
  }
  return true;
}

unsigned int Cube::closestIndex(const Vector3& pos) const
{
  int i, j, k;
  // Calculate how many steps each coordinate is along its axis
  i = int((pos.x() - m_min.x()) / m_spacing.x());
  j = int((pos.y() - m_min.y()) / m_spacing.y());
  k = int((pos.z() - m_min.z()) / m_spacing.z());
  return i * m_points.y() * m_points.z() + j * m_points.z() + k;
}

Vector3i Cube::indexVector(const Vector3& pos) const
{
  // Calculate how many steps each coordinate is along its axis
  int i, j, k;
  i = int((pos.x() - m_min.x()) / m_spacing.x());
  j = int((pos.y() - m_min.y()) / m_spacing.y());
  k = int((pos.z() - m_min.z()) / m_spacing.z());
  return Vector3i(i, j, k);
}

Vector3 Cube::position(unsigned int index) const
{
  int x, y, z;
  x = int(index / (m_points.y() * m_points.z()));
  y = int((index - (x * m_points.y() * m_points.z())) / m_points.z());
  z = index % m_points.z();
  return Vector3(x * m_spacing.x() + m_min.x(), y * m_spacing.y() + m_min.y(),
                 z * m_spacing.z() + m_min.z());
}

double Cube::value(int i, int j, int k) const
{
  unsigned int index = i * m_points.y() * m_points.z() + j * m_points.z() + k;
  if (index < m_data.size())
    return m_data[index];
  else
    return 0.0;
}

double Cube::value(const Vector3i& pos) const
{
  unsigned int index =
    pos.x() * m_points.y() * m_points.z() + pos.y() * m_points.z() + pos.z();
  if (index < m_data.size())
    return m_data[index];
  else
    return 6969.0;
}

float Cube::valuef(const Vector3f& pos) const
{
  // This is a really expensive operation and so should be avoided
  // Interpolate the value at the supplied vector - trilinear interpolation...
  Vector3f delta = pos - m_min.cast<float>();
  // Find the integer low and high corners
  Vector3i lC(static_cast<int>(delta.x() / m_spacing.x()),
              static_cast<int>(delta.y() / m_spacing.y()),
              static_cast<int>(delta.z() / m_spacing.z()));
  Vector3i hC(lC.x() + 1, lC.y() + 1, lC.z() + 1);
  // So there are six corners in total - work out the delta of the position
  // and the low corner
  const Vector3f lCf(lC.cast<float>());
  const Vector3f spacingf(m_spacing.cast<float>());
  Vector3f P((delta.x() - lCf.x() * spacingf.x()) / spacingf.x(),
             (delta.y() - lCf.y() * spacingf.y()) / spacingf.y(),
             (delta.z() - lCf.z() * spacingf.z()) / spacingf.z());
  Vector3f dP = Vector3f(1.0f, 1.0f, 1.0f) - P;
  // Now calculate and return the interpolated value
  return static_cast<float>(
    value(lC.x(), lC.y(), lC.z()) * dP.x() * dP.y() * dP.z() +
    value(hC.x(), lC.y(), lC.z()) * P.x() * dP.y() * dP.z() +
    value(lC.x(), hC.y(), lC.z()) * dP.x() * P.y() * dP.z() +
    value(lC.x(), lC.y(), hC.z()) * dP.x() * dP.y() * P.z() +
    value(hC.x(), lC.y(), hC.z()) * P.x() * dP.y() * P.z() +
    value(lC.x(), hC.y(), hC.z()) * dP.x() * P.y() * P.z() +
    value(hC.x(), hC.y(), lC.z()) * P.x() * P.y() * dP.z() +
    value(hC.x(), hC.y(), hC.z()) * P.x() * P.y() * P.z());
}

double Cube::value(const Vector3& pos) const
{
  // This is a really expensive operation and so should be avoided
  // Interpolate the value at the supplied vector - trilinear interpolation...
  Vector3 delta = pos - m_min;
  // Find the integer low and high corners
  Vector3i lC(static_cast<int>(delta.x() / m_spacing.x()),
              static_cast<int>(delta.y() / m_spacing.y()),
              static_cast<int>(delta.z() / m_spacing.z()));
  Vector3i hC(lC.x() + 1, lC.y() + 1, lC.z() + 1);
  // So there are six corners in total - work out the delta of the position
  // and the low corner
  Vector3 P((delta.x() - lC.x() * m_spacing.x()) / m_spacing.x(),
            (delta.y() - lC.y() * m_spacing.y()) / m_spacing.y(),
            (delta.z() - lC.z() * m_spacing.z()) / m_spacing.z());
  Vector3 dP = Vector3(1.0, 1.0, 1.0) - P;
  // Now calculate and return the interpolated value
  return value(lC.x(), lC.y(), lC.z()) * dP.x() * dP.y() * dP.z() +
         value(hC.x(), lC.y(), lC.z()) * P.x() * dP.y() * dP.z() +
         value(lC.x(), hC.y(), lC.z()) * dP.x() * P.y() * dP.z() +
         value(lC.x(), lC.y(), hC.z()) * dP.x() * dP.y() * P.z() +
         value(hC.x(), lC.y(), hC.z()) * P.x() * dP.y() * P.z() +
         value(lC.x(), hC.y(), hC.z()) * dP.x() * P.y() * P.z() +
         value(hC.x(), hC.y(), lC.z()) * P.x() * P.y() * dP.z() +
         value(hC.x(), hC.y(), hC.z()) * P.x() * P.y() * P.z();
}

bool Cube::setValue(int i, int j, int k, double value_)
{
  unsigned int index = i * m_points.y() * m_points.z() + j * m_points.z() + k;
  if (index < m_data.size()) {
    m_data[index] = value_;
    if (value_ < m_minValue)
      m_minValue = value_;
    else if (value_ > m_maxValue)
      m_maxValue = value_;
    return true;
  } else {
    return false;
  }
}

} // End Core namespace
} // End Avogadro namespace
