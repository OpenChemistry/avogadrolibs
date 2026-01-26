/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cube.h"

#include "molecule.h"
#include "mutex.h"

namespace Avogadro::Core {

Cube::Cube()
  : m_data(0), m_min(0.0, 0.0, 0.0), m_max(0.0, 0.0, 0.0),
    m_spacing(0.0, 0.0, 0.0), m_points(0, 0, 0), m_minValue(0.0),
    m_maxValue(0.0), m_cubeType(None), m_lock(nullptr)
{
}

Cube::~Cube()
{
  // delete m_lock;
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
bool Cube::setLimits(const Vector3& min_, const Vector3& max_, float spacing_)
{
  Vector3 delta = max_ - min_;
  delta = delta / spacing_;
  return setLimits(min_, max_, delta.cast<int>());
}

bool Cube::setLimits(const Vector3& min_, const Vector3i& dim, float spacing_)
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

bool Cube::setLimits(const Molecule& mol, float spacing_, float padding)
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

std::vector<float>* Cube::data()
{
  return &m_data;
}

const std::vector<float>* Cube::data() const
{
  return &m_data;
}

bool Cube::setData(const std::vector<float>& values)
{
  if (!values.size())
    return false;

  if (static_cast<int>(values.size()) ==
      m_points.x() * m_points.y() * m_points.z()) {
    m_data = values;
    // Now to update the minimum and maximum values
    m_minValue = m_maxValue = m_data[0];
    for (float value : values) {
      if (value < m_minValue)
        m_minValue = value;
      else if (value > m_maxValue)
        m_maxValue = value;
    }
    return true;
  } else {
    return false;
  }
}

bool Cube::addData(const std::vector<float>& values)
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

float Cube::value(int i, int j, int k) const
{
  unsigned int index = i * m_points.y() * m_points.z() + j * m_points.z() + k;
  if (index < m_data.size())
    return m_data[index];
  else
    return 0.0;
}

std::array<float, 3> Cube::computeGradient(int i, int j, int k) const
{
  int nx = m_points.x();
  int ny = m_points.y();
  int nz = m_points.z();
  int dataIdx = (i * ny * nz) + (j * nz) + k;

  std::array<std::array<float, 2>, 3> x;
  std::array<float, 3> run;

  // X-direction
  if (i == 0) {
    x[0][0] = m_data[dataIdx + ny * nz];
    x[0][1] = m_data[dataIdx];
    run[0] = m_spacing.x();
  } else if (i == (nx - 1)) {
    x[0][0] = m_data[dataIdx];
    x[0][1] = m_data[dataIdx - ny * nz];
    run[0] = m_spacing.x();
  } else {
    x[0][0] = m_data[dataIdx + ny * nz];
    x[0][1] = m_data[dataIdx - ny * nz];
    run[0] = 2 * m_spacing.x();
  }

  // Y-direction
  if (j == 0) {
    x[1][0] = m_data[dataIdx + nz];
    x[1][1] = m_data[dataIdx];
    run[1] = m_spacing.y();
  } else if (j == (ny - 1)) {
    x[1][0] = m_data[dataIdx];
    x[1][1] = m_data[dataIdx - nz];
    run[1] = m_spacing.y();
  } else {
    x[1][0] = m_data[dataIdx + nz];
    x[1][1] = m_data[dataIdx - nz];
    run[1] = 2 * m_spacing.y();
  }

  // Z-direction
  if (k == 0) {
    x[2][0] = m_data[dataIdx + 1];
    x[2][1] = m_data[dataIdx];
    run[2] = m_spacing.z();
  } else if (k == (nz - 1)) {
    x[2][0] = m_data[dataIdx];
    x[2][1] = m_data[dataIdx - 1];
    run[2] = m_spacing.z();
  } else {
    x[2][0] = m_data[dataIdx + 1];
    x[2][1] = m_data[dataIdx - 1];
    run[2] = 2 * m_spacing.z();
  }

  std::array<float, 3> ret;

  ret[0] = (x[0][1] - x[0][0]) / run[0];
  ret[1] = (x[1][1] - x[1][0]) / run[1];
  ret[2] = (x[2][1] - x[2][0]) / run[2];

  return ret;
}

std::array<std::array<float, 3>, 8> Cube::getGradCube(int i, int j, int k) const
{
  std::array<std::array<float, 3>, 8> grad;

  grad[0] = computeGradient(i, j, k);
  grad[1] = computeGradient(i + 1, j, k);
  grad[2] = computeGradient(i + 1, j + 1, k);
  grad[3] = computeGradient(i, j + 1, k);
  grad[4] = computeGradient(i, j, k + 1);
  grad[5] = computeGradient(i + 1, j, k + 1);
  grad[6] = computeGradient(i + 1, j + 1, k + 1);
  grad[7] = computeGradient(i, j + 1, k + 1);

  return grad;
}

std::array<float, 8> Cube::getValsCube(int i, int j, int k) const
{
  std::array<float, 8> vals;

  vals[0] = getData(i, j, k);
  vals[1] = getData(i + 1, j, k);
  vals[2] = getData(i + 1, j + 1, k);
  vals[3] = getData(i, j + 1, k);
  vals[4] = getData(i, j, k + 1);
  vals[5] = getData(i + 1, j, k + 1);
  vals[6] = getData(i + 1, j + 1, k + 1);
  vals[7] = getData(i, j + 1, k + 1);

  return vals;
}

float Cube::getData(int i, int j, int k) const
{
  int ny = m_points.y();
  int nz = m_points.z();
  return m_data[(i * ny * nz) + (j * nz) + k];
}

std::array<std::array<float, 3>, 8> Cube::getPosCube(int i, int j, int k) const
{

  std::array<std::array<float, 3>, 8> pos;

  float xpos = m_min.x() + (i * m_spacing.x());
  float ypos = m_min.y() + (j * m_spacing.y());
  float zpos = m_min.z() + (k * m_spacing.z());

  pos[0][0] = xpos;
  pos[0][1] = ypos;
  pos[0][2] = zpos;

  pos[1][0] = xpos + m_spacing.x();
  pos[1][1] = ypos;
  pos[1][2] = zpos;

  pos[2][0] = xpos + m_spacing.x();
  pos[2][1] = ypos + m_spacing.y();
  pos[2][2] = zpos;

  pos[3][0] = xpos;
  pos[3][1] = ypos + m_spacing.y();
  pos[3][2] = zpos;

  pos[4][0] = xpos;
  pos[4][1] = ypos;
  pos[4][2] = zpos + m_spacing.z();

  pos[5][0] = xpos + m_spacing.x();
  pos[5][1] = ypos;
  pos[5][2] = zpos + m_spacing.z();

  pos[6][0] = xpos + m_spacing.x();
  pos[6][1] = ypos + m_spacing.y();
  pos[6][2] = zpos + m_spacing.z();

  pos[7][0] = xpos;
  pos[7][1] = ypos + m_spacing.y();
  pos[7][2] = zpos + m_spacing.z();

  return pos;
}

float Cube::value(const Vector3i& pos) const
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

float Cube::value(const Vector3& pos) const
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

bool Cube::setValue(unsigned int i, unsigned int j, unsigned int k,
                    float value_)
{
  unsigned int index = i * m_points.y() * m_points.z() + j * m_points.z() + k;
  if (index >= m_data.size())
    return false;
  m_data[index] = value_;
  if (value_ < m_minValue)
    m_minValue = value_;
  else if (value_ > m_maxValue)
    m_maxValue = value_;
  return true;
}

void Cube::fill(float value_)
{
  std::fill(m_data.begin(), m_data.end(), value_);
  m_minValue = m_maxValue = value_;
}

bool Cube::fillStripe(unsigned int i, unsigned int j, unsigned int kfirst,
                      unsigned int klast, float value_)
{
  unsigned int stripeStartIndex =
    i * m_points.y() * m_points.z() + j * m_points.z();
  unsigned int firstIndex = stripeStartIndex + kfirst;
  if (firstIndex >= m_data.size())
    return false;
  unsigned int lastIndex = stripeStartIndex + klast;
  if (lastIndex >= m_data.size())
    return false;
  std::fill(&m_data[firstIndex], &m_data[lastIndex + 1], value_);
  return true;
}

} // namespace Avogadro::Core
