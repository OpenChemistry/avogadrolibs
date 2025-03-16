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
    m_maxValue(0.0), m_cubeType(None), m_lock(new Mutex)
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
  // We can calculate all necessary properties and initialize our data
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
  if (values.empty())
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
  // Initialize the cube to zero if necessary
  if (m_data.empty())
    m_data.resize(m_points.x() * m_points.y() * m_points.z());

  if (values.size() != m_data.size() || values.empty())
    return false;

  // Update data and min/max
  for (unsigned int i = 0; i < m_data.size(); ++i) {
    m_data[i] += values[i];
    if (m_data[i] < m_minValue)
      m_minValue = m_data[i];
    else if (m_data[i] > m_maxValue)
      m_maxValue = m_data[i];
  }
  return true;
}

// Return the 1D index for a given (x=i, y=j, z=k) in row-major [x, y, z]:
static inline unsigned int idx(unsigned int x, unsigned int y, unsigned int z,
                               unsigned int Nx, unsigned int Ny, unsigned int /*Nz*/)
{
  return x + Nx * (y + Ny * z);
}

unsigned int Cube::closestIndex(const Vector3& pos) const
{
  int i = int((pos.x() - m_min.x()) / m_spacing.x());
  int j = int((pos.y() - m_min.y()) / m_spacing.y());
  int k = int((pos.z() - m_min.z()) / m_spacing.z());

  if (i < 0) i = 0; // clamp to [0, Nx-1] if needed
  if (j < 0) j = 0;
  if (k < 0) k = 0;
  if (i >= m_points.x()) i = m_points.x() - 1;
  if (j >= m_points.y()) j = m_points.y() - 1;
  if (k >= m_points.z()) k = m_points.z() - 1;

  return idx(i, j, k, m_points.x(), m_points.y(), m_points.z());
}

Vector3i Cube::indexVector(const Vector3& pos) const
{
  // Calculate how many steps each coordinate is along its axis
  int i = int((pos.x() - m_min.x()) / m_spacing.x());
  int j = int((pos.y() - m_min.y()) / m_spacing.y());
  int k = int((pos.z() - m_min.z()) / m_spacing.z());
  return Vector3i(i, j, k);
}

Vector3 Cube::position(unsigned int index) const
{
  // Reverse of index = x + Nx*(y + Ny*z)
  unsigned int Nx = m_points.x();
  unsigned int Ny = m_points.y();
  unsigned int Nz = m_points.z();

  unsigned int z = index / (Nx * Ny);
  unsigned int remainder = index % (Nx * Ny);
  unsigned int y = remainder / Nx;
  unsigned int x = remainder % Nx;

  return Vector3(
    x * m_spacing.x() + m_min.x(),
    y * m_spacing.y() + m_min.y(),
    z * m_spacing.z() + m_min.z()
  );
}

float Cube::value(int i, int j, int k) const
{
  unsigned int Nx = m_points.x();
  unsigned int Ny = m_points.y();
  unsigned int Nz = m_points.z();

  if (i < 0 || i >= static_cast<int>(Nx) ||
      j < 0 || j >= static_cast<int>(Ny) ||
      k < 0 || k >= static_cast<int>(Nz)) {
    return 0.0f;
  }

  unsigned int index = idx(i, j, k, Nx, Ny, Nz);
  return m_data[index];
}

std::array<float, 3> Cube::computeGradient(int i, int j, int k) const
{
  // For convenience
  int nx = m_points.x();
  int ny = m_points.y();
  int nz = m_points.z();

  // If out of range, just return zero gradient
  if (i < 0 || j < 0 || k < 0 || i >= nx || j >= ny || k >= nz) {
    return {0.0f, 0.0f, 0.0f};
  }

  // Index of the current voxel
  int dataIdx = i + nx * (j + ny * k);

  // We'll store the pair of values in x[coord][0,1]
  // [0] = forward (pos), [1] = backward (neg)
  std::array<std::array<float, 2>, 3> x;
  std::array<float, 3> run;

  // ----- X direction -----
  if (i == 0) {
    // forward neighbor
    x[0][0] = m_data[dataIdx + 1];
    // no backward neighbor, so use current
    x[0][1] = m_data[dataIdx];
    run[0] = m_spacing.x();
  }
  else if (i == nx - 1) {
    // no forward neighbor, so use current
    x[0][0] = m_data[dataIdx];
    // backward neighbor
    x[0][1] = m_data[dataIdx - 1];
    run[0] = m_spacing.x();
  }
  else {
    x[0][0] = m_data[dataIdx + 1];
    x[0][1] = m_data[dataIdx - 1];
    run[0] = 2.0f * m_spacing.x();
  }

  // ----- Y direction -----
  if (j == 0) {
    x[1][0] = m_data[dataIdx + nx];
    x[1][1] = m_data[dataIdx];
    run[1] = m_spacing.y();
  }
  else if (j == ny - 1) {
    x[1][0] = m_data[dataIdx];
    x[1][1] = m_data[dataIdx - nx];
    run[1] = m_spacing.y();
  }
  else {
    x[1][0] = m_data[dataIdx + nx];
    x[1][1] = m_data[dataIdx - nx];
    run[1] = 2.0f * m_spacing.y();
  }

  // ----- Z direction -----
  if (k == 0) {
    x[2][0] = m_data[dataIdx + (nx * ny)];
    x[2][1] = m_data[dataIdx];
    run[2] = m_spacing.z();
  }
  else if (k == nz - 1) {
    x[2][0] = m_data[dataIdx];
    x[2][1] = m_data[dataIdx - (nx * ny)];
    run[2] = m_spacing.z();
  }
  else {
    x[2][0] = m_data[dataIdx + (nx * ny)];
    x[2][1] = m_data[dataIdx - (nx * ny)];
    run[2] = 2.0f * m_spacing.z();
  }

  // final gradient in x,y,z
  std::array<float, 3> ret;
  // derivative = (negVal - posVal) / distance
  ret[0] = (x[0][1] - x[0][0]) / run[0];
  ret[1] = (x[1][1] - x[1][0]) / run[1];
  ret[2] = (x[2][1] - x[2][0]) / run[2];

  return ret;
}

std::array<std::array<float, 3>, 8>
Cube::getGradCube(int i, int j, int k) const
{
  std::array<std::array<float, 3>, 8> grad;

  grad[0] = computeGradient(i,     j,     k);
  grad[1] = computeGradient(i + 1, j,     k);
  grad[2] = computeGradient(i + 1, j + 1, k);
  grad[3] = computeGradient(i,     j + 1, k);
  grad[4] = computeGradient(i,     j,     k + 1);
  grad[5] = computeGradient(i + 1, j,     k + 1);
  grad[6] = computeGradient(i + 1, j + 1, k + 1);
  grad[7] = computeGradient(i,     j + 1, k + 1);

  return grad;
}

std::array<float, 8> Cube::getValsCube(int i, int j, int k) const
{
  std::array<float, 8> vals;

  vals[0] = getData(i,     j,     k);
  vals[1] = getData(i + 1, j,     k);
  vals[2] = getData(i + 1, j + 1, k);
  vals[3] = getData(i,     j + 1, k);
  vals[4] = getData(i,     j,     k + 1);
  vals[5] = getData(i + 1, j,     k + 1);
  vals[6] = getData(i + 1, j + 1, k + 1);
  vals[7] = getData(i,     j + 1, k + 1);

  return vals;
}

float Cube::getData(int i, int j, int k) const
{
  unsigned int Nx = m_points.x();
  unsigned int Ny = m_points.y();
  unsigned int Nz = m_points.z();
  // clamp or check if out-of-range as needed
  if (i < 0 || i >= static_cast<int>(Nx) ||
      j < 0 || j >= static_cast<int>(Ny) ||
      k < 0 || k >= static_cast<int>(Nz)) {
    return 0.0f;
  }
  unsigned int index = idx(i, j, k, Nx, Ny, Nz);
  return m_data[index];
}

std::array<std::array<float, 3>, 8> Cube::getPosCube(int i, int j, int k) const
{
  std::array<std::array<float, 3>, 8> pos;

  float xpos = m_min.x() + (i * m_spacing.x());
  float ypos = m_min.y() + (j * m_spacing.y());
  float zpos = m_min.z() + (k * m_spacing.z());

  pos[0] = { xpos,            ypos,            zpos };
  pos[1] = { xpos + m_spacing.x(), ypos,            zpos };
  pos[2] = { xpos + m_spacing.x(), ypos + m_spacing.y(), zpos };
  pos[3] = { xpos,            ypos + m_spacing.y(), zpos };
  pos[4] = { xpos,            ypos,            zpos + m_spacing.z() };
  pos[5] = { xpos + m_spacing.x(), ypos,            zpos + m_spacing.z() };
  pos[6] = { xpos + m_spacing.x(), ypos + m_spacing.y(), zpos + m_spacing.z() };
  pos[7] = { xpos,            ypos + m_spacing.y(), zpos + m_spacing.z() };

  return pos;
}

float Cube::value(const Vector3i& pos) const
{
  unsigned int Nx = m_points.x();
  unsigned int Ny = m_points.y();
  unsigned int Nz = m_points.z();
  int i = pos.x(), j = pos.y(), k = pos.z();
  if (i < 0 || i >= static_cast<int>(Nx) ||
      j < 0 || j >= static_cast<int>(Ny) ||
      k < 0 || k >= static_cast<int>(Nz))
    return 6969.0f;

  unsigned int index = idx(i, j, k, Nx, Ny, Nz);
  return m_data[index];
}

float Cube::valuef(const Vector3f& pos) const
{
  // Trilinear interpolation in float
  Vector3f delta = pos - m_min.cast<float>();
  Vector3f spacingf = m_spacing.cast<float>();

  // integer corners
  int i = static_cast<int>(delta.x() / spacingf.x());
  int j = static_cast<int>(delta.y() / spacingf.y());
  int k = static_cast<int>(delta.z() / spacingf.z());

  // clamp to volume bounds if needed
  if (i < 0) i = 0;
  if (j < 0) j = 0;
  if (k < 0) k = 0;
  if (i >= m_points.x()-1) i = m_points.x()-2;
  if (j >= m_points.y()-1) j = m_points.y()-2;
  if (k >= m_points.z()-1) k = m_points.z()-2;

  int i1 = i + 1;
  int j1 = j + 1;
  int k1 = k + 1;

  // fractional offsets in each direction
  float fx = (delta.x() - i*spacingf.x()) / spacingf.x();
  float fy = (delta.y() - j*spacingf.y()) / spacingf.y();
  float fz = (delta.z() - k*spacingf.z()) / spacingf.z();

  float c000 = value(i,  j,  k);
  float c100 = value(i1, j,  k);
  float c010 = value(i,  j1, k);
  float c001 = value(i,  j,  k1);
  float c110 = value(i1, j1, k);
  float c101 = value(i1, j,  k1);
  float c011 = value(i,  j1, k1);
  float c111 = value(i1, j1, k1);

  // trilinear interpolation
  return c000 * (1 - fx)*(1 - fy)*(1 - fz) +
         c100 * (    fx)*(1 - fy)*(1 - fz) +
         c010 * (1 - fx)*(    fy)*(1 - fz) +
         c001 * (1 - fx)*(1 - fy)*(    fz) +
         c101 * (    fx)*(1 - fy)*(    fz) +
         c011 * (1 - fx)*(    fy)*(    fz) +
         c110 * (    fx)*(    fy)*(1 - fz) +
         c111 * (    fx)*(    fy)*(    fz);
}

float Cube::value(const Vector3& pos) const
{
  // Same as valuef(), but using double
  Vector3 delta = pos - m_min;
  Vector3 spacingd = m_spacing;

  // integer corners
  int i = static_cast<int>(delta.x() / spacingd.x());
  int j = static_cast<int>(delta.y() / spacingd.y());
  int k = static_cast<int>(delta.z() / spacingd.z());

  if (i < 0) i = 0;
  if (j < 0) j = 0;
  if (k < 0) k = 0;
  if (i >= m_points.x()-1) i = m_points.x()-2;
  if (j >= m_points.y()-1) j = m_points.y()-2;
  if (k >= m_points.z()-1) k = m_points.z()-2;

  int i1 = i + 1;
  int j1 = j + 1;
  int k1 = k + 1;

  double fx = (delta.x() - i*spacingd.x()) / spacingd.x();
  double fy = (delta.y() - j*spacingd.y()) / spacingd.y();
  double fz = (delta.z() - k*spacingd.z()) / spacingd.z();

  double c000 = value(i,  j,  k);
  double c100 = value(i1, j,  k);
  double c010 = value(i,  j1, k);
  double c001 = value(i,  j,  k1);
  double c110 = value(i1, j1, k);
  double c101 = value(i1, j,  k1);
  double c011 = value(i,  j1, k1);
  double c111 = value(i1, j1, k1);

  return c000 * (1 - fx)*(1 - fy)*(1 - fz) +
         c100 * (    fx)*(1 - fy)*(1 - fz) +
         c010 * (1 - fx)*(    fy)*(1 - fz) +
         c001 * (1 - fx)*(1 - fy)*(    fz) +
         c101 * (    fx)*(1 - fy)*(    fz) +
         c011 * (1 - fx)*(    fy)*(    fz) +
         c110 * (    fx)*(    fy)*(1 - fz) +
         c111 * (    fx)*(    fy)*(    fz);
}

bool Cube::setValue(unsigned int i, unsigned int j, unsigned int k, float value_)
{
  unsigned int Nx = m_points.x();
  unsigned int Ny = m_points.y();
  unsigned int Nz = m_points.z();

  if (i >= Nx || j >= Ny || k >= Nz)
    return false;

  unsigned int index = idx(i, j, k, Nx, Ny, Nz);
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

bool Cube::fillStripe(unsigned int i, unsigned int j,
                      unsigned int kfirst, unsigned int klast, float value_)
{
  // Because x is now the fastest dimension in memory, changing k does NOT give
  // us a contiguous stripe. We'll just loop rather than a single std::fill.
  // If you only want to fill contiguous memory, you'd need x in that dimension.
  
  unsigned int Nx = m_points.x();
  unsigned int Ny = m_points.y();
  unsigned int Nz = m_points.z();

  if (i >= Nx || j >= Ny || kfirst > klast || klast >= Nz)
    return false;

  for (unsigned int k = kfirst; k <= klast; ++k) {
    unsigned int index = idx(i, j, k, Nx, Ny, Nz);
    m_data[index] = value_;
    // Optionally update min/max here, or do a full pass later
  }
  return true;
}

} // End Avogadro namespace
