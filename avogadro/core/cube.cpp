/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cube.h"

#include "molecule.h"
#include "mutex.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>

namespace Avogadro::Core {

Cube::Cube()
  : m_data(0), m_min(0.0, 0.0, 0.0), m_max(0.0, 0.0, 0.0),
    m_spacing(0.0, 0.0, 0.0), m_points(0, 0, 0), m_minValue(0.0),
    m_maxValue(0.0), m_cubeType(None), m_lock(nullptr),
    m_steps(Matrix3::Zero()), m_stepsInverse(Matrix3::Zero()),
    m_axisAligned(true)
{
}

Cube::~Cube()
{
  // delete m_lock;
  m_lock = nullptr;
}

namespace {

// Each axis needs at least minimumPoints points, and the total point count
// must fit in an int: setData() and the index helpers compute x * y * z as
// int. The product is taken in 64 bits so it cannot wrap while testing.
bool validPointCount(const Vector3i& points, int minimumPoints)
{
  if (points.x() < minimumPoints || points.y() < minimumPoints ||
      points.z() < minimumPoints)
    return false;
  const auto total = static_cast<std::uint64_t>(points.x()) *
                     static_cast<std::uint64_t>(points.y()) *
                     static_cast<std::uint64_t>(points.z());
  return total <= static_cast<std::uint64_t>(std::numeric_limits<int>::max());
}

bool validSpacing(const Vector3& spacing)
{
  return spacing.allFinite() && spacing.x() > 0.0 && spacing.y() > 0.0 &&
         spacing.z() > 0.0;
}

// A step matrix is usable when it is finite and its columns are linearly
// independent, judged against the size of the columns so the test does not
// depend on the unit (Angstrom or bohr) or on the grid being fine or coarse.
bool validSteps(const Matrix3& steps)
{
  if (!steps.allFinite())
    return false;
  const double scale =
    steps.col(0).norm() * steps.col(1).norm() * steps.col(2).norm();
  const double det = steps.determinant();
  if (!std::isfinite(scale) || !std::isfinite(det))
    return false;
  return std::abs(det) > 1.0e-9 * scale;
}

// Truncating a double outside int's range is undefined, so index conversions
// are clamped well inside it.
int truncateIndex(double value)
{
  constexpr double limit = 1.0e9;
  if (!(value > -limit))
    return value < 0.0 ? -static_cast<int>(limit) : 0; // NaN -> 0
  if (value > limit)
    return static_cast<int>(limit);
  return static_cast<int>(value);
}

} // namespace

bool Cube::setLimits(const Vector3& min_, const Vector3& max_,
                     const Vector3i& points)
{
  // The spacing is delta / (points - 1), so a single point on any axis has
  // no defined spacing (and zero or negative counts none at all).
  if (!validPointCount(points, 2) || !min_.allFinite() || !max_.allFinite())
    return false;

  // We can calculate all necessary properties and initialise our data
  Vector3 delta = max_ - min_;
  const Vector3 spacing_(delta.x() / (points.x() - 1),
                         delta.y() / (points.y() - 1),
                         delta.z() / (points.z() - 1));
  if (!spacing_.allFinite())
    return false;
  applyLimits(min_, points, Matrix3(spacing_.asDiagonal()));
  // Keep the caller's far corner exactly, rather than the recomputed one.
  m_max = max_;
  return true;
}

bool Cube::setLimits(const Vector3& min_, const Vector3& max_, float spacing_)
{
  if (!std::isfinite(spacing_) || spacing_ <= 0.0f)
    return false;
  Vector3 delta = max_ - min_;
  delta = delta / spacing_;
  // Converting a double outside int's range is undefined behaviour, so
  // anything that large is rejected here; the overload below rejects
  // anything under two points per axis.
  constexpr double maxPoints = std::numeric_limits<int>::max();
  if (!delta.allFinite() || delta.x() >= maxPoints || delta.y() >= maxPoints ||
      delta.z() >= maxPoints || delta.minCoeff() < 0.0)
    return false;
  return setLimits(min_, max_, delta.cast<int>());
}

bool Cube::setLimits(const Vector3& min_, const Vector3i& dim, float spacing_)
{
  return setLimits(min_, dim, Vector3(spacing_, spacing_, spacing_));
}

bool Cube::setLimits(const Vector3& min_, const Vector3i& dim,
                     const Vector3& spacing_)
{
  // The spacing is given, so one point per axis is well defined here.
  if (!validPointCount(dim, 1) || !validSpacing(spacing_) || !min_.allFinite())
    return false;

  applyLimits(min_, dim, Matrix3(spacing_.asDiagonal()));
  return true;
}

bool Cube::setStepLimits(const Vector3& origin, const Vector3i& dim,
                         const Matrix3& steps_)
{
  if (!validPointCount(dim, 1) || !origin.allFinite() || !validSteps(steps_))
    return false;
  applyLimits(origin, dim, steps_);
  return true;
}

void Cube::applyLimits(const Vector3& origin, const Vector3i& dim,
                       const Matrix3& steps_)
{
  m_min = origin;
  m_points = dim;
  m_steps = steps_;
  m_axisAligned = steps_(0, 1) == 0.0 && steps_(0, 2) == 0.0 &&
                  steps_(1, 0) == 0.0 && steps_(1, 2) == 0.0 &&
                  steps_(2, 0) == 0.0 && steps_(2, 1) == 0.0;

  const Vector3 last(dim.x() - 1, dim.y() - 1, dim.z() - 1);
  m_max = origin + steps_ * last;

  if (m_axisAligned) {
    m_spacing = Vector3(steps_(0, 0), steps_(1, 1), steps_(2, 2));
    // A diagonal with a zero entry is singular; keep the inverse zero then.
    m_stepsInverse.setZero();
    for (int d = 0; d < 3; ++d)
      if (steps_(d, d) != 0.0)
        m_stepsInverse(d, d) = 1.0 / steps_(d, d);
  } else {
    m_spacing =
      Vector3(steps_.col(0).norm(), steps_.col(1).norm(), steps_.col(2).norm());
    m_stepsInverse =
      validSteps(steps_) ? Matrix3(steps_.inverse()) : Matrix3(Matrix3::Zero());
  }
  m_data.resize(static_cast<size_t>(m_points.x()) * m_points.y() *
                m_points.z());
}

void Cube::boundingBox(Vector3& lo, Vector3& hi) const
{
  lo = hi = m_min;
  const Vector3 last(m_points.x() - 1, m_points.y() - 1, m_points.z() - 1);
  for (int corner = 1; corner < 8; ++corner) {
    Vector3 r = m_min;
    for (int d = 0; d < 3; ++d)
      if (corner & (1 << d))
        r += m_steps.col(d) * last(d);
    lo = lo.cwiseMin(r);
    hi = hi.cwiseMax(r);
  }
}

bool Cube::fractionalIndex(const Vector3& pos, Vector3& index) const
{
  if (!pos.allFinite())
    return false;
  const Vector3 delta = pos - m_min;
  if (m_axisAligned) {
    // Divide rather than multiply by the inverse, as the code always has.
    for (int d = 0; d < 3; ++d) {
      if (m_spacing(d) == 0.0)
        return false;
      index(d) = delta(d) / m_spacing(d);
    }
  } else {
    index = m_stepsInverse * delta;
  }
  return index.allFinite();
}

bool Cube::setLimits(const Cube& cube)
{
  if (!validPointCount(cube.m_points, 1))
    return false;

  m_min = cube.m_min;
  m_max = cube.m_max;
  m_points = cube.m_points;
  m_spacing = cube.m_spacing;
  m_steps = cube.m_steps;
  m_stepsInverse = cube.m_stepsInverse;
  m_axisAligned = cube.m_axisAligned;
  m_data.resize(static_cast<size_t>(m_points.x()) * m_points.y() *
                m_points.z());
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
  // Initialise the cube to zero if necessary
  if (m_data.empty())
    m_data.resize(m_points.x() * m_points.y() * m_points.z());
  if (values.size() != m_data.size() || values.empty())
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
  // The result always refers to a point of the grid: positions outside it
  // give the nearest edge point instead of an out-of-range index.
  if (m_points.x() < 1 || m_points.y() < 1 || m_points.z() < 1)
    return 0;
  const Vector3i idx = indexVector(pos);
  const int i = std::min(std::max(idx.x(), 0), m_points.x() - 1);
  const int j = std::min(std::max(idx.y(), 0), m_points.y() - 1);
  const int k = std::min(std::max(idx.z(), 0), m_points.z() - 1);
  return static_cast<unsigned int>(i * m_points.y() * m_points.z() +
                                   j * m_points.z() + k);
}

Vector3i Cube::indexVector(const Vector3& pos) const
{
  // Calculate how many steps each coordinate is along its axis, truncating
  // toward zero. A position that is not finite gives the origin index.
  Vector3 frac;
  if (!fractionalIndex(pos, frac))
    return Vector3i(0, 0, 0);
  return Vector3i(truncateIndex(frac.x()), truncateIndex(frac.y()),
                  truncateIndex(frac.z()));
}

Vector3 Cube::position(unsigned int index) const
{
  if (m_points.y() < 1 || m_points.z() < 1)
    return m_min;
  const unsigned int yz =
    static_cast<unsigned int>(m_points.y()) * m_points.z();
  const unsigned int x = index / yz;
  const unsigned int y = (index - x * yz) / m_points.z();
  const unsigned int z = index % m_points.z();
  return m_min + m_steps * Vector3(x, y, z);
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
  const int nx = m_points.x();
  const int ny = m_points.y();
  const int nz = m_points.z();
  std::array<float, 3> ret = { 0.0f, 0.0f, 0.0f };
  if (i < 0 || j < 0 || k < 0 || i >= nx || j >= ny || k >= nz ||
      m_data.size() != static_cast<size_t>(nx) * ny * nz)
    return ret;
  const int dataIdx = (i * ny * nz) + (j * nz) + k;

  // Differences along each grid index. diff[d] is the "next" sample minus the
  // "previous" one (the point itself at an edge) and run[d] the number of
  // index steps between them: 1 at an edge, 2 inside, and 0 for an axis with
  // a single point, which has no gradient.
  const std::array<int, 3> idx = { i, j, k };
  const std::array<int, 3> count = { nx, ny, nz };
  const std::array<int, 3> stride = { ny * nz, nz, 1 };
  std::array<float, 3> diff;
  std::array<float, 3> run;
  for (int d = 0; d < 3; ++d) {
    if (count[d] < 2) {
      diff[d] = 0.0f;
      run[d] = 0.0f;
      continue;
    }
    const float next =
      m_data[idx[d] == count[d] - 1 ? dataIdx : dataIdx + stride[d]];
    const float prev = m_data[idx[d] == 0 ? dataIdx : dataIdx - stride[d]];
    diff[d] = next - prev;
    run[d] = (idx[d] == 0 || idx[d] == count[d] - 1) ? 1.0f : 2.0f;
  }

  if (m_axisAligned) {
    // Same arithmetic as ever: the difference over the distance in space.
    for (int d = 0; d < 3; ++d) {
      const float distance = static_cast<float>(run[d] * m_spacing(d));
      ret[d] = (run[d] > 0.0f && distance != 0.0f) ? diff[d] / distance : 0.0f;
    }
    return ret;
  }

  // f(origin + S u) has index-space gradient S^T grad f, so the gradient in
  // space is S^{-T} times the index-space one.
  Vector3 indexGrad(0.0, 0.0, 0.0);
  for (int d = 0; d < 3; ++d)
    if (run[d] > 0.0f)
      indexGrad(d) = static_cast<double>(diff[d]) / run[d];
  const Vector3 world = m_stepsInverse.transpose() * indexGrad;
  for (int d = 0; d < 3; ++d)
    ret[d] = std::isfinite(world(d)) ? static_cast<float>(world(d)) : 0.0f;
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
  if (i < 0 || j < 0 || k < 0 || i >= m_points.x() || j >= m_points.y() ||
      k >= m_points.z())
    return 0.0f;
  const size_t index = (static_cast<size_t>(i) * m_points.y() + j) *
                         static_cast<size_t>(m_points.z()) +
                       k;
  return index < m_data.size() ? m_data[index] : 0.0f;
}

std::array<std::array<float, 3>, 8> Cube::getPosCube(int i, int j, int k) const
{

  std::array<std::array<float, 3>, 8> pos;

  if (!m_axisAligned) {
    // Corners in the order of getValsCube: the cell spanned by one step
    // along each of the three step vectors.
    static constexpr int corners[8][3] = { { 0, 0, 0 }, { 1, 0, 0 },
                                           { 1, 1, 0 }, { 0, 1, 0 },
                                           { 0, 0, 1 }, { 1, 0, 1 },
                                           { 1, 1, 1 }, { 0, 1, 1 } };
    for (int c = 0; c < 8; ++c) {
      const Vector3 r =
        m_min + m_steps * Vector3(i + corners[c][0], j + corners[c][1],
                                  k + corners[c][2]);
      pos[c] = { static_cast<float>(r.x()), static_cast<float>(r.y()),
                 static_cast<float>(r.z()) };
    }
    return pos;
  }

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
  return value(pos.cast<double>().eval());
}

float Cube::value(const Vector3& pos) const
{
  // This is a really expensive operation and so should be avoided
  // Interpolate the value at the supplied vector - trilinear interpolation
  // in index space, so skewed grids need nothing special.
  Vector3 frac;
  if (!fractionalIndex(pos, frac))
    return 0.0f;
  // Far outside the grid everything is zero (and the int conversion below
  // would not be defined).
  if (frac.cwiseAbs().maxCoeff() > 1.0e9)
    return 0.0f;
  const Vector3 low = frac.array().floor().matrix();
  const Vector3i lC(static_cast<int>(low.x()), static_cast<int>(low.y()),
                    static_cast<int>(low.z()));
  const Vector3i hC(lC.x() + 1, lC.y() + 1, lC.z() + 1);
  const Vector3 P = frac - low;
  const Vector3 dP = Vector3(1.0, 1.0, 1.0) - P;
  // Points outside the grid count as zero (getData() checks the bounds).
  auto at = [this](int a, int b, int c) {
    return static_cast<double>(getData(a, b, c));
  };
  return static_cast<float>(
    at(lC.x(), lC.y(), lC.z()) * dP.x() * dP.y() * dP.z() +
    at(hC.x(), lC.y(), lC.z()) * P.x() * dP.y() * dP.z() +
    at(lC.x(), hC.y(), lC.z()) * dP.x() * P.y() * dP.z() +
    at(lC.x(), lC.y(), hC.z()) * dP.x() * dP.y() * P.z() +
    at(hC.x(), lC.y(), hC.z()) * P.x() * dP.y() * P.z() +
    at(lC.x(), hC.y(), hC.z()) * dP.x() * P.y() * P.z() +
    at(hC.x(), hC.y(), lC.z()) * P.x() * P.y() * dP.z() +
    at(hC.x(), hC.y(), hC.z()) * P.x() * P.y() * P.z());
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
