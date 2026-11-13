/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "edtfill.h"

#include <avogadro/core/cube.h>

#include <QtConcurrent/QtConcurrent>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <limits>
#include <numeric>

namespace Avogadro::QtPlugins {

namespace {

// QtConcurrent::blockingMap(begin, end, task), with the hand-offs made
// visible to thread sanitizers, which cannot see the synchronization inside
// an uninstrumented Qt: each task acquires what the caller wrote before, and
// the caller acquires what every task wrote. Without them, every voxel
// raced, and matching those reports against suppressions cost TSan builds
// minutes per surface.
template <typename Iterator, typename Task>
void parallelFor(Iterator begin, Iterator end, Task&& task)
{
  std::atomic<int> handoff{ 0 };
  handoff.store(1, std::memory_order_release);
  // The element is read only after the acquire.
  QtConcurrent::blockingMap(begin, end, [&](const int& item) {
    handoff.load(std::memory_order_acquire);
    task(item);
    handoff.fetch_add(1, std::memory_order_acq_rel);
  });
  handoff.load(std::memory_order_acquire);
}

inline double square(double x)
{
  return x * x;
}

// True if the cube has a grid that matches its data, with a positive spacing.
bool usableGrid(const Core::Cube& cube)
{
  const Vector3i dims = cube.dimensions();
  const Vector3 spacing = cube.spacing();
  if (dims.minCoeff() < 1 || !spacing.allFinite() ||
      spacing.minCoeff() <= 0.0 || !cube.min().allFinite())
    return false;
  const size_t total = static_cast<size_t>(dims(0)) * dims(1) * dims(2);
  return cube.data() != nullptr && cube.data()->size() == total;
}

// Bin each sphere into every x slab it covers, extended by @p extra. The
// slabs outside the cube have no voxels to write and are skipped.
std::vector<std::vector<size_t>> binIntoSlabs(
  const Core::Cube& cube, const std::vector<EdtSphere>& spheres, double extra)
{
  const Vector3i dims = cube.dimensions();
  const Vector3 min = cube.min();
  const double sx = cube.spacing()(0);
  std::vector<std::vector<size_t>> slabs(dims(0));
  for (size_t a = 0; a < spheres.size(); ++a) {
    const double radius = spheres[a].second + extra;
    const double centerX = spheres[a].first(0);
    const double first = std::floor((centerX - radius - min(0)) / sx);
    const double last = std::floor((centerX + radius - min(0)) / sx) + 1.0;
    if (!std::isfinite(first) || !std::isfinite(last) || last < 0.0 ||
        first >= dims(0))
      continue;
    const int startX = static_cast<int>(std::max(first, 0.0));
    const int endX = static_cast<int>(std::min(last, double(dims(0))));
    for (int indexX = startX; indexX < endX; ++indexX)
      slabs[indexX].push_back(a);
  }
  return slabs;
}

// Set @p background over @p cube, then call
// perSphere(float* slab, double posX, const EdtSphere& sphere) for every
// sphere that reaches each x slab (@p extra grows the spheres for the
// binning). Overlapping spheres touch the same voxels, so threads must not be
// handed spheres: two of them would write one voxel at the same time. Instead
// each sphere is binned into every x slab (constant indexX) it covers, and
// each slab goes to exactly one thread. perSphere() only raises voxels above
// the background, so the result equals filling sphere by sphere. The caller
// has checked usableGrid().
template <typename PerSphere>
void forEachSlab(Core::Cube& cube, const std::vector<EdtSphere>& spheres,
                 double extra, float background, PerSphere&& perSphere)
{
  const Vector3i dims = cube.dimensions();
  const Vector3 min = cube.min();
  const Vector3 spacing = cube.spacing();
  float* data = cube.data()->data();
  const size_t slabSize = static_cast<size_t>(dims(1)) * dims(2);

  const std::vector<std::vector<size_t>> slabAtoms =
    binIntoSlabs(cube, spheres, extra);

  std::vector<int> slabIndices(dims(0));
  std::iota(slabIndices.begin(), slabIndices.end(), 0);

  parallelFor(slabIndices.begin(), slabIndices.end(), [&](int indexX) {
    float* slab = data + static_cast<size_t>(indexX) * slabSize;
    std::fill(slab, slab + slabSize, background);
    const double posX = indexX * spacing(0) + min(0);
    for (size_t a : slabAtoms[indexX])
      perSphere(slab, posX, spheres[a]);
  });
}

// Lower envelope of the parabolas cost_q(p) = g(q) + (s * (p - q))^2, for
// the finite g(q) among the n samples (Felzenszwalb and Huttenlocher,
// "Distance Transforms of Sampled Functions"). Writes the minimum at every
// p to @p out (infinity if no sample is finite). @p vertex and @p bound are
// scratch arrays of n + 1 entries; @p g and @p out may not overlap.
void lowerEnvelope(const double* g, int n, double s, double* out, int* vertex,
                   double* bound)
{
  const double inf = std::numeric_limits<double>::infinity();
  const double s2 = s * s;
  int k = -1; // index of the rightmost parabola in the envelope
  for (int q = 0; q < n; ++q) {
    if (!std::isfinite(g[q]))
      continue;
    if (k < 0) {
      k = 0;
      vertex[0] = q;
      bound[0] = -inf;
      bound[1] = inf;
      continue;
    }
    double cross = 0.0;
    while (true) { // bound[0] is -infinity, so k never goes below 0
      const int r = vertex[k];
      // Where the parabolas at q and r cost the same. q > r, so the
      // denominator is positive (and s > 0 is checked by usableGrid()).
      cross =
        ((g[q] + s2 * q * q) - (g[r] + s2 * r * r)) / (2.0 * s2 * (q - r));
      if (cross <= bound[k])
        --k;
      else
        break;
    }
    ++k;
    vertex[k] = q;
    bound[k] = cross;
    bound[k + 1] = inf;
  }
  if (k < 0) {
    for (int p = 0; p < n; ++p)
      out[p] = inf;
    return;
  }
  k = 0;
  for (int p = 0; p < n; ++p) {
    while (bound[k + 1] < p)
      ++k;
    const double d = s * (p - vertex[k]);
    out[p] = g[vertex[k]] + d * d;
  }
}

// Scratch for one task of the transform.
struct LineScratch
{
  std::vector<double> in, out, bound;
  std::vector<int> vertex;
  void resize(int n)
  {
    in.resize(n);
    out.resize(n);
    bound.resize(n + 1);
    vertex.resize(n + 1);
  }
};

// Transform the n values data[0], data[stride], ... in place.
void transformLine(float* data, size_t stride, int n, double s,
                   LineScratch& scratch)
{
  scratch.resize(n);
  for (int i = 0; i < n; ++i)
    scratch.in[i] = data[i * stride];
  lowerEnvelope(scratch.in.data(), n, s, scratch.out.data(),
                scratch.vertex.data(), scratch.bound.data());
  for (int i = 0; i < n; ++i)
    data[i * stride] = static_cast<float>(scratch.out[i]);
}

// Fill @p cube with @p inside in the spheres and @p outside elsewhere.
bool fillBinary(Core::Cube& cube, const std::vector<EdtSphere>& spheres,
                float inside, float outside)
{
  if (!usableGrid(cube))
    return false;

  const Vector3i dims = cube.dimensions();
  const Vector3 min = cube.min();
  const Vector3 spacing = cube.spacing();

  forEachSlab(
    cube, spheres, 0.0, outside,
    [&](float* slab, double posX, const EdtSphere& in) {
      const double radiusXsq = square(in.second) - square(posX - in.first(0));
      if (radiusXsq < 0.0)
        return;
      const double radiusX = std::sqrt(radiusXsq);
      const double startPosY = in.first(1) - radiusX;
      const double endPosY = in.first(1) + radiusX;
      const int startIndexY =
        static_cast<int>(std::max((startPosY - min(1)) / spacing(1), 0.0));
      const int endIndexY = static_cast<int>(std::min(
        (endPosY - min(1)) / spacing(1) + 1.0, static_cast<double>(dims(1))));
      for (int indexY = startIndexY; indexY < endIndexY; ++indexY) {
        const double posY = indexY * spacing(1) + min(1);
        const double lengthXYsq = square(radiusX) - square(posY - in.first(1));
        if (lengthXYsq < 0.0)
          continue;
        const double lengthXY = std::sqrt(lengthXYsq);
        const double startPosZ = in.first(2) - lengthXY;
        const double endPosZ = in.first(2) + lengthXY;
        // Round up: a voxel below startPosZ lies outside the sphere.
        const int firstZ = static_cast<int>(
          std::max(std::ceil((startPosZ - min(2)) / spacing(2)), 0.0));
        const int lastZ = static_cast<int>(std::min(
          (endPosZ - min(2)) / spacing(2), static_cast<double>(dims(2) - 1)));
        if (firstZ > lastZ)
          continue;
        float* stripe = slab + static_cast<size_t>(indexY) * dims(2);
        std::fill(stripe + firstZ, stripe + lastZ + 1, inside);
      }
    });
  return true;
}

} // namespace

void squaredDistanceTransform(std::vector<float>& squared,
                              const Vector3i& dimensions,
                              const Vector3& spacing)
{
  if (dimensions.minCoeff() < 1 || spacing.minCoeff() <= 0.0 ||
      !spacing.allFinite())
    return;
  const size_t dimX = static_cast<size_t>(dimensions(0));
  const size_t dimY = static_cast<size_t>(dimensions(1));
  const size_t dimZ = static_cast<size_t>(dimensions(2));
  if (squared.size() != dimX * dimY * dimZ)
    return;
  float* data = squared.data();

  // Each pass hands every line to exactly one task, so no two tasks write
  // the same voxel. The scratch is per pool thread. Line number l of a pass
  // starts at voxel base(l), and its n voxels are stride apart.
  std::vector<int> lines(std::max({ dimX * dimY, dimX * dimZ, dimY * dimZ }));
  std::iota(lines.begin(), lines.end(), 0);
  auto runPass = [&](size_t count, auto&& base, size_t stride, int n,
                     double lineSpacing) {
    parallelFor(lines.begin(), lines.begin() + count, [&](int line) {
      thread_local LineScratch scratch;
      transformLine(data + base(static_cast<size_t>(line)), stride, n,
                    lineSpacing, scratch);
    });
  };
  // Along z: contiguous, one line per (x, y).
  runPass(
    dimX * dimY, [&](size_t line) { return line * dimZ; }, 1, dimensions(2),
    spacing(2));
  // Along y: one line per (x, z), a stride of dimZ apart.
  runPass(
    dimX * dimZ,
    [&](size_t line) { return (line / dimZ) * dimY * dimZ + line % dimZ; },
    dimZ, dimensions(1), spacing(1));
  // Along x: one line per (y, z), a stride of dimY * dimZ apart.
  runPass(
    dimY * dimZ, [&](size_t line) { return line; }, dimY * dimZ, dimensions(0),
    spacing(0));
}

namespace {

constexpr double TwoPi = 6.283185307179586;
// A point this far inside a sphere's surface is not covered by it, which keeps
// tangent and coincident spheres from hiding each other.
constexpr double CoverTolerance = 1.0e-7;

// A sphere of the solvent-accessible surface.
struct Ball
{
  Vector3 center;
  double radius;
};

// A ball overlapping another, with what the cover test needs inline.
struct Neighbor
{
  Vector3 center;
  double coverSq; // (radius - CoverTolerance)^2
  double radius;
  std::uint32_t index;
};

// True if @p point is strictly inside none of @p neighbors, that is on the
// surface of their union. @p last is the one that covered the previous point
// asked about, which is likely to cover this one: it is tried first.
bool isExposed(const Vector3& point, const std::vector<Neighbor>& neighbors,
               const Neighbor*& last)
{
  if (last != nullptr && (point - last->center).squaredNorm() < last->coverSq)
    return false;
  for (const Neighbor& neighbor : neighbors) {
    if ((point - neighbor.center).squaredNorm() < neighbor.coverSq) {
      last = &neighbor;
      return false;
    }
  }
  return true;
}

// The balls in a dense grid of cells, for finding those near a point.
class BallGrid
{
public:
  explicit BallGrid(const std::vector<Ball>& balls)
  {
    m_min = balls[0].center;
    Vector3 max = balls[0].center;
    for (const Ball& ball : balls) {
      m_min = m_min.cwiseMin(ball.center);
      max = max.cwiseMax(ball.center);
    }
    // Keep the number of cells in check for widely spread atoms.
    m_cell = 2.0;
    const Vector3 extent = max - m_min;
    while (cellCount(extent, m_cell) > 4.0e6)
      m_cell *= 2.0;
    for (int axis = 0; axis < 3; ++axis)
      m_dims[axis] = static_cast<int>(extent(axis) / m_cell) + 1;
    m_start.assign(static_cast<size_t>(m_dims[0]) * m_dims[1] * m_dims[2] + 1,
                   0);
    for (const Ball& ball : balls)
      ++m_start[cellOf(ball.center) + 1];
    for (size_t i = 1; i < m_start.size(); ++i)
      m_start[i] += m_start[i - 1];
    std::vector<size_t> fill(m_start.begin(), m_start.end() - 1);
    m_items.resize(balls.size());
    for (size_t b = 0; b < balls.size(); ++b)
      m_items[fill[cellOf(balls[b].center)]++] = static_cast<std::uint32_t>(b);
  }

  // Call visit(index) for every ball whose center lies within @p reach of
  // @p point, and possibly for a few farther away.
  template <typename Visit>
  void forEachNear(const Vector3& point, double reach, Visit&& visit) const
  {
    int low[3], high[3];
    for (int axis = 0; axis < 3; ++axis) {
      const double lo =
        std::floor((point(axis) - reach - m_min(axis)) / m_cell);
      const double hi =
        std::floor((point(axis) + reach - m_min(axis)) / m_cell);
      if (hi < 0.0 || lo >= m_dims[axis])
        return;
      low[axis] = static_cast<int>(std::max(lo, 0.0));
      high[axis] = static_cast<int>(std::min(hi, double(m_dims[axis] - 1)));
    }
    for (int x = low[0]; x <= high[0]; ++x) {
      for (int y = low[1]; y <= high[1]; ++y) {
        const size_t row = (static_cast<size_t>(x) * m_dims[1] + y) * m_dims[2];
        for (size_t i = m_start[row + low[2]]; i < m_start[row + high[2] + 1];
             ++i)
          visit(m_items[i]);
      }
    }
  }

private:
  static double cellCount(const Vector3& extent, double cell)
  {
    return (std::floor(extent(0) / cell) + 1.0) *
           (std::floor(extent(1) / cell) + 1.0) *
           (std::floor(extent(2) / cell) + 1.0);
  }

  size_t cellOf(const Vector3& point) const
  {
    int index[3];
    for (int axis = 0; axis < 3; ++axis) {
      index[axis] =
        std::clamp(static_cast<int>((point(axis) - m_min(axis)) / m_cell), 0,
                   m_dims[axis] - 1);
    }
    return (static_cast<size_t>(index[0]) * m_dims[1] + index[1]) * m_dims[2] +
           index[2];
  }

  Vector3 m_min;
  double m_cell;
  int m_dims[3];
  std::vector<size_t> m_start;
  std::vector<std::uint32_t> m_items;
};

// The circle where two balls' surfaces meet, and which of it no other ball
// covers. The circle is center + radius (cos t u + sin t v) with axis the
// line of centers; the exposed parts are the angle intervals [from, to] in
// [0, 2 pi] of the owner's spans, from firstSpan to endSpan. Their ends are
// the points where three balls meet.
struct Crease
{
  Vector3 center, axis, u, v;
  double radius;
  size_t firstSpan, endSpan;
};

struct BallCreases
{
  std::vector<Crease> creases;
  std::vector<std::pair<double, double>> spans;
};

// Add to @p out the closed interval of angles of length @p length starting
// at @p start, as intervals in [0, 2 pi] (two if it wraps around).
void addInterval(std::vector<std::pair<double, double>>& out, double start,
                 double length)
{
  start = std::fmod(start, TwoPi);
  if (start < 0.0)
    start += TwoPi;
  if (start + length > TwoPi) {
    out.emplace_back(start, TwoPi);
    out.emplace_back(0.0, start + length - TwoPi);
  } else {
    out.emplace_back(start, start + length);
  }
}

// The overlaps of each ball, and the exposed creases between pairs.
struct Topology
{
  std::vector<std::vector<Neighbor>> overlaps;
  std::vector<BallCreases> creases;
};

// Record the crease of ball @p i with the ball @p j (of higher index) into
// @p out, if any of it is exposed. @p neighbors are the overlaps of i, the
// only balls that can reach the circle.
void addCrease(const std::vector<Ball>& balls, std::uint32_t i, std::uint32_t j,
               const std::vector<Neighbor>& neighbors, BallCreases& out)
{
  const Ball& first = balls[i];
  const Ball& second = balls[j];
  const Vector3 offset = second.center - first.center;
  const double between = offset.norm();
  if (between <= 1.0e-9 || between >= first.radius + second.radius ||
      between <= std::abs(first.radius - second.radius))
    return; // coincident, apart, nested, or touching at a point
  const Vector3 axis = offset / between;
  const double along =
    (square(between) + square(first.radius) - square(second.radius)) /
    (2.0 * between);
  const double radiusSq = square(first.radius) - square(along);
  if (radiusSq <= 1.0e-12)
    return;
  Crease crease;
  crease.radius = std::sqrt(radiusSq);
  crease.center = first.center + axis * along;
  crease.axis = axis;
  crease.u =
    axis.cross(std::abs(axis(0)) < 0.9 ? Vector3::UnitX() : Vector3::UnitY());
  crease.u.normalize();
  crease.v = axis.cross(crease.u);

  // Where a ball k covers the circle: |center + radius (cos t u + sin t v) -
  // c_k|^2 <= R_k^2, which is A cos t + B sin t <= K.
  std::vector<std::pair<double, double>> covered;
  for (const Neighbor& k : neighbors) {
    if (k.index == j)
      continue;
    const Vector3 w = crease.center - k.center;
    const double a = 2.0 * crease.radius * w.dot(crease.u);
    const double b = 2.0 * crease.radius * w.dot(crease.v);
    const double limit = square(k.radius) - w.squaredNorm() - radiusSq;
    const double amplitude = std::hypot(a, b);
    if (amplitude <= 1.0e-12) {
      if (limit >= 0.0)
        return; // covered all around
      continue;
    }
    if (limit >= amplitude)
      return; // covered all around
    if (limit <= -amplitude)
      continue; // not covered anywhere
    const double half = std::acos(limit / amplitude);
    addInterval(covered, std::atan2(b, a) + half, TwoPi - 2.0 * half);
  }
  std::sort(covered.begin(), covered.end());

  crease.firstSpan = out.spans.size();
  double reach = 0.0; // angles below this are covered or recorded
  for (const auto& interval : covered) {
    if (interval.first > reach)
      out.spans.emplace_back(reach, interval.first);
    reach = std::max(reach, interval.second);
  }
  if (reach < TwoPi)
    out.spans.emplace_back(reach, TwoPi);
  crease.endSpan = out.spans.size();
  if (crease.endSpan > crease.firstSpan)
    out.creases.push_back(crease);
}

Topology buildTopology(const std::vector<Ball>& balls, const BallGrid& grid,
                       double maxRadius)
{
  Topology topology;
  topology.overlaps.resize(balls.size());
  topology.creases.resize(balls.size());
  std::vector<int> indices(balls.size());
  std::iota(indices.begin(), indices.end(), 0);
  parallelFor(indices.begin(), indices.end(), [&](int i) {
    std::vector<Neighbor>& list = topology.overlaps[i];
    grid.forEachNear(
      balls[i].center, balls[i].radius + maxRadius, [&](std::uint32_t j) {
        if (j == static_cast<std::uint32_t>(i))
          return;
        const double reach = balls[i].radius + balls[j].radius;
        if ((balls[j].center - balls[i].center).squaredNorm() < square(reach))
          list.push_back({ balls[j].center,
                           square(balls[j].radius - CoverTolerance),
                           balls[j].radius, j });
      });
  });
  parallelFor(indices.begin(), indices.end(), [&](int i) {
    for (const Neighbor& j : topology.overlaps[i]) {
      if (j.index > static_cast<std::uint32_t>(i))
        addCrease(balls, i, j.index, topology.overlaps[i], topology.creases[i]);
    }
  });
  return topology;
}

// The balls with a surface point within @p limit of a point, nearest surface
// first, as (gap, index), where gap is the distance to the surface. Squared
// distances decide which balls qualify; only those take a square root.
using CloseBalls = std::vector<std::pair<double, std::uint32_t>>;

void gatherCloseBalls(const BallGrid& grid, const std::vector<Ball>& balls,
                      double maxRadius, const Vector3& pos, double limit,
                      CloseBalls& out)
{
  out.clear();
  grid.forEachNear(pos, maxRadius + limit, [&](std::uint32_t b) {
    const double distanceSq = (pos - balls[b].center).squaredNorm();
    const double radius = balls[b].radius;
    // |distance - radius| < limit
    if (distanceSq >= square(radius + limit) ||
        (radius > limit && distanceSq <= square(radius - limit)))
      return;
    out.emplace_back(std::abs(std::sqrt(distanceSq) - radius), b);
  });
  // The list is short, and nearly sorted by the grid's cell order.
  for (size_t i = 1; i < out.size(); ++i) {
    const auto item = out[i];
    size_t j = i;
    for (; j > 0 && item < out[j - 1]; --j)
      out[j] = out[j - 1];
    out[j] = item;
  }
}

// The exact distance from @p pos to the surface of the union of the balls,
// or @p nearest, an upper bound on it, if that is smaller. The nearest point
// is on a ball's own surface (the projection of @p pos onto it, if no other
// ball covers that) or on an exposed arc of the circle where two balls meet
// (the point of the circle at the same angle around its axis, or the end of
// the arc nearest in angle).
double surfaceDistance(const Vector3& pos, double nearest,
                       const CloseBalls& close, const std::vector<Ball>& balls,
                       const Topology& topology, const Neighbor*& lastCover)
{
  // Two phases, balls first: the circles are pruned by the best distance, and
  // that is tightest after all the balls have been tried.
  for (const auto& [gap, b] : close) {
    if (gap >= nearest)
      break;
    const Vector3 offset = pos - balls[b].center;
    const double distance = offset.norm();
    if (distance <= 1.0e-12)
      continue; // at the center there is no direction to project along
    const Vector3 foot =
      balls[b].center + offset * (balls[b].radius / distance);
    if (isExposed(foot, topology.overlaps[b], lastCover))
      nearest = gap;
  }
  for (const auto& [gap, b] : close) {
    if (gap >= nearest)
      break;
    const BallCreases& owned = topology.creases[b];
    for (const Crease& crease : owned.creases) {
      const Vector3 rel = pos - crease.center;
      const double axial = rel.dot(crease.axis);
      const double a = rel.dot(crease.u);
      const double c = rel.dot(crease.v);
      const double planarSq = square(a) + square(c);
      // Even the whole circle is not nearer than what is known.
      if (square(axial) + square(std::sqrt(planarSq) - crease.radius) >=
          square(nearest))
        continue;
      // Distance to a circle point grows with its angle from pos's own.
      double angle = planarSq > 1.0e-24 ? std::atan2(c, a) : 0.0;
      if (angle < 0.0)
        angle += TwoPi;
      double best = TwoPi; // smallest angular distance to an exposed point
      double target = angle;
      for (size_t s = crease.firstSpan; s < crease.endSpan; ++s) {
        const auto& [from, to] = owned.spans[s];
        if (angle >= from && angle <= to) {
          best = 0.0;
          target = angle;
          break;
        }
        for (double end : { from, to }) {
          double delta = std::abs(angle - end);
          delta = std::min(delta, TwoPi - delta);
          if (delta < best) {
            best = delta;
            target = end;
          }
        }
      }
      const double distanceSq = square(axial) +
                                square(a - crease.radius * std::cos(target)) +
                                square(c - crease.radius * std::sin(target));
      nearest = std::min(nearest, std::sqrt(distanceSq));
    }
  }
  return nearest;
}

// The field value of a voxel from its squared distance to the nearest
// outside voxel center, or @p farValue if there is none.
inline double coarseField(float squared, double probeRadius)
{
  return std::sqrt(static_cast<double>(squared)) - probeRadius;
}

} // namespace

bool fillSolventExcluded(Core::Cube& cube,
                         const std::vector<EdtSphere>& spheres,
                         double probeRadius)
{
  // Seed: 0 outside the solvent-accessible spheres, infinity inside.
  if (!fillBinary(cube, spheres, std::numeric_limits<float>::infinity(), 0.0f))
    return false;

  const Vector3i dims = cube.dimensions();
  const Vector3 min = cube.min();
  const Vector3 spacing = cube.spacing();
  std::vector<float>& values = *cube.data();
  const size_t dimY = static_cast<size_t>(dims(1));
  const size_t dimZ = static_cast<size_t>(dims(2));
  const size_t slabSize = dimY * dimZ;

  squaredDistanceTransform(values, dims, spacing);

  // A voxel with no seed (not possible with the padding Surfaces adds) is
  // farther than anything in the grid: use the grid diagonal.
  const double diagonal =
    (dims.cast<double>() - Vector3::Ones()).cwiseProduct(spacing).norm();
  const float farValue = static_cast<float>(diagonal - probeRadius);

  std::vector<Ball> balls;
  double maxRadius = 0.0;
  for (const EdtSphere& sphere : spheres) {
    if (sphere.first.allFinite() && std::isfinite(sphere.second) &&
        sphere.second > 0.0) {
      balls.push_back({ sphere.first, sphere.second });
      maxRadius = std::max(maxRadius, sphere.second);
    }
  }
  if (balls.empty()) {
    for (float& v : values)
      v = std::isfinite(v) ? static_cast<float>(coarseField(v, probeRadius))
                           : farValue;
    return true;
  }

  // The distance to the nearest outside voxel center is only an upper bound
  // on the distance to the SAS, and over by up to half a voxel diagonal, by a
  // different amount in every voxel. That dents the zero level. Near it,
  // measure to the surface itself (see surfaceDistance()).
  //
  // f = distance - probe is 1-Lipschitz, with h the largest spacing. The
  // marching-cubes edges that cross the zero level end at |f| <= h, and the
  // central-difference normals there read the axis neighbors of those, at
  // |f| <= 2h. The coarse value is at least the true one and at most
  // overestimates by a half diagonal, so every voxel whose true value is in
  // (-2h, 2h) has a coarse one in (-2h, 2h + bias). Voxels outside the SAS
  // keep -probe, and ones farther from the zero level keep the coarse value.
  const double h = spacing.maxCoeff();
  const double bias = 0.5 * spacing.norm();
  const double bandLow = -2.0 * h;
  const double bandHigh = 2.0 * h + bias;

  const BallGrid grid(balls);
  const Topology topology = buildTopology(balls, grid, maxRadius);

  std::vector<int> slabIndices(dims(0));
  std::iota(slabIndices.begin(), slabIndices.end(), 0);
  parallelFor(slabIndices.begin(), slabIndices.end(), [&](int x) {
    thread_local CloseBalls close;
    const Neighbor* lastCover = nullptr;
    float* data = values.data();
    const size_t base = static_cast<size_t>(x) * slabSize;
    for (size_t y = 0; y < dimY; ++y) {
      for (size_t z = 0; z < dimZ; ++z) {
        const size_t i = base + y * dimZ + z;
        const float squared = data[i];
        if (!std::isfinite(squared)) {
          data[i] = farValue;
          continue;
        }
        const double coarse = coarseField(squared, probeRadius);
        data[i] = static_cast<float>(coarse);
        if (squared <= 0.0f || coarse <= bandLow || coarse >= bandHigh)
          continue;
        const Vector3 pos =
          min + Vector3(double(x), double(y), double(z)).cwiseProduct(spacing);
        const double bound = std::sqrt(static_cast<double>(squared));
        gatherCloseBalls(grid, balls, maxRadius, pos, bound, close);
        data[i] = static_cast<float>(
          surfaceDistance(pos, bound, close, balls, topology, lastCover) -
          probeRadius);
      }
    }
  });
  return true;
}

bool fillBinarySpheres(Core::Cube& cube, const std::vector<EdtSphere>& spheres)
{
  return fillBinary(cube, spheres, 1.0f, -1.0f);
}

double distanceFieldMargin(const Core::Cube& cube)
{
  return 2.0 * cube.spacing().maxCoeff();
}

bool fillDistanceSpheres(Core::Cube& cube,
                         const std::vector<EdtSphere>& spheres)
{
  if (!usableGrid(cube))
    return false;

  const Vector3i dims = cube.dimensions();
  const Vector3 min = cube.min();
  const Vector3 spacing = cube.spacing();
  const double margin = distanceFieldMargin(cube);
  const float background = static_cast<float>(-margin);

  // The same slab partition as fillBinarySpheres(), with each sphere grown by
  // the margin: the voxels it can raise above the background lie within it.
  forEachSlab(
    cube, spheres, margin, background,
    [&](float* slab, double posX, const EdtSphere& in) {
      const double radius = in.second;
      const double reach = radius + margin;
      const double reachXsq = square(reach) - square(posX - in.first(0));
      if (reachXsq < 0.0)
        return;
      const double reachX = std::sqrt(reachXsq);
      const int startIndexY = static_cast<int>(std::max(
        std::floor((in.first(1) - reachX - min(1)) / spacing(1)), 0.0));
      const int endIndexY = static_cast<int>(
        std::min(std::floor((in.first(1) + reachX - min(1)) / spacing(1)) + 1.0,
                 static_cast<double>(dims(1))));
      const float radiusF = static_cast<float>(radius);
      for (int indexY = startIndexY; indexY < endIndexY; ++indexY) {
        const double posY = indexY * spacing(1) + min(1);
        const double reachXYsq = reachXsq - square(posY - in.first(1));
        if (reachXYsq < 0.0)
          continue;
        const double reachXY = std::sqrt(reachXYsq);
        const int firstZ = static_cast<int>(std::max(
          std::floor((in.first(2) - reachXY - min(2)) / spacing(2)), 0.0));
        const int lastZ = static_cast<int>(
          std::min(std::floor((in.first(2) + reachXY - min(2)) / spacing(2)),
                   static_cast<double>(dims(2) - 1)));
        if (firstZ > lastZ)
          continue;
        const float distanceXYsq = static_cast<float>(
          square(posX - in.first(0)) + square(posY - in.first(1)));
        const float zStart = static_cast<float>(min(2) - in.first(2));
        const float zStep = static_cast<float>(spacing(2));
        float* stripe = slab + static_cast<size_t>(indexY) * dims(2);
        for (int z = firstZ; z <= lastZ; ++z) {
          const float dz = zStart + static_cast<float>(z) * zStep;
          const float value = radiusF - std::sqrt(distanceXYsq + dz * dz);
          stripe[z] = std::max(stripe[z], value);
        }
      }
    });
  return true;
}

} // namespace Avogadro::QtPlugins
