/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "edtfill.h"

#include <avogadro/core/cube.h>

#include <QtConcurrent/QtConcurrent>

#include <algorithm>
#include <cmath>
#include <numeric>

namespace Avogadro::QtPlugins {

namespace {

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

  QtConcurrent::blockingMap(slabIndices, [&](int indexX) {
    float* slab = data + static_cast<size_t>(indexX) * slabSize;
    std::fill(slab, slab + slabSize, background);
    const double posX = indexX * spacing(0) + min(0);
    for (size_t a : slabAtoms[indexX])
      perSphere(slab, posX, spheres[a]);
  });
}

} // namespace

bool fillBinarySpheres(Core::Cube& cube, const std::vector<EdtSphere>& spheres)
{
  if (!usableGrid(cube))
    return false;

  const Vector3i dims = cube.dimensions();
  const Vector3 min = cube.min();
  const Vector3 spacing = cube.spacing();

  forEachSlab(
    cube, spheres, 0.0, -1.0f,
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
        std::fill(stripe + firstZ, stripe + lastZ + 1, 1.0f);
      }
    });
  return true;
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
