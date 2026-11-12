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

} // namespace

bool fillBinarySpheres(Core::Cube& cube, const std::vector<EdtSphere>& spheres)
{
  if (!usableGrid(cube))
    return false;

  const Vector3i dims = cube.dimensions();
  const Vector3 min = cube.min();
  const Vector3 spacing = cube.spacing();
  float* data = cube.data()->data();
  const size_t slabSize = static_cast<size_t>(dims(1)) * dims(2);

  // Overlapping atom spheres touch the same voxels, so threads must not be
  // handed atoms: two of them would write one voxel at the same time. Instead
  // each atom is binned into every x slab (constant indexX) it covers, and
  // each slab goes to exactly one thread. Filling only sets 1.0 over the
  // -1.0 background, so the result equals filling atom by atom.
  const std::vector<std::vector<size_t>> slabAtoms =
    binIntoSlabs(cube, spheres, 0.0);

  std::vector<int> slabIndices(dims(0));
  std::iota(slabIndices.begin(), slabIndices.end(), 0);

  QtConcurrent::blockingMap(slabIndices, [&](int indexX) {
    float* slab = data + static_cast<size_t>(indexX) * slabSize;
    std::fill(slab, slab + slabSize, -1.0f);
    const double posX = indexX * spacing(0) + min(0);
    for (size_t a : slabAtoms[indexX]) {
      const EdtSphere& in = spheres[a];
      const double radiusXsq = square(in.second) - square(posX - in.first(0));
      if (radiusXsq < 0.0)
        continue;
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
        const int firstZ =
          static_cast<int>(std::max((startPosZ - min(2)) / spacing(2), 0.0));
        const int lastZ = static_cast<int>(std::min(
          (endPosZ - min(2)) / spacing(2), static_cast<double>(dims(2) - 1)));
        if (firstZ > lastZ)
          continue;
        float* stripe = slab + static_cast<size_t>(indexY) * dims(2);
        std::fill(stripe + firstZ, stripe + lastZ + 1, 1.0f);
      }
    }
  });
  return true;
}

} // namespace Avogadro::QtPlugins
