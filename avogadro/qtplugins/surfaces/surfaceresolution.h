/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SURFACERESOLUTION_H
#define AVOGADRO_QTPLUGINS_SURFACERESOLUTION_H

#include <avogadro/core/vector.h>

#include <algorithm>
#include <cmath>
#include <cstddef>

namespace Avogadro::QtPlugins {

/**
 * Upper limit on the number of grid points (voxels) of an automatically
 * sized surface grid. Measured cost is about 4 bytes per voxel for the cube
 * plus about 130 bytes per mesh triangle, and 70-90 ns of compute per voxel.
 * 50 million voxels is roughly 200 MB and a few seconds, which is the
 * practical limit for an interactive surface. Without it, a 184k-atom capsid
 * at the 0.5 Angstrom ceiling needs 181M voxels (4.6 GB, 13.6 s) and a
 * 1M-atom one needs over a billion.
 */
constexpr double SurfaceVoxelBudget = 50.0e6;

/**
 * The automatic grid resolution (spacing, in Angstrom) for a surface.
 *
 * The base value is 0.02 * N^(1/3) Angstrom, clamped to [@p minimum, 0.5].
 * That is then raised, if needed, so that a grid covering @p paddedExtent
 * holds no more than SurfaceVoxelBudget voxels. The budget result is not
 * capped at 0.5: a huge system gets a coarser grid rather than an
 * unbuildable one. The result is never below the base value.
 *
 * @param atomCount The number of atoms in the molecule.
 * @param paddedExtent The size of the grid box along x, y and z in Angstrom:
 * the atoms' bounding box including the padding on both sides.
 * @param minimum The smallest resolution the base formula may return.
 */
inline float automaticSurfaceResolution(size_t atomCount,
                                        const Vector3& paddedExtent,
                                        float minimum = 0.05f)
{
  constexpr float maximum = 0.5f;
  float formula = 0.02f * std::cbrt(static_cast<float>(atomCount));
  formula = std::clamp(formula, minimum, maximum);

  if (!paddedExtent.allFinite() || paddedExtent.minCoeff() <= 0.0)
    return formula;

  const double volume = paddedExtent.x() * paddedExtent.y() * paddedExtent.z();
  const double budgetResolution = std::cbrt(volume / SurfaceVoxelBudget);
  if (!std::isfinite(budgetResolution))
    return formula;
  return std::max(formula, static_cast<float>(budgetResolution));
}

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_SURFACERESOLUTION_H
