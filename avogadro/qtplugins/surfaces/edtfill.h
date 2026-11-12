/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_EDTFILL_H
#define AVOGADRO_QTPLUGINS_EDTFILL_H

#include <avogadro/core/vector.h>

#include <utility>
#include <vector>

namespace Avogadro::Core {
class Cube;
}

namespace Avogadro::QtPlugins {

/**
 * A sphere to rasterize: the center and the radius in Angstrom (the van der
 * Waals radius, plus the probe radius for a solvent-accessible surface).
 */
using EdtSphere = std::pair<Vector3, double>;

/**
 * Fill @p cube with +1 inside any of the @p spheres and -1 elsewhere.
 *
 * The grid is indexed with the cube's own origin and per-axis spacing. The
 * work is split into slabs of constant x, each written by exactly one thread,
 * so overlapping spheres never race on a voxel.
 *
 * @return False, leaving the cube untouched, if the cube holds no grid.
 */
bool fillBinarySpheres(Core::Cube& cube, const std::vector<EdtSphere>& spheres);

/**
 * The value an outside voxel far from every sphere has in the field written
 * by fillDistanceSpheres(): minus twice the cube's largest grid spacing.
 */
double distanceFieldMargin(const Core::Cube& cube);

/**
 * Fill @p cube with the signed distance field f(x) = max_i (r_i - |x - c_i|)
 * of the @p spheres: positive inside, negative outside, and zero exactly on
 * the sphere surfaces, so the zero isosurface follows them.
 *
 * Values below -distanceFieldMargin() are not computed: those voxels hold
 * -distanceFieldMargin(). That keeps the field exact in every voxel a
 * marching-cubes pass or a gradient of neighboring voxels can see near the
 * surface, at a cost proportional to the sphere volume plus the margin.
 * The grid and threading are as for fillBinarySpheres().
 *
 * @return False, leaving the cube untouched, if the cube holds no grid.
 */
bool fillDistanceSpheres(Core::Cube& cube,
                         const std::vector<EdtSphere>& spheres);

/**
 * Fill @p cube with the signed distance field of the solvent-excluded surface
 * (SES) of the atoms: positive inside the SES, -@p probeRadius outside the
 * solvent-accessible surface, and zero on the SES.
 *
 * @p spheres carry the solvent-accessible radii (van der Waals radius plus
 * the probe radius). The SES is the set of points farther than the probe
 * radius from every point outside those spheres, so the field is
 * sqrt(D2) - probeRadius, where D2 is the exact squared Euclidean distance to
 * the nearest voxel outside the spheres. D2 comes from the separable
 * Felzenszwalb-Huttenlocher transform, run over the lines along z, then y,
 * then x, each pass split over independent lines. The distances use the
 * cube's per-axis spacing.
 *
 * The center-to-center distance is only an upper bound on the distance to the
 * solvent-accessible surface (up to 0.87 voxel too large, differently in every
 * voxel). Within a few voxels of the zero level the field is therefore
 * measured to the surface itself: to the projection onto each nearby sphere
 * that no other sphere covers, and to the exact nearest point of each exposed
 * arc where two spheres cross (the arcs end where three spheres meet).
 *
 * @return False, leaving the cube untouched, if the cube holds no grid.
 */
bool fillSolventExcluded(Core::Cube& cube,
                         const std::vector<EdtSphere>& spheres,
                         double probeRadius);

/**
 * Replace the seeds in @p squared (indexed (x * dimY + y) * dimZ + z, like a
 * cube) by the exact squared Euclidean distance, in the units of
 * @p spacing, to the nearest voxel seeded with a finite value of 0. Seeds
 * must be 0 or infinity. A voxel with no zero seed anywhere keeps infinity.
 * Exposed for testing.
 */
void squaredDistanceTransform(std::vector<float>& squared,
                              const Vector3i& dimensions,
                              const Vector3& spacing);

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_EDTFILL_H
