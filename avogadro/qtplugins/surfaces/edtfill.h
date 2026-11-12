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

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_EDTFILL_H
