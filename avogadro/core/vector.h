/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_VECTOR_H
#define AVOGADRO_CORE_VECTOR_H

#include "avogadrocore.h"
#include <Eigen/Dense>

namespace Avogadro {

/** Typedefs for vector types. */
using Vector2 = Eigen::Matrix<Real, 2, 1>;
using Vector3 = Eigen::Matrix<Real, 3, 1>;
using Vector4 = Eigen::Matrix<Real, 4, 1>;

using Vector2f = Eigen::Matrix<float, 2, 1>;
using Vector3f = Eigen::Matrix<float, 3, 1>;
using Vector4f = Eigen::Matrix<float, 4, 1>;
using Vector2i = Eigen::Matrix<int, 2, 1>;
using Vector3i = Eigen::Matrix<int, 3, 1>;
using Vector4i = Eigen::Matrix<int, 4, 1>;
using Vector2ub = Eigen::Matrix<unsigned char, 2, 1>;
using Vector3ub = Eigen::Matrix<unsigned char, 3, 1>;
using Vector4ub = Eigen::Matrix<unsigned char, 4, 1>;

/** A simple struct composed of Vector3f to represent a frustrum. */
struct Frustrum
{
  Vector3f points[8];
  Vector3f planes[4];
};

} // namespace Avogadro

#endif // AVOGADRO_CORE_VECTOR_H
