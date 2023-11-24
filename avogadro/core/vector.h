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
typedef Eigen::Matrix<Real, 2, 1> Vector2;
typedef Eigen::Matrix<Real, 3, 1> Vector3;
typedef Eigen::Matrix<Real, 4, 1> Vector4;

typedef Eigen::Matrix<float, 2, 1> Vector2f;
typedef Eigen::Matrix<float, 3, 1> Vector3f;
typedef Eigen::Matrix<float, 4, 1> Vector4f;
typedef Eigen::Matrix<int, 2, 1> Vector2i;
typedef Eigen::Matrix<int, 3, 1> Vector3i;
typedef Eigen::Matrix<int, 4, 1> Vector4i;
typedef Eigen::Matrix<unsigned char, 2, 1> Vector2ub;
typedef Eigen::Matrix<unsigned char, 3, 1> Vector3ub;
typedef Eigen::Matrix<unsigned char, 4, 1> Vector4ub;

/** A simple struct composed of Vector3f to represent a frustrum. */
struct Frustrum
{
  Vector3f points[8];
  Vector3f planes[4];
};

} // end Avogadro namespace

#endif // AVOGADRO_CORE_VECTOR_H
