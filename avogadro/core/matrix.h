/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_MATRIX_H
#define AVOGADRO_CORE_MATRIX_H

#include "avogadrocore.h"
#include <Eigen/Dense>

namespace Avogadro {

/** Typedefs for vector types. */
using Matrix2 = Eigen::Matrix<Real, 2, 2>;
using Matrix3 = Eigen::Matrix<Real, 3, 3>;
using Matrix4 = Eigen::Matrix<Real, 4, 4>;
using MatrixX = Eigen::Matrix<Real, Eigen::Dynamic, Eigen::Dynamic>;

using Matrix2f = Eigen::Matrix<float, 2, 2>;
using Matrix3f = Eigen::Matrix<float, 3, 3>;
using Matrix4f = Eigen::Matrix<float, 4, 4>;
using MatrixXf = Eigen::Matrix<float, Eigen::Dynamic, Eigen::Dynamic>;

} // namespace Avogadro

#endif // AVOGADRO_CORE_MATRIX_H
