/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_MATRIX_H
#define AVOGADRO_CORE_MATRIX_H

#include "avogadrocore.h"
#include <Eigen/Dense>

namespace Avogadro {

/** Typedefs for vector types. */
typedef Eigen::Matrix<Real, 2, 2> Matrix2;
typedef Eigen::Matrix<Real, 3, 3> Matrix3;
typedef Eigen::Matrix<Real, 4, 4> Matrix4;
typedef Eigen::Matrix<Real, Eigen::Dynamic, Eigen::Dynamic> MatrixX;

typedef Eigen::Matrix<float, 2, 2> Matrix2f;
typedef Eigen::Matrix<float, 3, 3> Matrix3f;
typedef Eigen::Matrix<float, 4, 4> Matrix4f;
typedef Eigen::Matrix<float, Eigen::Dynamic, Eigen::Dynamic> MatrixXf;

} // end Avogadro namespace

#endif // AVOGADRO_CORE_MATRIX_H
