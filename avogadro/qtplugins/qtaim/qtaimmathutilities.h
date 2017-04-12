/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright (C) 2010 Eric C. Brown

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef QTAIMMATHUTILITIES_H
#define QTAIMMATHUTILITIES_H

#include <QtGlobal>

#include <Eigen/Core>

using namespace Eigen;

namespace Avogadro {
namespace QtPlugins {

namespace QTAIMMathUtilities {
Matrix<qreal, 3, 1> eigenvaluesOfASymmetricThreeByThreeMatrix(
  const Matrix<qreal, 3, 3>& A);
Matrix<qreal, 3, 3> eigenvectorsOfASymmetricThreeByThreeMatrix(
  const Matrix<qreal, 3, 3>& A);
Matrix<qreal, 4, 1> eigenvaluesOfASymmetricFourByFourMatrix(
  const Matrix<qreal, 4, 4>& A);
Matrix<qreal, 4, 4> eigenvectorsOfASymmetricFourByFourMatrix(
  const Matrix<qreal, 4, 4>& A);

qint64 signOfARealNumber(qreal x);
qint64 signatureOfASymmetricThreeByThreeMatrix(const Matrix<qreal, 3, 3>& A);
qreal ellipticityOfASymmetricThreeByThreeMatrix(const Matrix<qreal, 3, 3>& A);

qreal distance(const Matrix<qreal, 3, 1>& a, const Matrix<qreal, 3, 1>& b);

Matrix<qreal, 3, 1> sphericalToCartesian(const Matrix<qreal, 3, 1>& rtp,
                                         const Matrix<qreal, 3, 1>& x0y0z0);
Matrix<qreal, 3, 1> sphericalToCartesian(const Matrix<qreal, 3, 1>& rtp);

Matrix<qreal, 3, 1> cartesianToSpherical(const Matrix<qreal, 3, 1>& xyz,
                                         const Matrix<qreal, 3, 1>& x0y0z0);
Matrix<qreal, 3, 1> cartesianToSpherical(const Matrix<qreal, 3, 1>& xyz);

// Cerjan-Miller-Baker-Popelier Methods

// A small number to prevent divide by zero in CMBP routines
#define SMALL 1.e-10

Matrix<qreal, 3, 1> minusThreeSignatureLocatorGradient(
  const Matrix<qreal, 3, 1>& g, const Matrix<qreal, 3, 3>& H);
Matrix<qreal, 3, 1> minusOneSignatureLocatorGradient(
  const Matrix<qreal, 3, 1>& g, const Matrix<qreal, 3, 3>& H);
Matrix<qreal, 3, 1> plusOneSignatureLocatorGradient(
  const Matrix<qreal, 3, 1>& g, const Matrix<qreal, 3, 3>& H);
Matrix<qreal, 3, 1> plusThreeSignatureLocatorGradient(
  const Matrix<qreal, 3, 1>& g, const Matrix<qreal, 3, 3>& H);
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // QTAIMMATHUTILITIES_H
