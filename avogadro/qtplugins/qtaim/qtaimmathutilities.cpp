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

#include "qtaimmathutilities.h"

#include <Eigen/Eigenvalues>
#include <Eigen/QR>
#include <cmath>

namespace Avogadro {
namespace QtPlugins {
namespace QTAIMMathUtilities {

Matrix<qreal, 3, 1> eigenvaluesOfASymmetricThreeByThreeMatrix(
  const Matrix<qreal, 3, 3>& A)
{
  SelfAdjointEigenSolver<Matrix<qreal, 3, 3>> eigensolver(A);
  return eigensolver.eigenvalues();
}

Matrix<qreal, 3, 3> eigenvectorsOfASymmetricThreeByThreeMatrix(
  const Matrix<qreal, 3, 3>& A)
{
  SelfAdjointEigenSolver<Matrix<qreal, 3, 3>> eigensolver(A);
  return eigensolver.eigenvectors();
}

Matrix<qreal, 4, 1> eigenvaluesOfASymmetricFourByFourMatrix(
  const Matrix<qreal, 4, 4>& A)
{
  SelfAdjointEigenSolver<Matrix<qreal, 4, 4>> eigensolver(A);
  return eigensolver.eigenvalues();
}

Matrix<qreal, 4, 4> eigenvectorsOfASymmetricFourByFourMatrix(
  const Matrix<qreal, 4, 4>& A)
{
  SelfAdjointEigenSolver<Matrix<qreal, 4, 4>> eigensolver(A);
  return eigensolver.eigenvectors();
}

qint64 signOfARealNumber(qreal x)
{
  if (x > 0.)
    return 1;
  else if (x == 0.)
    return 0;
  else
    return -1;
}

qint64 signatureOfASymmetricThreeByThreeMatrix(const Matrix<qreal, 3, 3>& A)
{
  SelfAdjointEigenSolver<Matrix<qreal, 3, 3>> eigensolver(A);
  Matrix<qreal, 3, 1> eigenvalues = eigensolver.eigenvalues();

  return signOfARealNumber(eigenvalues(0)) + signOfARealNumber(eigenvalues(1)) +
         signOfARealNumber(eigenvalues(2));
}

qreal ellipticityOfASymmetricThreeByThreeMatrix(const Matrix<qreal, 3, 3>& A)
{
  SelfAdjointEigenSolver<Matrix<qreal, 3, 3>> eigensolver(A);
  Matrix<qreal, 3, 1> eigenvalues = eigensolver.eigenvalues();

  return (eigenvalues(0) / eigenvalues(1)) - 1.0;
}

qreal distance(const Matrix<qreal, 3, 1>& a, const Matrix<qreal, 3, 1>& b)
{
  return sqrt(pow(a(0) - b(0), 2) + pow(a(1) - b(1), 2) + pow(a(2) - b(2), 2));
}

Matrix<qreal, 3, 1> sphericalToCartesian(const Matrix<qreal, 3, 1>& rtp,
                                         const Matrix<qreal, 3, 1>& x0y0z0)
{
  qreal r = rtp(0);
  qreal theta = rtp(1);
  qreal phi = rtp(2);

  qreal x0 = x0y0z0(0);
  qreal y0 = x0y0z0(1);
  qreal z0 = x0y0z0(2);

  qreal costheta = cos(theta);
  qreal cosphi = cos(phi);
  qreal sintheta = sin(theta);
  qreal sinphi = sin(phi);

  Matrix<qreal, 3, 1> xyz(r * cosphi * sintheta + x0,
                          r * sintheta * sinphi + y0, r * costheta + z0);

  return xyz;
}

Matrix<qreal, 3, 1> sphericalToCartesian(const Matrix<qreal, 3, 1>& rtp)
{
  Matrix<qreal, 3, 1> x0y0z0(0., 0., 0.);

  return sphericalToCartesian(rtp, x0y0z0);
}

Matrix<qreal, 3, 1> cartesianToSpherical(const Matrix<qreal, 3, 1>& xyz,
                                         const Matrix<qreal, 3, 1>& x0y0z0)
{
  qreal x = xyz(0);
  qreal y = xyz(1);
  qreal z = xyz(2);

  qreal x0 = x0y0z0(0);
  qreal y0 = x0y0z0(1);
  qreal z0 = x0y0z0(2);

  qreal xshift = x - x0;
  qreal yshift = y - y0;
  qreal zshift = z - z0;

  qreal length = sqrt(pow(xshift, 2) + pow(yshift, 2) + pow(zshift, 2));

  Matrix<qreal, 3, 1> rtp;

  if (length == 0.)
    rtp << x0, y0, z0;
  else if (xshift == 0. && yshift == 0.)
    rtp << length, acos(zshift / length), 0.;
  else
    rtp << length, acos(zshift / length), atan2(xshift, yshift);

  return rtp;
}

Matrix<qreal, 3, 1> cartesianToSpherical(const Matrix<qreal, 3, 1>& xyz)
{
  Matrix<qreal, 3, 1> x0y0z0(0., 0., 0.);

  return cartesianToSpherical(xyz, x0y0z0);
}

// Cerjan-Miller-Baker-Popelier Methods
//
// Based on:
// Popelier, P.L.A. Comput. Phys. Comm. 1996, 93, 212.

Matrix<qreal, 3, 1> minusThreeSignatureLocatorGradient(
  const Matrix<qreal, 3, 1>& g, const Matrix<qreal, 3, 3>& H)
{
  Matrix<qreal, 3, 1> value;

  Matrix<qreal, 3, 1> b = eigenvaluesOfASymmetricThreeByThreeMatrix(H);
  Matrix<qreal, 3, 3> U = eigenvectorsOfASymmetricThreeByThreeMatrix(H);

  Matrix<qreal, 3, 1> F = U.transpose() * g;

  Matrix<qreal, 4, 4> A;
  A << b(0), 0., 0., F(0), 0., b(1), 0., F(1), 0., 0., b(2), F(2), F(0), F(1),
    F(2), 0.;

  Matrix<qreal, 4, 1> eval = eigenvaluesOfASymmetricFourByFourMatrix(A);

  Matrix<qreal, 3, 1> lambda;
  lambda << eval(3), eval(3), eval(3);

  Matrix<qreal, 3, 1> denom;
  denom = b - lambda;

  for (qint64 i = 0; i < 3; ++i)
    if (denom(i) < SMALL)
      denom(i) = denom(i) + SMALL;

  Matrix<qreal, 3, 1> h;
  h << 0., 0., 0.;

  for (qint64 j = 0; j < 3; ++j)
    for (qint64 i = 0; i < 3; ++i)
      h(j) = h(j) + (-F(i) * U(j, i)) / denom(i);

  value = h;

  return value;
}

Matrix<qreal, 3, 1> minusOneSignatureLocatorGradient(
  const Matrix<qreal, 3, 1>& g, const Matrix<qreal, 3, 3>& H)
{
  Matrix<qreal, 3, 1> value;

  Matrix<qreal, 3, 1> b = eigenvaluesOfASymmetricThreeByThreeMatrix(H);
  Matrix<qreal, 3, 3> U = eigenvectorsOfASymmetricThreeByThreeMatrix(H);

  Matrix<qreal, 3, 1> F = U.transpose() * g;

  Matrix<qreal, 3, 3> A;
  A << b(0), 0., F(0), 0., b(1), F(1), F(0), F(1), 0.;

  Matrix<qreal, 3, 1> eval = eigenvaluesOfASymmetricThreeByThreeMatrix(A);

  Matrix<qreal, 3, 1> lambda;
  lambda << eval(2), eval(2),
    (0.5) * (b(2) - sqrt(pow(b(2), 2) + 4.0 * pow(F(2), 2)));

  Matrix<qreal, 3, 1> denom;
  denom = b - lambda;

  for (qint64 i = 0; i < 3; ++i)
    if (denom(i) < SMALL)
      denom(i) = denom(i) + SMALL;

  Matrix<qreal, 3, 1> h;
  h << 0., 0., 0.;

  for (qint64 j = 0; j < 3; ++j)
    for (qint64 i = 0; i < 3; ++i)
      h(j) = h(j) + (-F(i) * U(j, i)) / denom(i);

  value = h;

  return value;
}

Matrix<qreal, 3, 1> plusOneSignatureLocatorGradient(
  const Matrix<qreal, 3, 1>& g, const Matrix<qreal, 3, 3>& H)
{
  Matrix<qreal, 3, 1> value;

  Matrix<qreal, 3, 1> b = eigenvaluesOfASymmetricThreeByThreeMatrix(H);
  Matrix<qreal, 3, 3> U = eigenvectorsOfASymmetricThreeByThreeMatrix(H);

  Matrix<qreal, 3, 1> F = U * g;

  Matrix<qreal, 3, 3> A;
  A << b(1), 0., F(1), 0., b(2), F(2), F(1), F(2), 0.;

  Matrix<qreal, 3, 1> eval = eigenvaluesOfASymmetricThreeByThreeMatrix(A);

  Matrix<qreal, 3, 1> lambda;
  lambda << eval(2), eval(2),
    (0.5) * (b(0) + sqrt(pow(b(0), 2) + 4.0 * pow(F(0), 2)));

  Matrix<qreal, 3, 1> denom;
  denom = b - lambda;

  for (qint64 i = 0; i < 3; ++i)
    if (denom(i) < SMALL)
      denom(i) = denom(i) + SMALL;

  Matrix<qreal, 3, 1> h;
  h << 0., 0., 0.;

  for (qint64 j = 0; j < 3; ++j)
    for (qint64 i = 0; i < 3; ++i)
      h(j) = h(j) + (-F(i) * U(i, j)) / denom(i);

  value = h;

  return value;
}

Matrix<qreal, 3, 1> plusThreeSignatureLocatorGradient(
  const Matrix<qreal, 3, 1>& g, const Matrix<qreal, 3, 3>& H)
{
  Matrix<qreal, 3, 1> value;

  Matrix<qreal, 3, 1> b = eigenvaluesOfASymmetricThreeByThreeMatrix(H);
  Matrix<qreal, 3, 3> U = eigenvectorsOfASymmetricThreeByThreeMatrix(H);

  Matrix<qreal, 3, 1> F = U * g;

  Matrix<qreal, 4, 4> A;
  A << b(0), 0., 0., F(0), 0., b(1), 0., F(1), 0., 0., b(2), F(2), F(0), F(1),
    F(2), 0.;

  Matrix<qreal, 4, 1> eval = eigenvaluesOfASymmetricFourByFourMatrix(A);

  Matrix<qreal, 3, 1> lambda;
  lambda << eval(0), eval(0), eval(0);

  Matrix<qreal, 3, 1> denom;
  denom = b - lambda;

  for (qint64 i = 0; i < 3; ++i)
    if (denom(i) < SMALL)
      denom(i) = denom(i) + SMALL;

  Matrix<qreal, 3, 1> h;
  h << 0., 0., 0.;

  for (qint64 j = 0; j < 3; ++j)
    for (qint64 i = 0; i < 3; ++i)
      h(j) = h(j) + (-F(i) * U(i, j)) / denom(i);

  value = h;

  return value;
}

} // namespace QTAIMMathUtilities
} // namespace QtPlugins
} // namespace Avogadro
