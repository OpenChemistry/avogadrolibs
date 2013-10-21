/**********************************************************************
  QTAIM - Extension for Quantum Theory of Atoms In Molecules Analysis

  Copyright (C) 2010 Eric C. Brown

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.openmolecules.net/>

  Avogadro is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  Avogadro is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301, USA.
**********************************************************************/
#ifndef QTAIMMATHUTILITIES_H
#define QTAIMMATHUTILITIES_H

#include <QtGlobal>

#include <Eigen/Core>

using namespace Eigen;

namespace Avogadro {

  namespace QTAIMMathUtilities
  {
    Matrix<qreal,3,1> eigenvaluesOfASymmetricThreeByThreeMatrix(const Matrix<qreal,3,3> &A);
    Matrix<qreal,3,3> eigenvectorsOfASymmetricThreeByThreeMatrix(const Matrix<qreal,3,3> &A);
    Matrix<qreal,4,1> eigenvaluesOfASymmetricFourByFourMatrix(const Matrix<qreal,4,4> &A);
    Matrix<qreal,4,4> eigenvectorsOfASymmetricFourByFourMatrix(const Matrix<qreal,4,4> &A);

    qint64 signOfARealNumber(qreal x);
    qint64 signatureOfASymmetricThreeByThreeMatrix(const Matrix<qreal,3,3> &A);
    qreal ellipticityOfASymmetricThreeByThreeMatrix(const Matrix<qreal,3,3> &A);

    qreal distance(const Matrix<qreal,3,1> &a, const Matrix<qreal,3,1> &b);

    Matrix<qreal,3,1> sphericalToCartesian(const Matrix<qreal,3,1> &rtp,
                                           const Matrix<qreal,3,1> &x0y0z0);
    Matrix<qreal,3,1> sphericalToCartesian(const Matrix<qreal,3,1> &rtp);

    Matrix<qreal,3,1> cartesianToSpherical(const Matrix<qreal,3,1> &xyz,
                                           const Matrix<qreal,3,1> &x0y0z0);
    Matrix<qreal,3,1> cartesianToSpherical(const Matrix<qreal,3,1> &xyz);

    // Cerjan-Miller-Baker-Popelier Methods

    // A small number to prevent divide by zero in CMBP routines
#define SMALL 1.e-10

    Matrix<qreal,3,1> minusThreeSignatureLocatorGradient(const Matrix<qreal,3,1> &g,
                                                         const Matrix<qreal,3,3> &H);
    Matrix<qreal,3,1> minusOneSignatureLocatorGradient(const Matrix<qreal,3,1> &g,
                                                       const Matrix<qreal,3,3> &H);
    Matrix<qreal,3,1> plusOneSignatureLocatorGradient(const Matrix<qreal,3,1> &g,
                                                      const Matrix<qreal,3,3> &H);
    Matrix<qreal,3,1> plusThreeSignatureLocatorGradient(const Matrix<qreal,3,1> &g,
                                                        const Matrix<qreal,3,3> &H);
  }
} // namespace Avogadro

#endif // QTAIMMATHUTILITIES_H
