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

#ifndef QTAIMWAVEFUNCTIONEVALUATOR_H
#define QTAIMWAVEFUNCTIONEVALUATOR_H

#include <QObject>

#include "qtaimwavefunction.h"

#include <Eigen/Eigen>

using namespace Eigen;

namespace Avogadro
{

  class QTAIMWavefunction;

  class QTAIMWavefunctionEvaluator : public QObject
  {
    Q_OBJECT

  public:
    EIGEN_MAKE_ALIGNED_OPERATOR_NEW

    explicit QTAIMWavefunctionEvaluator(QTAIMWavefunction &wfn, QObject *parent = 0);

    const qreal molecularOrbital(const qint64 mo, const Matrix<qreal,3,1> xyz);
    const qreal electronDensity(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,1> gradientOfElectronDensity(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,3> hessianOfElectronDensity(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,4> gradientAndHessianOfElectronDensity(const Matrix<qreal,3,1> xyz);
    const qreal laplacianOfElectronDensity(const Matrix<qreal,3,1> xyz);
    const qreal electronDensityLaplacian(const Matrix<qreal,3,1> xyz) {return laplacianOfElectronDensity(xyz);}

  private:
    qint64 nmo;   // m_numberOfMolecularOrbitals;
    qint64 nprim; // m_numberOfGaussianPrimitives;
    qint64 nnuc;  // m_numberOfNuclei;
//    qint64 noccmo; // number of (significantly) occupied molecular orbitals
    Matrix<qreal,Dynamic,1> nucxcoord;
    Matrix<qreal,Dynamic,1> nucycoord;
    Matrix<qreal,Dynamic,1> nuczcoord;
    Matrix<qint64,Dynamic,1> nucz;
    Matrix<qreal,Dynamic,1> X0;
    Matrix<qreal,Dynamic,1> Y0;
    Matrix<qreal,Dynamic,1> Z0;
    Matrix<qint64,Dynamic,1> xamom;
    Matrix<qint64,Dynamic,1> yamom;
    Matrix<qint64,Dynamic,1> zamom;
    Matrix<qreal,Dynamic,1> alpha;
    Matrix<qreal,Dynamic,1> occno;
    Matrix<qreal,Dynamic,1> orbe;
    Matrix<qreal,Dynamic,Dynamic,RowMajor> coef;
    qreal totalEnergy;
    qreal virialRatio;

    qreal cutoff;

    Matrix<qreal,Dynamic,1> xx0;
    Matrix<qreal,Dynamic,1> yy0;
    Matrix<qreal,Dynamic,1> zz0;

    Matrix<qint64,Dynamic,1> aax0;
    Matrix<qint64,Dynamic,1> aay0;
    Matrix<qint64,Dynamic,1> aaz0;
    Matrix<qint64,Dynamic,1> aax1;
    Matrix<qint64,Dynamic,1> aay1;
    Matrix<qint64,Dynamic,1> aaz1;
    Matrix<qint64,Dynamic,1> aax2;
    Matrix<qint64,Dynamic,1> aay2;
    Matrix<qint64,Dynamic,1> aaz2;

    Matrix<qreal,Dynamic,1> ax0;
    Matrix<qreal,Dynamic,1> ay0;
    Matrix<qreal,Dynamic,1> az0;
    Matrix<qreal,Dynamic,1> ax1;
    Matrix<qreal,Dynamic,1> ay1;
    Matrix<qreal,Dynamic,1> az1;
    Matrix<qreal,Dynamic,1> ax2;
    Matrix<qreal,Dynamic,1> ay2;
    Matrix<qreal,Dynamic,1> az2;

    Matrix<qreal,Dynamic,1> b0;
    Matrix<qreal,Dynamic,1> b0arg;

    Matrix<qreal,Dynamic,1> bx0;
    Matrix<qreal,Dynamic,1> by0;
    Matrix<qreal,Dynamic,1> bz0;
    Matrix<qreal,Dynamic,1> bx1;
    Matrix<qreal,Dynamic,1> by1;
    Matrix<qreal,Dynamic,1> bz1;
    Matrix<qreal,Dynamic,1> bx2;
    Matrix<qreal,Dynamic,1> by2;
    Matrix<qreal,Dynamic,1> bz2;

    Matrix<qreal,Dynamic,1> dg000;
    Matrix<qreal,Dynamic,1> dg100;
    Matrix<qreal,Dynamic,1> dg010;
    Matrix<qreal,Dynamic,1> dg001;
    Matrix<qreal,Dynamic,1> dg200;
    Matrix<qreal,Dynamic,1> dg110;
    Matrix<qreal,Dynamic,1> dg101;
    Matrix<qreal,Dynamic,1> dg020;
    Matrix<qreal,Dynamic,1> dg011;
    Matrix<qreal,Dynamic,1> dg002;

    Matrix<qreal,Dynamic,1> cdg000;
    Matrix<qreal,Dynamic,1> cdg100;
    Matrix<qreal,Dynamic,1> cdg010;
    Matrix<qreal,Dynamic,1> cdg001;
    Matrix<qreal,Dynamic,1> cdg200;
    Matrix<qreal,Dynamic,1> cdg110;
    Matrix<qreal,Dynamic,1> cdg101;
    Matrix<qreal,Dynamic,1> cdg020;
    Matrix<qreal,Dynamic,1> cdg011;
    Matrix<qreal,Dynamic,1> cdg002;

  };

} // namespace Avogadro

#endif // QTAIMWAVEFUNCTIONEVALUATOR_H
