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
    const Matrix<qreal,3,1> gradientOfElectronDensityLaplacian(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,3> hessianOfElectronDensityLaplacian(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,4> gradientAndHessianOfElectronDensityLaplacian(const Matrix<qreal,3,1> xyz);
    const qreal kineticEnergyDensityG(const Matrix<qreal,3,1> xyz);
    const qreal kineticEnergyDensityK(const Matrix<qreal,3,1> xyz);
    const Matrix<qreal,3,3> quantumStressTensor(const Matrix<qreal,3,1> xyz);

  private:
    qint64 nmo;
    qint64 nprim;
    qint64 nnuc;
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
    Matrix<qreal,Dynamic,1> cdg300;
    Matrix<qreal,Dynamic,1> cdg120;
    Matrix<qreal,Dynamic,1> cdg102;
    Matrix<qreal,Dynamic,1> cdg210;
    Matrix<qreal,Dynamic,1> cdg030;
    Matrix<qreal,Dynamic,1> cdg012;
    Matrix<qreal,Dynamic,1> cdg201;
    Matrix<qreal,Dynamic,1> cdg021;
    Matrix<qreal,Dynamic,1> cdg003;
    Matrix<qreal,Dynamic,1> cdg111;
    Matrix<qreal,Dynamic,1> cdg400;
    Matrix<qreal,Dynamic,1> cdg220;
    Matrix<qreal,Dynamic,1> cdg202;
    Matrix<qreal,Dynamic,1> cdg310;
    Matrix<qreal,Dynamic,1> cdg130;
    Matrix<qreal,Dynamic,1> cdg112;
    Matrix<qreal,Dynamic,1> cdg301;
    Matrix<qreal,Dynamic,1> cdg121;
    Matrix<qreal,Dynamic,1> cdg103;
    Matrix<qreal,Dynamic,1> cdg040;
    Matrix<qreal,Dynamic,1> cdg022;
    Matrix<qreal,Dynamic,1> cdg211;
    Matrix<qreal,Dynamic,1> cdg031;
    Matrix<qreal,Dynamic,1> cdg013;
    Matrix<qreal,Dynamic,1> cdg004;

  };

} // namespace Avogadro

#endif // QTAIMWAVEFUNCTIONEVALUATOR_H
