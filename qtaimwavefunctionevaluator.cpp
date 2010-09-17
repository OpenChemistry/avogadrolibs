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

#include <cmath>

#include "qtaimwavefunctionevaluator.h"

namespace Avogadro
{
  QTAIMWavefunctionEvaluator::QTAIMWavefunctionEvaluator(QTAIMWavefunction &wfn, QObject *parent) : QObject(parent)
  {

    nmo=wfn.numberOfMolecularOrbitals();
    nprim=wfn.numberOfGaussianPrimitives();
    nnuc=wfn.numberOfNuclei();

    nucxcoord=Map<Matrix<qreal,Dynamic,1> >(wfn.xNuclearCoordinates(),nnuc);
    nucycoord=Map<Matrix<qreal,Dynamic,1> >(wfn.yNuclearCoordinates(),nnuc);
    nuczcoord=Map<Matrix<qreal,Dynamic,1> >(wfn.zNuclearCoordinates(),nnuc);
    nucz=Map<Matrix<qint64,Dynamic,1> >(wfn.nuclearCharges(),nnuc);
    X0=Map<Matrix<qreal,Dynamic,1> >(wfn.xGaussianPrimitiveCenterCoordinates(),nprim,1);
    Y0=Map<Matrix<qreal,Dynamic,1> >(wfn.yGaussianPrimitiveCenterCoordinates(),nprim,1);
    Z0=Map<Matrix<qreal,Dynamic,1> >(wfn.zGaussianPrimitiveCenterCoordinates(),nprim,1);
    xamom=Map<Matrix<qint64,Dynamic,1> >(wfn.xGaussianPrimitiveAngularMomenta(),nprim,1);
    yamom=Map<Matrix<qint64,Dynamic,1> >(wfn.yGaussianPrimitiveAngularMomenta(),nprim,1);
    zamom=Map<Matrix<qint64,Dynamic,1> >(wfn.zGaussianPrimitiveAngularMomenta(),nprim,1);
    alpha=Map<Matrix<qreal,Dynamic,1> >(wfn.gaussianPrimitiveExponentCoefficients(),nprim,1);
    // TODO Implement screening for unoccupied molecular orbitals.
    occno=Map<Matrix<qreal,Dynamic,1> >(wfn.molecularOrbitalOccupationNumbers(),nmo,1);
    orbe=Map<Matrix<qreal,Dynamic,1> >(wfn.molecularOrbitalEigenvalues(),nmo,1);
    coef=Map<Matrix<qreal,Dynamic,Dynamic,RowMajor> >(wfn.molecularOrbitalCoefficients(),nmo,nprim);
    totalEnergy=wfn.totalEnergy();
    virialRatio=wfn.virialRatio();

    cutoff=log(1.e-15);

    cdg000.resize(nmo);
    cdg100.resize(nmo);
    cdg010.resize(nmo);
    cdg001.resize(nmo);
    cdg200.resize(nmo);
    cdg110.resize(nmo);
    cdg101.resize(nmo);
    cdg020.resize(nmo);
    cdg011.resize(nmo);
    cdg002.resize(nmo);
    cdg300.resize(nmo);
    cdg120.resize(nmo);
    cdg102.resize(nmo);
    cdg210.resize(nmo);
    cdg030.resize(nmo);
    cdg012.resize(nmo);
    cdg201.resize(nmo);
    cdg021.resize(nmo);
    cdg003.resize(nmo);
    cdg111.resize(nmo);
    cdg400.resize(nmo);
    cdg220.resize(nmo);
    cdg202.resize(nmo);
    cdg310.resize(nmo);
    cdg130.resize(nmo);
    cdg112.resize(nmo);
    cdg301.resize(nmo);
    cdg121.resize(nmo);
    cdg103.resize(nmo);
    cdg040.resize(nmo);
    cdg022.resize(nmo);
    cdg211.resize(nmo);
    cdg031.resize(nmo);
    cdg013.resize(nmo);
    cdg004.resize(nmo);
  }

  const qreal QTAIMWavefunctionEvaluator::molecularOrbital( const qint64 mo, const Matrix<qreal,3,1> xyz )
  {
    
    qreal value=0.0;

    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 ); 

      if( b0arg > cutoff )
      {
        qreal ax0 = pow( xx0, xamom(p) );
        qreal ay0 = pow( yy0, yamom(p) );
        qreal az0 = pow( zz0, zamom(p) );

        qreal b0 = exp( b0arg );

        qreal dg000 = ax0*ay0*az0*b0;

        value += coef(mo,p)*dg000;
      }

    }
    
    return value;

  }

  const qreal QTAIMWavefunctionEvaluator::electronDensity( const Matrix<qreal,3,1> xyz )
  {

    qreal value;

    cdg000.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );
      
      if( b0arg > cutoff )
      {
        qreal ax0 = pow( xx0, xamom(p) );
        qreal ay0 = pow( yy0, yamom(p) );
        qreal az0 = pow( zz0, zamom(p) );

        qreal b0 = exp(b0arg);

        qreal dg000 = ax0*ay0*az0*b0;

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
        }

      }
    }

    value=0.0;
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      value += occno(m)*pow(cdg000(m),2);
    }

    return value;

  }

  const Matrix<qreal,3,1> QTAIMWavefunctionEvaluator::gradientOfElectronDensity(Matrix<qreal,3,1> xyz)
  {

    Matrix<qreal,3,1> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );
      
      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);

        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }
       
        qreal b0 = exp(b0arg);

        qreal bx1= -2*alpha(p)*xx0;
        qreal by1= -2*alpha(p)*yy0;
        qreal bz1= -2*alpha(p)*zz0;
        
        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
        }

      }
    }

    value.setZero();
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      value(0) += occno(m)*cdg100(m)*cdg000(m);
      value(1) += occno(m)*cdg010(m)*cdg000(m);
      value(2) += occno(m)*cdg001(m)*cdg000(m);
    }

    return value;

  }

  const Matrix<qreal,3,3> QTAIMWavefunctionEvaluator::hessianOfElectronDensity( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,3> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    cdg200.setZero();
    cdg020.setZero();
    cdg002.setZero();
    cdg110.setZero();
    cdg101.setZero();
    cdg011.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );
      
      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);
        qint64 aax2=xamom(p)*(xamom(p)-1);
        qint64 aay2=yamom(p)*(yamom(p)-1);
        qint64 aaz2=zamom(p)*(zamom(p)-1);
        
        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*pow(xx0,xamom(p)-2);
        }

        if     ( yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*pow(yy0,yamom(p)-2);
        }

        if     ( zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*pow(zz0,zamom(p)-2);
        }
        
        qreal b0 = exp(b0arg);

        qreal bx1 = -2*alpha(p)*xx0;
        qreal by1 = -2*alpha(p)*yy0;
        qreal bz1 = -2*alpha(p)*zz0;
        qreal bx2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(xx0,2));
        qreal by2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(yy0,2));
        qreal bz2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(zz0,2));
        
        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);
        qreal dg110 = az0*b0*(ax1+ax0*bx1)*(ay1+ay0*by1);
        qreal dg101 = ay0*b0*(ax1+ax0*bx1)*(az1+az0*bz1);
        qreal dg011 = ax0*b0*(ay1+ay0*by1)*(az1+az0*bz1);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
          cdg200(m) += coef(m,p) * dg200;
          cdg020(m) += coef(m,p) * dg020;
          cdg002(m) += coef(m,p) * dg002;
          cdg110(m) += coef(m,p) * dg110;
          cdg101(m) += coef(m,p) * dg101;
          cdg011(m) += coef(m,p) * dg011;
        }

      }
    }

    value.setZero();
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      value(0,0) += 2*occno(m)*(pow(cdg100(m),2)+cdg000(m)*cdg200(m));
      value(1,1) += 2*occno(m)*(pow(cdg010(m),2)+cdg000(m)*cdg020(m));
      value(2,2) += 2*occno(m)*(pow(cdg001(m),2)+cdg000(m)*cdg002(m));
      value(0,1) += 2*occno(m)*(cdg100(m)*cdg010(m)+cdg000(m)*cdg110(m));
      value(0,2) += 2*occno(m)*(cdg100(m)*cdg001(m)+cdg000(m)*cdg101(m));
      value(1,2) += 2*occno(m)*(cdg010(m)*cdg001(m)+cdg000(m)*cdg011(m));
    }
    value(1,0)=value(0,1);
    value(2,0)=value(0,2);
    value(2,1)=value(1,2);

    return value;

  }

  const Matrix<qreal,3,4> QTAIMWavefunctionEvaluator::gradientAndHessianOfElectronDensity( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,1> gValue;
    Matrix<qreal,3,3> hValue;
    Matrix<qreal,3,4> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    cdg200.setZero();
    cdg020.setZero();
    cdg002.setZero();
    cdg110.setZero();
    cdg101.setZero();
    cdg011.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );
      
      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);
        qint64 aax2=xamom(p)*(xamom(p)-1);
        qint64 aay2=yamom(p)*(yamom(p)-1);
        qint64 aaz2=zamom(p)*(zamom(p)-1);
        
        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*pow(xx0,xamom(p)-2);
        }

        if     ( yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*pow(yy0,yamom(p)-2);
        }

        if     ( zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*pow(zz0,zamom(p)-2);
        }
        
        qreal b0 = exp(b0arg);

        qreal bx1 = -2*alpha(p)*xx0;
        qreal by1 = -2*alpha(p)*yy0;
        qreal bz1 = -2*alpha(p)*zz0;
        qreal bx2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(xx0,2));
        qreal by2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(yy0,2));
        qreal bz2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(zz0,2));
        
        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);
        qreal dg110 = az0*b0*(ax1+ax0*bx1)*(ay1+ay0*by1);
        qreal dg101 = ay0*b0*(ax1+ax0*bx1)*(az1+az0*bz1);
        qreal dg011 = ax0*b0*(ay1+ay0*by1)*(az1+az0*bz1);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
          cdg200(m) += coef(m,p) * dg200;
          cdg020(m) += coef(m,p) * dg020;
          cdg002(m) += coef(m,p) * dg002;
          cdg110(m) += coef(m,p) * dg110;
          cdg101(m) += coef(m,p) * dg101;
          cdg011(m) += coef(m,p) * dg011;
        }

      }
    }

    gValue.setZero();
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      gValue(0) += occno(m)*cdg100(m)*cdg000(m);
      gValue(1) += occno(m)*cdg010(m)*cdg000(m);
      gValue(2) += occno(m)*cdg001(m)*cdg000(m);
    }

    hValue.setZero();
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      hValue(0,0) += 2*occno(m)*(pow(cdg100(m),2)+cdg000(m)*cdg200(m));
      hValue(1,1) += 2*occno(m)*(pow(cdg010(m),2)+cdg000(m)*cdg020(m));
      hValue(2,2) += 2*occno(m)*(pow(cdg001(m),2)+cdg000(m)*cdg002(m));
      hValue(0,1) += 2*occno(m)*(cdg100(m)*cdg010(m)+cdg000(m)*cdg110(m));
      hValue(0,2) += 2*occno(m)*(cdg100(m)*cdg001(m)+cdg000(m)*cdg101(m));
      hValue(1,2) += 2*occno(m)*(cdg010(m)*cdg001(m)+cdg000(m)*cdg011(m));
    }
    hValue(1,0)=hValue(0,1);
    hValue(2,0)=hValue(0,2);
    hValue(2,1)=hValue(1,2);

    value(0,0) = gValue(0);
    value(1,0) = gValue(1);
    value(2,0) = gValue(2);
    value(0,1) = hValue(0,0);
    value(1,1) = hValue(1,0);
    value(2,1) = hValue(2,0);
    value(0,2) = hValue(0,1);
    value(1,2) = hValue(1,1);
    value(2,2) = hValue(2,1);
    value(0,3) = hValue(0,2);
    value(1,3) = hValue(1,2);
    value(2,3) = hValue(2,2);
    
    return value;

  }

  const qreal QTAIMWavefunctionEvaluator::laplacianOfElectronDensity( const Matrix<qreal,3,1> xyz )
  {

    qreal value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    cdg200.setZero();
    cdg020.setZero();
    cdg002.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );
      
      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);
        qint64 aax2=xamom(p)*(xamom(p)-1);
        qint64 aay2=yamom(p)*(yamom(p)-1);
        qint64 aaz2=zamom(p)*(zamom(p)-1);
        
        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*pow(xx0,xamom(p)-2);
        }

        if     ( yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*pow(yy0,yamom(p)-2);
        }

        if     ( zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*pow(zz0,zamom(p)-2);
        }
        
        qreal b0 = exp(b0arg);

        qreal bx1 = -2*alpha(p)*xx0;
        qreal by1 = -2*alpha(p)*yy0;
        qreal bz1 = -2*alpha(p)*zz0;
        qreal bx2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(xx0,2));
        qreal by2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(yy0,2));
        qreal bz2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(zz0,2));
        
        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
          cdg200(m) += coef(m,p) * dg200;
          cdg020(m) += coef(m,p) * dg020;
          cdg002(m) += coef(m,p) * dg002;
        }

      }
    }

    value=0.0;
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      value +=    2*occno(m)*(pow(cdg100(m),2)+cdg000(m)*cdg200(m))
                 +2*occno(m)*(pow(cdg010(m),2)+cdg000(m)*cdg020(m))
                 +2*occno(m)*(pow(cdg001(m),2)+cdg000(m)*cdg002(m));
    }

    return value;

  }


  const Matrix<qreal,3,1> QTAIMWavefunctionEvaluator::gradientOfElectronDensityLaplacian( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,1> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    cdg200.setZero();
    cdg020.setZero();
    cdg002.setZero();
    cdg110.setZero();
    cdg101.setZero();
    cdg011.setZero();
    cdg300.setZero();
    cdg120.setZero();
    cdg102.setZero();
    cdg210.setZero();
    cdg030.setZero();
    cdg012.setZero();
    cdg201.setZero();
    cdg021.setZero();
    cdg003.setZero();
    // cdg111.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );
      
      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);
        qint64 aax2=xamom(p)*(xamom(p)-1);
        qint64 aay2=yamom(p)*(yamom(p)-1);
        qint64 aaz2=zamom(p)*(zamom(p)-1);
        qint64 aax3=xamom(p)*(xamom(p)-1)*(xamom(p)-2);
        qint64 aay3=yamom(p)*(yamom(p)-1)*(yamom(p)-2);
        qint64 aaz3=zamom(p)*(zamom(p)-1)*(zamom(p)-2);

        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*pow(xx0,xamom(p)-2);
        }

        if     ( yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*pow(yy0,yamom(p)-2);
        }

        if     ( zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*pow(zz0,zamom(p)-2);
        }
        
        qreal ax3;
        qreal ay3;
        qreal az3;
        if     ( xamom(p) <  3 )
        {
          ax3=zero;
        }
        else if( xamom(p) == 3 )
        {
          ax3=one;
        }
        else
        {
          ax3=aax3*pow(xx0,xamom(p)-3);
        }

        if     ( yamom(p) <  3 )
        {
          ay3=zero;
        }
        else if( yamom(p) == 3 )
        {
          ay3=one;
        }
        else
        {
          ay3=aay3*pow(yy0,yamom(p)-3);
        }

        if     ( zamom(p) <  3 )
        {
          az3=zero;
        }
        else if( zamom(p) == 3 )
        {
          az3=one;
        }
        else
        {
          az3=aaz3*pow(zz0,zamom(p)-3);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*alpha(p)*xx0;
        qreal by1 = -2*alpha(p)*yy0;
        qreal bz1 = -2*alpha(p)*zz0;
        qreal bx2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(xx0,2));
        qreal by2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(yy0,2));
        qreal bz2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(zz0,2));
        qreal bx3 = (12*pow(alpha(p),2)*xx0)-(8*pow(alpha(p),3) * pow(xx0,3));
        qreal by3 = (12*pow(alpha(p),2)*yy0)-(8*pow(alpha(p),3) * pow(yy0,3));
        qreal bz3 = (12*pow(alpha(p),2)*zz0)-(8*pow(alpha(p),3) * pow(zz0,3));

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);
        qreal dg110 = az0*b0*(ax1+ax0*bx1)*(ay1+ay0*by1);
        qreal dg101 = ay0*b0*(ax1+ax0*bx1)*(az1+az0*bz1);
        qreal dg011 = ax0*b0*(ay1+ay0*by1)*(az1+az0*bz1);
        qreal dg300 = ay0*az0*b0*(ax3+3*ax2*bx1+3*ax1*bx2+ax0*bx3);
        qreal dg030 = ax0*az0*b0*(ay3+3*ay2*by1+3*ay1*by2+ay0*by3);
        qreal dg003 = ax0*ay0*b0*(az3+3*az2*bz1+3*az1*bz2+az0*bz3);
        qreal dg210 = az0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(ay1+ay0*by1);
        qreal dg201 = ay0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(az1+az0*bz1);
        qreal dg120 = az0*b0*(ax1+ax0*bx1)*(ay2+2*ay1*by1+ay0*by2);
        qreal dg021 = ax0*b0*(ay2+2*ay1*by1+ay0*by2)*(az1+az0*bz1);
        qreal dg102 = ay0*b0*(ax1+ax0*bx1)*(az2+2*az1*bz1+az0*bz2);
        qreal dg012 = ax0*b0*(ay1+ay0*by1)*(az2+2*az1*bz1+az0*bz2);
        // qreal dg111 = b0*(ax1+ax0*bx1)*(ay1+ay0*by1)*(az1+az0*bz1);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
          cdg200(m) += coef(m,p) * dg200;
          cdg020(m) += coef(m,p) * dg020;
          cdg002(m) += coef(m,p) * dg002;
          cdg110(m) += coef(m,p) * dg110;
          cdg101(m) += coef(m,p) * dg101;
          cdg011(m) += coef(m,p) * dg011;
          cdg300(m) += coef(m,p) * dg300;
          cdg030(m) += coef(m,p) * dg030;
          cdg003(m) += coef(m,p) * dg003;
          cdg210(m) += coef(m,p) * dg210;
          cdg201(m) += coef(m,p) * dg201;
          cdg120(m) += coef(m,p) * dg120;
          cdg021(m) += coef(m,p) * dg021;
          cdg102(m) += coef(m,p) * dg102;
          cdg012(m) += coef(m,p) * dg012;
          // cdg111(m) += coef(m,p) * dg111;
        }

      }
    }

    qreal deriv300=zero;
    qreal deriv030=zero;
    qreal deriv003=zero;
    qreal deriv210=zero;
    qreal deriv201=zero;
    qreal deriv120=zero;
    qreal deriv021=zero;
    qreal deriv102=zero;
    qreal deriv012=zero;
    // qreal deriv111=zero;
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      deriv300+=(occno(m)*( 6*cdg100(m)*cdg200(m)+2*cdg000(m)*cdg300(m) ));
      deriv030+=(occno(m)*( 6*cdg010(m)*cdg020(m)+2*cdg000(m)*cdg030(m) ));
      deriv003+=(occno(m)*( 6*cdg001(m)*cdg002(m)+2*cdg000(m)*cdg003(m) ));
      deriv210+=(occno(m)*( 2*(2*cdg100(m)*cdg110(m)+cdg010(m)*cdg200(m)+cdg000(m)*cdg210(m)) ));
      deriv201+=(occno(m)*( 2*(2*cdg100(m)*cdg101(m)+cdg001(m)*cdg200(m)+cdg000(m)*cdg201(m)) ));
      deriv120+=(occno(m)*( 2*(cdg020(m)*cdg100(m)+2*cdg010(m)*cdg110(m)+cdg000(m)*cdg120(m)) ));
      deriv021+=(occno(m)*( 2*(2*cdg010(m)*cdg011(m)+cdg001(m)*cdg020(m)+cdg000(m)*cdg021(m)) ));
      deriv102+=(occno(m)*( 2*(cdg002(m)*cdg100(m)+2*cdg001(m)*cdg101(m)+cdg000(m)*cdg102(m)) ));
      deriv012+=(occno(m)*( 2*(cdg002(m)*cdg010(m)+2*cdg001(m)*cdg011(m)+cdg000(m)*cdg012(m)) ));
      // deriv111+=(occno(m)*( 2*(cdg011(m)*cdg100(m)+cdg010(m)*cdg101(m)+cdg001(m)*cdg110(m)+cdg000(m)*cdg111(m)) ));
    }

    value(0)=deriv300+deriv120+deriv102;
    value(1)=deriv210+deriv030+deriv012;
    value(2)=deriv201+deriv021+deriv003;

    return value;

  }

  const Matrix<qreal,3,3> QTAIMWavefunctionEvaluator::hessianOfElectronDensityLaplacian( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,3> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    cdg200.setZero();
    cdg020.setZero();
    cdg002.setZero();
    cdg110.setZero();
    cdg101.setZero();
    cdg011.setZero();
    cdg300.setZero();
    cdg120.setZero();
    cdg102.setZero();
    cdg210.setZero();
    cdg030.setZero();
    cdg012.setZero();
    cdg201.setZero();
    cdg021.setZero();
    cdg003.setZero();
    cdg111.setZero();
    cdg400.setZero();
    cdg040.setZero();
    cdg004.setZero();
    cdg310.setZero();
    cdg301.setZero();
    cdg130.setZero();
    cdg031.setZero();
    cdg103.setZero();
    cdg013.setZero();
    cdg220.setZero();
    cdg202.setZero();
    cdg022.setZero();
    cdg211.setZero();
    cdg121.setZero();
    cdg112.setZero();

    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);
        qint64 aax2=xamom(p)*(xamom(p)-1);
        qint64 aay2=yamom(p)*(yamom(p)-1);
        qint64 aaz2=zamom(p)*(zamom(p)-1);
        qint64 aax3=xamom(p)*(xamom(p)-1)*(xamom(p)-2);
        qint64 aay3=yamom(p)*(yamom(p)-1)*(yamom(p)-2);
        qint64 aaz3=zamom(p)*(zamom(p)-1)*(zamom(p)-2);
        qint64 aax4=xamom(p)*(xamom(p)-1)*(xamom(p)-2)*(xamom(p)-3);
        qint64 aay4=yamom(p)*(yamom(p)-1)*(yamom(p)-2)*(xamom(p)-3);
        qint64 aaz4=zamom(p)*(zamom(p)-1)*(zamom(p)-2)*(xamom(p)-3);

        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*pow(xx0,xamom(p)-2);
        }

        if     ( yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*pow(yy0,yamom(p)-2);
        }

        if     ( zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*pow(zz0,zamom(p)-2);
        }

        qreal ax3;
        qreal ay3;
        qreal az3;
        if     ( xamom(p) <  3 )
        {
          ax3=zero;
        }
        else if( xamom(p) == 3 )
        {
          ax3=one;
        }
        else
        {
          ax3=aax3*pow(xx0,xamom(p)-3);
        }

        if     ( yamom(p) <  3 )
        {
          ay3=zero;
        }
        else if( yamom(p) == 3 )
        {
          ay3=one;
        }
        else
        {
          ay3=aay3*pow(yy0,yamom(p)-3);
        }

        if     ( zamom(p) <  3 )
        {
          az3=zero;
        }
        else if( zamom(p) == 3 )
        {
          az3=one;
        }
        else
        {
          az3=aaz3*pow(zz0,zamom(p)-3);
        }

        qreal ax4;
        qreal ay4;
        qreal az4;
        if     ( xamom(p) <  4 )
        {
          ax4=zero;
        }
        else if( xamom(p) == 4 )
        {
          ax4=one;
        }
        else
        {
          ax4=aax4*pow(xx0,xamom(p)-4);
        }

        if     ( yamom(p) <  4 )
        {
          ay4=zero;
        }
        else if( yamom(p) == 4 )
        {
          ay4=one;
        }
        else
        {
          ay4=aay4*pow(yy0,yamom(p)-4);
        }

        if     ( zamom(p) <  4 )
        {
          az4=zero;
        }
        else if( zamom(p) == 4 )
        {
          az4=one;
        }
        else
        {
          az4=aaz4*pow(zz0,zamom(p)-4);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*alpha(p)*xx0;
        qreal by1 = -2*alpha(p)*yy0;
        qreal bz1 = -2*alpha(p)*zz0;
        qreal bx2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(xx0,2));
        qreal by2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(yy0,2));
        qreal bz2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(zz0,2));
        qreal bx3 = (12*pow(alpha(p),2)*xx0)-(8*pow(alpha(p),3) * pow(xx0,3));
        qreal by3 = (12*pow(alpha(p),2)*yy0)-(8*pow(alpha(p),3) * pow(yy0,3));
        qreal bz3 = (12*pow(alpha(p),2)*zz0)-(8*pow(alpha(p),3) * pow(zz0,3));
        qreal bx4 = (12*pow(alpha(p),2))-(48*pow(alpha(p),3) * pow(xx0,2))+(16*pow(alpha(p),4) * pow(xx0,4));
        qreal by4 = (12*pow(alpha(p),2))-(48*pow(alpha(p),3) * pow(yy0,2))+(16*pow(alpha(p),4) * pow(yy0,4));
        qreal bz4 = (12*pow(alpha(p),2))-(48*pow(alpha(p),3) * pow(zz0,2))+(16*pow(alpha(p),4) * pow(zz0,4));

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);
        qreal dg110 = az0*b0*(ax1+ax0*bx1)*(ay1+ay0*by1);
        qreal dg101 = ay0*b0*(ax1+ax0*bx1)*(az1+az0*bz1);
        qreal dg011 = ax0*b0*(ay1+ay0*by1)*(az1+az0*bz1);
        qreal dg300 = ay0*az0*b0*(ax3+3*ax2*bx1+3*ax1*bx2+ax0*bx3);
        qreal dg030 = ax0*az0*b0*(ay3+3*ay2*by1+3*ay1*by2+ay0*by3);
        qreal dg003 = ax0*ay0*b0*(az3+3*az2*bz1+3*az1*bz2+az0*bz3);
        qreal dg210 = az0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(ay1+ay0*by1);
        qreal dg201 = ay0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(az1+az0*bz1);
        qreal dg120 = az0*b0*(ax1+ax0*bx1)*(ay2+2*ay1*by1+ay0*by2);
        qreal dg021 = ax0*b0*(ay2+2*ay1*by1+ay0*by2)*(az1+az0*bz1);
        qreal dg102 = ay0*b0*(ax1+ax0*bx1)*(az2+2*az1*bz1+az0*bz2);
        qreal dg012 = ax0*b0*(ay1+ay0*by1)*(az2+2*az1*bz1+az0*bz2);
        qreal dg111 = b0*(ax1+ax0*bx1)*(ay1+ay0*by1)*(az1+az0*bz1);
        qreal dg400 = ay0*az0*b0*(ax4+4*ax3*bx1+6*ax2*bx2+4*ax1*bx3+ax0*bx4);
        qreal dg040 = ax0*az0*b0*(ay4+4*ay3*by1+6*ay2*by2+4*ay1*by3+ay0*by4);
        qreal dg004 = ax0*ay0*b0*(az4+4*az3*bz1+6*az2*bz2+4*az1*bz3+az0*bz4);
        qreal dg310 = az0*b0*(ax3+3*ax2*bx1+3*ax1*bx2+ax0*bx3)*(ay1+ay0*by1);
        qreal dg301 = ay0*b0*(ax3+3*ax2*bx1+3*ax1*bx2+ax0*bx3)*(az1+az0*bz1);
        qreal dg130 = az0*b0*(ax1+ax0*bx1)*(ay3+3*ay2*by1+3*ay1*by2+ay0*by3);
        qreal dg031 = ax0*b0*(ay3+3*ay2*by1+3*ay1*by2+ay0*by3)*(az1+az0*bz1);
        qreal dg103 = ay0*b0*(ax1+ax0*bx1)*(az3+3*az2*bz1+3*az1*bz2+az0*bz3);
        qreal dg013 = ax0*b0*(ay1+ay0*by1)*(az3+3*az2*bz1+3*az1*bz2+az0*bz3);
        qreal dg220 = az0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(ay2+2*ay1*by1+ay0*by2);
        qreal dg202 = ay0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(az2+2*az1*bz1+az0*bz2);
        qreal dg022 = ax0*b0*(ay2+2*ay1*by1+ay0*by2)*(az2+2*az1*bz1+az0*bz2);
        qreal dg211 = b0*(ax2+2*ax1*bx1+ax0*bx2)*(ay1+ay0*by1)*(az1+az0*bz1);
        qreal dg121 = b0*(ax1+ax0*bx1)*(ay2+2*ay1*by1+ay0*by2)*(az1+az0*bz1);
        qreal dg112 = b0*(ax1+ax0*bx1)*(ay1+ay0*by1)*(az2+2*az1*bz1+az0*bz2);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
          cdg200(m) += coef(m,p) * dg200;
          cdg020(m) += coef(m,p) * dg020;
          cdg002(m) += coef(m,p) * dg002;
          cdg110(m) += coef(m,p) * dg110;
          cdg101(m) += coef(m,p) * dg101;
          cdg011(m) += coef(m,p) * dg011;
          cdg300(m) += coef(m,p) * dg300;
          cdg030(m) += coef(m,p) * dg030;
          cdg003(m) += coef(m,p) * dg003;
          cdg210(m) += coef(m,p) * dg210;
          cdg201(m) += coef(m,p) * dg201;
          cdg120(m) += coef(m,p) * dg120;
          cdg021(m) += coef(m,p) * dg021;
          cdg102(m) += coef(m,p) * dg102;
          cdg012(m) += coef(m,p) * dg012;
          cdg111(m) += coef(m,p) * dg111;
          cdg400(m) += coef(m,p) * dg400;
          cdg040(m) += coef(m,p) * dg040;
          cdg004(m) += coef(m,p) * dg004;
          cdg310(m) += coef(m,p) * dg310;
          cdg301(m) += coef(m,p) * dg301;
          cdg130(m) += coef(m,p) * dg130;
          cdg031(m) += coef(m,p) * dg031;
          cdg103(m) += coef(m,p) * dg103;
          cdg013(m) += coef(m,p) * dg013;
          cdg220(m) += coef(m,p) * dg220;
          cdg202(m) += coef(m,p) * dg202;
          cdg022(m) += coef(m,p) * dg022;
          cdg211(m) += coef(m,p) * dg211;
          cdg121(m) += coef(m,p) * dg121;
          cdg112(m) += coef(m,p) * dg112;
        }

      }
    }

    qreal deriv400=zero;
    qreal deriv040=zero;
    qreal deriv004=zero;
    qreal deriv310=zero;
    qreal deriv301=zero;
    qreal deriv130=zero;
    qreal deriv031=zero;
    qreal deriv103=zero;
    qreal deriv013=zero;
    qreal deriv220=zero;
    qreal deriv202=zero;
    qreal deriv022=zero;
    qreal deriv211=zero;
    qreal deriv121=zero;
    qreal deriv112=zero;
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      deriv400+=(occno(m)*(6*pow(cdg200(m),2)+8*cdg100(m)*cdg300(m)+2*cdg000(m)*cdg400(m)));
      deriv040+=(occno(m)*(6*pow(cdg020(m),2)+8*cdg010(m)*cdg030(m)+2*cdg000(m)*cdg040(m)));
      deriv004+=(occno(m)*(6*pow(cdg002(m),2)+8*cdg001(m)*cdg003(m)+2*cdg000(m)*cdg004(m)));
      deriv310+=(occno(m)*(2*(3*cdg110(m)*cdg200(m)+3*cdg100(m)*cdg210(m)+cdg010(m)*cdg300(m)+cdg000(m)*cdg310(m))));
      deriv301+=(occno(m)*(2*(3*cdg101(m)*cdg200(m)+3*cdg100(m)*cdg201(m)+cdg001(m)*cdg300(m)+cdg000(m)*cdg301(m))));
      deriv130+=(occno(m)*(2*(cdg030(m)*cdg100(m)+3*cdg020(m)*cdg110(m)+3*cdg010(m)*cdg120(m)+cdg000(m)*cdg130(m))));
      deriv031+=(occno(m)*(2*(3*cdg011(m)*cdg020(m)+3*cdg010(m)*cdg021(m)+cdg001(m)*cdg030(m)+cdg000(m)*cdg031(m))));
      deriv103+=(occno(m)*(2*(cdg003(m)*cdg100(m)+3*cdg002(m)*cdg101(m)+3*cdg001(m)*cdg102(m)+cdg000(m)*cdg103(m))));
      deriv013+=(occno(m)*(2*(cdg003(m)*cdg010(m)+3*cdg002(m)*cdg011(m)+3*cdg001(m)*cdg012(m)+cdg000(m)*cdg013(m))));
      deriv220+=(occno(m)*(2*(2*pow(cdg110(m),2)+2*cdg100(m)*cdg120(m)+cdg020(m)*cdg200(m)+2*cdg010(m)*cdg210(m)+cdg000(m)*cdg220(m))));
      deriv202+=(occno(m)*(2*(2*pow(cdg101(m),2)+2*cdg100(m)*cdg102(m)+cdg002(m)*cdg200(m)+2*cdg001(m)*cdg201(m)+cdg000(m)*cdg202(m))));
      deriv022+=(occno(m)*(2*(2*pow(cdg011(m),2)+2*cdg010(m)*cdg012(m)+cdg002(m)*cdg020(m)+2*cdg001(m)*cdg021(m)+cdg000(m)*cdg022(m))));
      deriv211+=(occno(m)*(2*(2*cdg101(m)*cdg110(m)+2*cdg100(m)*cdg111(m)+cdg011(m)*cdg200(m)+cdg010(m)*cdg201(m)+cdg001(m)*cdg210(m)+cdg000(m)*cdg211(m))));
      deriv121+=(occno(m)*(2*(cdg021(m)*cdg100(m)+cdg020(m)*cdg101(m)+2*cdg011(m)*cdg110(m)+2*cdg010(m)*cdg111(m)+cdg001(m)*cdg120(m)+cdg000(m)*cdg121(m))));
      deriv112+=(occno(m)*(2*(cdg012(m)*cdg100(m)+2*cdg011(m)*cdg101(m)+cdg010(m)*cdg102(m)+cdg002(m)*cdg110(m)+2*cdg001(m)*cdg111(m)+cdg000(m)*cdg112(m))));
    }

    value(0,0)=deriv400+deriv220+deriv202;
    value(1,1)=deriv220+deriv040+deriv022;
    value(2,2)=deriv202+deriv022+deriv004;
    value(0,1)=deriv310+deriv130+deriv112;
    value(0,2)=deriv301+deriv121+deriv103;
    value(1,2)=deriv211+deriv031+deriv013;
    value(1,0)=value(0,1);
    value(2,0)=value(0,2);
    value(2,1)=value(1,2);

    return value;

  }

  const Matrix<qreal,3,4> QTAIMWavefunctionEvaluator::gradientAndHessianOfElectronDensityLaplacian( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,1> gValue;
    Matrix<qreal,3,3> hValue;
    Matrix<qreal,3,4> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    cdg200.setZero();
    cdg020.setZero();
    cdg002.setZero();
    cdg110.setZero();
    cdg101.setZero();
    cdg011.setZero();
    cdg300.setZero();
    cdg120.setZero();
    cdg102.setZero();
    cdg210.setZero();
    cdg030.setZero();
    cdg012.setZero();
    cdg201.setZero();
    cdg021.setZero();
    cdg003.setZero();
    cdg111.setZero();
    cdg400.setZero();
    cdg040.setZero();
    cdg004.setZero();
    cdg310.setZero();
    cdg301.setZero();
    cdg130.setZero();
    cdg031.setZero();
    cdg103.setZero();
    cdg013.setZero();
    cdg220.setZero();
    cdg202.setZero();
    cdg022.setZero();
    cdg211.setZero();
    cdg121.setZero();
    cdg112.setZero();

    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);
        qint64 aax2=xamom(p)*(xamom(p)-1);
        qint64 aay2=yamom(p)*(yamom(p)-1);
        qint64 aaz2=zamom(p)*(zamom(p)-1);
        qint64 aax3=xamom(p)*(xamom(p)-1)*(xamom(p)-2);
        qint64 aay3=yamom(p)*(yamom(p)-1)*(yamom(p)-2);
        qint64 aaz3=zamom(p)*(zamom(p)-1)*(zamom(p)-2);
        qint64 aax4=xamom(p)*(xamom(p)-1)*(xamom(p)-2)*(xamom(p)-3);
        qint64 aay4=yamom(p)*(yamom(p)-1)*(yamom(p)-2)*(xamom(p)-3);
        qint64 aaz4=zamom(p)*(zamom(p)-1)*(zamom(p)-2)*(xamom(p)-3);

        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*pow(xx0,xamom(p)-2);
        }

        if     ( yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*pow(yy0,yamom(p)-2);
        }

        if     ( zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*pow(zz0,zamom(p)-2);
        }

        qreal ax3;
        qreal ay3;
        qreal az3;
        if     ( xamom(p) <  3 )
        {
          ax3=zero;
        }
        else if( xamom(p) == 3 )
        {
          ax3=one;
        }
        else
        {
          ax3=aax3*pow(xx0,xamom(p)-3);
        }

        if     ( yamom(p) <  3 )
        {
          ay3=zero;
        }
        else if( yamom(p) == 3 )
        {
          ay3=one;
        }
        else
        {
          ay3=aay3*pow(yy0,yamom(p)-3);
        }

        if     ( zamom(p) <  3 )
        {
          az3=zero;
        }
        else if( zamom(p) == 3 )
        {
          az3=one;
        }
        else
        {
          az3=aaz3*pow(zz0,zamom(p)-3);
        }

        qreal ax4;
        qreal ay4;
        qreal az4;
        if     ( xamom(p) <  4 )
        {
          ax4=zero;
        }
        else if( xamom(p) == 4 )
        {
          ax4=one;
        }
        else
        {
          ax4=aax4*pow(xx0,xamom(p)-4);
        }

        if     ( yamom(p) <  4 )
        {
          ay4=zero;
        }
        else if( yamom(p) == 4 )
        {
          ay4=one;
        }
        else
        {
          ay4=aay4*pow(yy0,yamom(p)-4);
        }

        if     ( zamom(p) <  4 )
        {
          az4=zero;
        }
        else if( zamom(p) == 4 )
        {
          az4=one;
        }
        else
        {
          az4=aaz4*pow(zz0,zamom(p)-4);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*alpha(p)*xx0;
        qreal by1 = -2*alpha(p)*yy0;
        qreal bz1 = -2*alpha(p)*zz0;
        qreal bx2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(xx0,2));
        qreal by2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(yy0,2));
        qreal bz2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(zz0,2));
        qreal bx3 = (12*pow(alpha(p),2)*xx0)-(8*pow(alpha(p),3) * pow(xx0,3));
        qreal by3 = (12*pow(alpha(p),2)*yy0)-(8*pow(alpha(p),3) * pow(yy0,3));
        qreal bz3 = (12*pow(alpha(p),2)*zz0)-(8*pow(alpha(p),3) * pow(zz0,3));
        qreal bx4 = (12*pow(alpha(p),2))-(48*pow(alpha(p),3) * pow(xx0,2))+(16*pow(alpha(p),4) * pow(xx0,4));
        qreal by4 = (12*pow(alpha(p),2))-(48*pow(alpha(p),3) * pow(yy0,2))+(16*pow(alpha(p),4) * pow(yy0,4));
        qreal bz4 = (12*pow(alpha(p),2))-(48*pow(alpha(p),3) * pow(zz0,2))+(16*pow(alpha(p),4) * pow(zz0,4));

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);
        qreal dg110 = az0*b0*(ax1+ax0*bx1)*(ay1+ay0*by1);
        qreal dg101 = ay0*b0*(ax1+ax0*bx1)*(az1+az0*bz1);
        qreal dg011 = ax0*b0*(ay1+ay0*by1)*(az1+az0*bz1);
        qreal dg300 = ay0*az0*b0*(ax3+3*ax2*bx1+3*ax1*bx2+ax0*bx3);
        qreal dg030 = ax0*az0*b0*(ay3+3*ay2*by1+3*ay1*by2+ay0*by3);
        qreal dg003 = ax0*ay0*b0*(az3+3*az2*bz1+3*az1*bz2+az0*bz3);
        qreal dg210 = az0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(ay1+ay0*by1);
        qreal dg201 = ay0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(az1+az0*bz1);
        qreal dg120 = az0*b0*(ax1+ax0*bx1)*(ay2+2*ay1*by1+ay0*by2);
        qreal dg021 = ax0*b0*(ay2+2*ay1*by1+ay0*by2)*(az1+az0*bz1);
        qreal dg102 = ay0*b0*(ax1+ax0*bx1)*(az2+2*az1*bz1+az0*bz2);
        qreal dg012 = ax0*b0*(ay1+ay0*by1)*(az2+2*az1*bz1+az0*bz2);
        qreal dg111 = b0*(ax1+ax0*bx1)*(ay1+ay0*by1)*(az1+az0*bz1);
        qreal dg400 = ay0*az0*b0*(ax4+4*ax3*bx1+6*ax2*bx2+4*ax1*bx3+ax0*bx4);
        qreal dg040 = ax0*az0*b0*(ay4+4*ay3*by1+6*ay2*by2+4*ay1*by3+ay0*by4);
        qreal dg004 = ax0*ay0*b0*(az4+4*az3*bz1+6*az2*bz2+4*az1*bz3+az0*bz4);
        qreal dg310 = az0*b0*(ax3+3*ax2*bx1+3*ax1*bx2+ax0*bx3)*(ay1+ay0*by1);
        qreal dg301 = ay0*b0*(ax3+3*ax2*bx1+3*ax1*bx2+ax0*bx3)*(az1+az0*bz1);
        qreal dg130 = az0*b0*(ax1+ax0*bx1)*(ay3+3*ay2*by1+3*ay1*by2+ay0*by3);
        qreal dg031 = ax0*b0*(ay3+3*ay2*by1+3*ay1*by2+ay0*by3)*(az1+az0*bz1);
        qreal dg103 = ay0*b0*(ax1+ax0*bx1)*(az3+3*az2*bz1+3*az1*bz2+az0*bz3);
        qreal dg013 = ax0*b0*(ay1+ay0*by1)*(az3+3*az2*bz1+3*az1*bz2+az0*bz3);
        qreal dg220 = az0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(ay2+2*ay1*by1+ay0*by2);
        qreal dg202 = ay0*b0*(ax2+2*ax1*bx1+ax0*bx2)*(az2+2*az1*bz1+az0*bz2);
        qreal dg022 = ax0*b0*(ay2+2*ay1*by1+ay0*by2)*(az2+2*az1*bz1+az0*bz2);
        qreal dg211 = b0*(ax2+2*ax1*bx1+ax0*bx2)*(ay1+ay0*by1)*(az1+az0*bz1);
        qreal dg121 = b0*(ax1+ax0*bx1)*(ay2+2*ay1*by1+ay0*by2)*(az1+az0*bz1);
        qreal dg112 = b0*(ax1+ax0*bx1)*(ay1+ay0*by1)*(az2+2*az1*bz1+az0*bz2);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
          cdg200(m) += coef(m,p) * dg200;
          cdg020(m) += coef(m,p) * dg020;
          cdg002(m) += coef(m,p) * dg002;
          cdg110(m) += coef(m,p) * dg110;
          cdg101(m) += coef(m,p) * dg101;
          cdg011(m) += coef(m,p) * dg011;
          cdg300(m) += coef(m,p) * dg300;
          cdg030(m) += coef(m,p) * dg030;
          cdg003(m) += coef(m,p) * dg003;
          cdg210(m) += coef(m,p) * dg210;
          cdg201(m) += coef(m,p) * dg201;
          cdg120(m) += coef(m,p) * dg120;
          cdg021(m) += coef(m,p) * dg021;
          cdg102(m) += coef(m,p) * dg102;
          cdg012(m) += coef(m,p) * dg012;
          cdg111(m) += coef(m,p) * dg111;
          cdg400(m) += coef(m,p) * dg400;
          cdg040(m) += coef(m,p) * dg040;
          cdg004(m) += coef(m,p) * dg004;
          cdg310(m) += coef(m,p) * dg310;
          cdg301(m) += coef(m,p) * dg301;
          cdg130(m) += coef(m,p) * dg130;
          cdg031(m) += coef(m,p) * dg031;
          cdg103(m) += coef(m,p) * dg103;
          cdg013(m) += coef(m,p) * dg013;
          cdg220(m) += coef(m,p) * dg220;
          cdg202(m) += coef(m,p) * dg202;
          cdg022(m) += coef(m,p) * dg022;
          cdg211(m) += coef(m,p) * dg211;
          cdg121(m) += coef(m,p) * dg121;
          cdg112(m) += coef(m,p) * dg112;
        }

      }
    }

    qreal deriv300=zero;
    qreal deriv030=zero;
    qreal deriv003=zero;
    qreal deriv210=zero;
    qreal deriv201=zero;
    qreal deriv120=zero;
    qreal deriv021=zero;
    qreal deriv102=zero;
    qreal deriv012=zero;
    qreal deriv400=zero;
    qreal deriv040=zero;
    qreal deriv004=zero;
    qreal deriv310=zero;
    qreal deriv301=zero;
    qreal deriv130=zero;
    qreal deriv031=zero;
    qreal deriv103=zero;
    qreal deriv013=zero;
    qreal deriv220=zero;
    qreal deriv202=zero;
    qreal deriv022=zero;
    qreal deriv211=zero;
    qreal deriv121=zero;
    qreal deriv112=zero;
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      deriv300+=(occno(m)*( 6*cdg100(m)*cdg200(m)+2*cdg000(m)*cdg300(m) ));
      deriv030+=(occno(m)*( 6*cdg010(m)*cdg020(m)+2*cdg000(m)*cdg030(m) ));
      deriv003+=(occno(m)*( 6*cdg001(m)*cdg002(m)+2*cdg000(m)*cdg003(m) ));
      deriv210+=(occno(m)*( 2*(2*cdg100(m)*cdg110(m)+cdg010(m)*cdg200(m)+cdg000(m)*cdg210(m)) ));
      deriv201+=(occno(m)*( 2*(2*cdg100(m)*cdg101(m)+cdg001(m)*cdg200(m)+cdg000(m)*cdg201(m)) ));
      deriv120+=(occno(m)*( 2*(cdg020(m)*cdg100(m)+2*cdg010(m)*cdg110(m)+cdg000(m)*cdg120(m)) ));
      deriv021+=(occno(m)*( 2*(2*cdg010(m)*cdg011(m)+cdg001(m)*cdg020(m)+cdg000(m)*cdg021(m)) ));
      deriv102+=(occno(m)*( 2*(cdg002(m)*cdg100(m)+2*cdg001(m)*cdg101(m)+cdg000(m)*cdg102(m)) ));
      deriv012+=(occno(m)*( 2*(cdg002(m)*cdg010(m)+2*cdg001(m)*cdg011(m)+cdg000(m)*cdg012(m)) ));
      // deriv111+=(occno(m)*( 2*(cdg011(m)*cdg100(m)+cdg010(m)*cdg101(m)+cdg001(m)*cdg110(m)+cdg000(m)*cdg111(m)) ));
      deriv400+=(occno(m)*(6*pow(cdg200(m),2)+8*cdg100(m)*cdg300(m)+2*cdg000(m)*cdg400(m)));
      deriv040+=(occno(m)*(6*pow(cdg020(m),2)+8*cdg010(m)*cdg030(m)+2*cdg000(m)*cdg040(m)));
      deriv004+=(occno(m)*(6*pow(cdg002(m),2)+8*cdg001(m)*cdg003(m)+2*cdg000(m)*cdg004(m)));
      deriv310+=(occno(m)*(2*(3*cdg110(m)*cdg200(m)+3*cdg100(m)*cdg210(m)+cdg010(m)*cdg300(m)+cdg000(m)*cdg310(m))));
      deriv301+=(occno(m)*(2*(3*cdg101(m)*cdg200(m)+3*cdg100(m)*cdg201(m)+cdg001(m)*cdg300(m)+cdg000(m)*cdg301(m))));
      deriv130+=(occno(m)*(2*(cdg030(m)*cdg100(m)+3*cdg020(m)*cdg110(m)+3*cdg010(m)*cdg120(m)+cdg000(m)*cdg130(m))));
      deriv031+=(occno(m)*(2*(3*cdg011(m)*cdg020(m)+3*cdg010(m)*cdg021(m)+cdg001(m)*cdg030(m)+cdg000(m)*cdg031(m))));
      deriv103+=(occno(m)*(2*(cdg003(m)*cdg100(m)+3*cdg002(m)*cdg101(m)+3*cdg001(m)*cdg102(m)+cdg000(m)*cdg103(m))));
      deriv013+=(occno(m)*(2*(cdg003(m)*cdg010(m)+3*cdg002(m)*cdg011(m)+3*cdg001(m)*cdg012(m)+cdg000(m)*cdg013(m))));
      deriv220+=(occno(m)*(2*(2*pow(cdg110(m),2)+2*cdg100(m)*cdg120(m)+cdg020(m)*cdg200(m)+2*cdg010(m)*cdg210(m)+cdg000(m)*cdg220(m))));
      deriv202+=(occno(m)*(2*(2*pow(cdg101(m),2)+2*cdg100(m)*cdg102(m)+cdg002(m)*cdg200(m)+2*cdg001(m)*cdg201(m)+cdg000(m)*cdg202(m))));
      deriv022+=(occno(m)*(2*(2*pow(cdg011(m),2)+2*cdg010(m)*cdg012(m)+cdg002(m)*cdg020(m)+2*cdg001(m)*cdg021(m)+cdg000(m)*cdg022(m))));
      deriv211+=(occno(m)*(2*(2*cdg101(m)*cdg110(m)+2*cdg100(m)*cdg111(m)+cdg011(m)*cdg200(m)+cdg010(m)*cdg201(m)+cdg001(m)*cdg210(m)+cdg000(m)*cdg211(m))));
      deriv121+=(occno(m)*(2*(cdg021(m)*cdg100(m)+cdg020(m)*cdg101(m)+2*cdg011(m)*cdg110(m)+2*cdg010(m)*cdg111(m)+cdg001(m)*cdg120(m)+cdg000(m)*cdg121(m))));
      deriv112+=(occno(m)*(2*(cdg012(m)*cdg100(m)+2*cdg011(m)*cdg101(m)+cdg010(m)*cdg102(m)+cdg002(m)*cdg110(m)+2*cdg001(m)*cdg111(m)+cdg000(m)*cdg112(m))));
    }

    gValue(0)=deriv300+deriv120+deriv102;
    gValue(1)=deriv210+deriv030+deriv012;
    gValue(2)=deriv201+deriv021+deriv003;

    hValue(0,0)=deriv400+deriv220+deriv202;
    hValue(1,1)=deriv220+deriv040+deriv022;
    hValue(2,2)=deriv202+deriv022+deriv004;
    hValue(0,1)=deriv310+deriv130+deriv112;
    hValue(0,2)=deriv301+deriv121+deriv103;
    hValue(1,2)=deriv211+deriv031+deriv013;
    hValue(1,0)=hValue(0,1);
    hValue(2,0)=hValue(0,2);
    hValue(2,1)=hValue(1,2);

    value(0,0) = gValue(0);
    value(1,0) = gValue(1);
    value(2,0) = gValue(2);
    value(0,1) = hValue(0,0);
    value(1,1) = hValue(1,0);
    value(2,1) = hValue(2,0);
    value(0,2) = hValue(0,1);
    value(1,2) = hValue(1,1);
    value(2,2) = hValue(2,1);
    value(0,3) = hValue(0,2);
    value(1,3) = hValue(1,2);
    value(2,3) = hValue(2,2);

    return value;

  }
  
  const qreal QTAIMWavefunctionEvaluator::kineticEnergyDensityG(Matrix<qreal,3,1> xyz)
  {

    qreal value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);

        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal b0 = exp(b0arg);

        qreal bx1= -2*alpha(p)*xx0;
        qreal by1= -2*alpha(p)*yy0;
        qreal bz1= -2*alpha(p)*zz0;

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
        }

      }
    }

    value=zero;
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      value += (0.5)*(occno(m)*(pow(cdg100(m),2)+pow(cdg010(m),2)+pow(cdg001(m),2)));
    }

    return value;

  }

  const qreal QTAIMWavefunctionEvaluator::kineticEnergyDensityK( const Matrix<qreal,3,1> xyz )
  {

    qreal value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg200.setZero();
    cdg020.setZero();
    cdg002.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);
        qint64 aax2=xamom(p)*(xamom(p)-1);
        qint64 aay2=yamom(p)*(yamom(p)-1);
        qint64 aaz2=zamom(p)*(zamom(p)-1);

        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*pow(xx0,xamom(p)-2);
        }

        if     ( yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*pow(yy0,yamom(p)-2);
        }

        if     ( zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*pow(zz0,zamom(p)-2);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*alpha(p)*xx0;
        qreal by1 = -2*alpha(p)*yy0;
        qreal bz1 = -2*alpha(p)*zz0;
        qreal bx2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(xx0,2));
        qreal by2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(yy0,2));
        qreal bz2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(zz0,2));

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg200(m) += coef(m,p) * dg200;
          cdg020(m) += coef(m,p) * dg020;
          cdg002(m) += coef(m,p) * dg002;
        }

      }
    }

    value=0.0;
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      value += (0.25)*(occno(m)*(2*cdg000(m)*(cdg200(m)+cdg020(m)+cdg002(m))));
    }

    return value;

  }

  const Matrix<qreal,3,3> QTAIMWavefunctionEvaluator::quantumStressTensor( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,3> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    cdg000.setZero();
    cdg100.setZero();
    cdg010.setZero();
    cdg001.setZero();
    cdg200.setZero();
    cdg020.setZero();
    cdg002.setZero();
    cdg110.setZero();
    cdg101.setZero();
    cdg011.setZero();
    for( qint64 p=0 ; p < nprim ; ++p )
    {
      qreal xx0 = xyz(0) - X0(p);
      qreal yy0 = xyz(1) - Y0(p);
      qreal zz0 = xyz(2) - Z0(p);

      qreal b0arg = -alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=xamom(p);
        qint64 aay1=yamom(p);
        qint64 aaz1=zamom(p);
        qint64 aax2=xamom(p)*(xamom(p)-1);
        qint64 aay2=yamom(p)*(yamom(p)-1);
        qint64 aaz2=zamom(p)*(zamom(p)-1);

        qreal ax0 = aax0*pow( xx0, xamom(p) );
        qreal ay0 = aay0*pow( yy0, yamom(p) );
        qreal az0 = aaz0*pow( zz0, zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*pow(xx0,xamom(p)-1);
        }

        if     ( yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*pow(yy0,yamom(p)-1);
        }

        if     ( zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*pow(zz0,zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*pow(xx0,xamom(p)-2);
        }

        if     ( yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*pow(yy0,yamom(p)-2);
        }

        if     ( zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*pow(zz0,zamom(p)-2);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*alpha(p)*xx0;
        qreal by1 = -2*alpha(p)*yy0;
        qreal bz1 = -2*alpha(p)*zz0;
        qreal bx2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(xx0,2));
        qreal by2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(yy0,2));
        qreal bz2 = -2*alpha(p) + 4*(pow(alpha(p),2) * pow(zz0,2));

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);
        qreal dg110 = az0*b0*(ax1+ax0*bx1)*(ay1+ay0*by1);
        qreal dg101 = ay0*b0*(ax1+ax0*bx1)*(az1+az0*bz1);
        qreal dg011 = ax0*b0*(ay1+ay0*by1)*(az1+az0*bz1);

        for( qint64 m=0 ; m < nmo ; ++m )
        {
          cdg000(m) += coef(m,p) * dg000;
          cdg100(m) += coef(m,p) * dg100;
          cdg010(m) += coef(m,p) * dg010;
          cdg001(m) += coef(m,p) * dg001;
          cdg200(m) += coef(m,p) * dg200;
          cdg020(m) += coef(m,p) * dg020;
          cdg002(m) += coef(m,p) * dg002;
          cdg110(m) += coef(m,p) * dg110;
          cdg101(m) += coef(m,p) * dg101;
          cdg011(m) += coef(m,p) * dg011;
        }

      }
    }

    value.setZero();
    for( qint64 m=0 ; m < nmo ; ++m )
    {
      value(0,0)+=(occno(m)*(2*cdg000(m)*cdg200(m)-2*pow(cdg100(m),2)));
      value(0,1)+=(occno(m)*(2*cdg000(m)*cdg110(m)-2*cdg100(m)*cdg010(m)));
      value(0,2)+=(occno(m)*(2*cdg000(m)*cdg101(m)-2*cdg100(m)*cdg001(m)));
      value(1,1)+=(occno(m)*(2*cdg000(m)*cdg020(m)-2*pow(cdg010(m),2)));
      value(1,2)+=(occno(m)*(2*cdg000(m)*cdg011(m)-2*cdg010(m)*cdg001(m)));
      value(2,2)+=(occno(m)*(2*cdg000(m)*cdg002(m)-2*pow(cdg001(m),2) ));
    }
    value(1,0)=value(0,1);
    value(2,0)=value(0,2);
    value(2,1)=value(1,2);

    return 0.25*value;

  }

} // namespace Avogadro
