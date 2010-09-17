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

    aax0.resize(nprim);
    aay0.resize(nprim);
    aaz0.resize(nprim);
    aax1.resize(nprim);
    aay1.resize(nprim);
    aaz1.resize(nprim);
    aax2.resize(nprim);
    aay2.resize(nprim);
    aaz2.resize(nprim);

    ax0.resize(nprim);
    ay0.resize(nprim);
    az0.resize(nprim);
    ax1.resize(nprim);
    ay1.resize(nprim);
    az1.resize(nprim);
    ax2.resize(nprim);
    ay2.resize(nprim);
    az2.resize(nprim);

    b0.resize(nprim);
    b0arg.resize(nprim);

    bx0.resize(nprim);
    by0.resize(nprim);
    bz0.resize(nprim);
    bx1.resize(nprim);
    by1.resize(nprim);
    bz1.resize(nprim);
    bx2.resize(nprim);
    by2.resize(nprim);
    bz2.resize(nprim);

    dg000.resize(nprim);
    dg100.resize(nprim);
    dg010.resize(nprim);
    dg001.resize(nprim);
    dg200.resize(nprim);
    dg110.resize(nprim);
    dg101.resize(nprim);
    dg020.resize(nprim);
    dg011.resize(nprim);
    dg002.resize(nprim);

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

} // namespace Avogadro
