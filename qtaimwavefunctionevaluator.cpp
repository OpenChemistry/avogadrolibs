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
  QTAIMWavefunctionEvaluator::QTAIMWavefunctionEvaluator(QTAIMWavefunction &wfn)
  {

    m_nmo=wfn.numberOfMolecularOrbitals();
    m_nprim=wfn.numberOfGaussianPrimitives();
    m_nnuc=wfn.numberOfNuclei();

    m_nucxcoord=Map<Matrix<qreal,Dynamic,1> >(wfn.xNuclearCoordinates(),m_nnuc);
    m_nucycoord=Map<Matrix<qreal,Dynamic,1> >(wfn.yNuclearCoordinates(),m_nnuc);
    m_nuczcoord=Map<Matrix<qreal,Dynamic,1> >(wfn.zNuclearCoordinates(),m_nnuc);
    m_nucz=Map<Matrix<qint64,Dynamic,1> >(wfn.nuclearCharges(),m_nnuc);
    m_X0=Map<Matrix<qreal,Dynamic,1> >(wfn.xGaussianPrimitiveCenterCoordinates(),m_nprim,1);
    m_Y0=Map<Matrix<qreal,Dynamic,1> >(wfn.yGaussianPrimitiveCenterCoordinates(),m_nprim,1);
    m_Z0=Map<Matrix<qreal,Dynamic,1> >(wfn.zGaussianPrimitiveCenterCoordinates(),m_nprim,1);
    m_xamom=Map<Matrix<qint64,Dynamic,1> >(wfn.xGaussianPrimitiveAngularMomenta(),m_nprim,1);
    m_yamom=Map<Matrix<qint64,Dynamic,1> >(wfn.yGaussianPrimitiveAngularMomenta(),m_nprim,1);
    m_zamom=Map<Matrix<qint64,Dynamic,1> >(wfn.zGaussianPrimitiveAngularMomenta(),m_nprim,1);
    m_alpha=Map<Matrix<qreal,Dynamic,1> >(wfn.gaussianPrimitiveExponentCoefficients(),m_nprim,1);
    // TODO Implement screening for unoccupied molecular orbitals.
    m_occno=Map<Matrix<qreal,Dynamic,1> >(wfn.molecularOrbitalOccupationNumbers(),m_nmo,1);
    m_orbe=Map<Matrix<qreal,Dynamic,1> >(wfn.molecularOrbitalEigenvalues(),m_nmo,1);
    m_coef=Map<Matrix<qreal,Dynamic,Dynamic,RowMajor> >(wfn.molecularOrbitalCoefficients(),m_nmo,m_nprim);
    m_totalEnergy=wfn.totalEnergy();
    m_virialRatio=wfn.virialRatio();

    m_cutoff=log(1.e-15);

    m_cdg000.resize(m_nmo);
    m_cdg100.resize(m_nmo);
    m_cdg010.resize(m_nmo);
    m_cdg001.resize(m_nmo);
    m_cdg200.resize(m_nmo);
    m_cdg110.resize(m_nmo);
    m_cdg101.resize(m_nmo);
    m_cdg020.resize(m_nmo);
    m_cdg011.resize(m_nmo);
    m_cdg002.resize(m_nmo);
    m_cdg300.resize(m_nmo);
    m_cdg120.resize(m_nmo);
    m_cdg102.resize(m_nmo);
    m_cdg210.resize(m_nmo);
    m_cdg030.resize(m_nmo);
    m_cdg012.resize(m_nmo);
    m_cdg201.resize(m_nmo);
    m_cdg021.resize(m_nmo);
    m_cdg003.resize(m_nmo);
    m_cdg111.resize(m_nmo);
    m_cdg400.resize(m_nmo);
    m_cdg220.resize(m_nmo);
    m_cdg202.resize(m_nmo);
    m_cdg310.resize(m_nmo);
    m_cdg130.resize(m_nmo);
    m_cdg112.resize(m_nmo);
    m_cdg301.resize(m_nmo);
    m_cdg121.resize(m_nmo);
    m_cdg103.resize(m_nmo);
    m_cdg040.resize(m_nmo);
    m_cdg022.resize(m_nmo);
    m_cdg211.resize(m_nmo);
    m_cdg031.resize(m_nmo);
    m_cdg013.resize(m_nmo);
    m_cdg004.resize(m_nmo);
  }

  const qreal QTAIMWavefunctionEvaluator::molecularOrbital( const qint64 mo, const Matrix<qreal,3,1> xyz )
  {

    qreal value=0.0;

    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qreal ax0 = ipow( xx0, m_xamom(p) );
        qreal ay0 = ipow( yy0, m_yamom(p) );
        qreal az0 = ipow( zz0, m_zamom(p) );

        qreal b0 = exp( b0arg );

        qreal dg000 = ax0*ay0*az0*b0;

        value += m_coef(mo,p)*dg000;
      }

    }

    return value;

  }

  const qreal QTAIMWavefunctionEvaluator::electronDensity( const Matrix<qreal,3,1> xyz )
  {

    qreal value;

    m_cdg000.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qreal ax0 = ipow( xx0, m_xamom(p) );
        qreal ay0 = ipow( yy0, m_yamom(p) );
        qreal az0 = ipow( zz0, m_zamom(p) );

        qreal b0 = exp(b0arg);

        qreal dg000 = ax0*ay0*az0*b0;

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
        }

      }
    }

    value=0.0;
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      value += m_occno(m)*ipow(m_cdg000(m),2);
    }

    return value;

  }

  const Matrix<qreal,3,1> QTAIMWavefunctionEvaluator::gradientOfElectronDensity(Matrix<qreal,3,1> xyz)
  {

    Matrix<qreal,3,1> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal b0 = exp(b0arg);

        qreal bx1= -2*m_alpha(p)*xx0;
        qreal by1= -2*m_alpha(p)*yy0;
        qreal bz1= -2*m_alpha(p)*zz0;

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
        }

      }
    }

    value.setZero();
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      value(0) += m_occno(m)*m_cdg100(m)*m_cdg000(m);
      value(1) += m_occno(m)*m_cdg010(m)*m_cdg000(m);
      value(2) += m_occno(m)*m_cdg001(m)*m_cdg000(m);
    }

    return value;

  }

  const Matrix<qreal,3,3> QTAIMWavefunctionEvaluator::hessianOfElectronDensity( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,3> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    m_cdg200.setZero();
    m_cdg020.setZero();
    m_cdg002.setZero();
    m_cdg110.setZero();
    m_cdg101.setZero();
    m_cdg011.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);
        qint64 aax2=m_xamom(p)*(m_xamom(p)-1);
        qint64 aay2=m_yamom(p)*(m_yamom(p)-1);
        qint64 aaz2=m_zamom(p)*(m_zamom(p)-1);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( m_xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( m_xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*ipow(xx0,m_xamom(p)-2);
        }

        if     ( m_yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( m_yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*ipow(yy0,m_yamom(p)-2);
        }

        if     ( m_zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( m_zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*ipow(zz0,m_zamom(p)-2);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*m_alpha(p)*xx0;
        qreal by1 = -2*m_alpha(p)*yy0;
        qreal bz1 = -2*m_alpha(p)*zz0;
        qreal bx2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(xx0,2));
        qreal by2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(yy0,2));
        qreal bz2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(zz0,2));

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

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
          m_cdg200(m) += m_coef(m,p) * dg200;
          m_cdg020(m) += m_coef(m,p) * dg020;
          m_cdg002(m) += m_coef(m,p) * dg002;
          m_cdg110(m) += m_coef(m,p) * dg110;
          m_cdg101(m) += m_coef(m,p) * dg101;
          m_cdg011(m) += m_coef(m,p) * dg011;
        }

      }
    }

    value.setZero();
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      value(0,0) += 2*m_occno(m)*(ipow(m_cdg100(m),2)+m_cdg000(m)*m_cdg200(m));
      value(1,1) += 2*m_occno(m)*(ipow(m_cdg010(m),2)+m_cdg000(m)*m_cdg020(m));
      value(2,2) += 2*m_occno(m)*(ipow(m_cdg001(m),2)+m_cdg000(m)*m_cdg002(m));
      value(0,1) += 2*m_occno(m)*(m_cdg100(m)*m_cdg010(m)+m_cdg000(m)*m_cdg110(m));
      value(0,2) += 2*m_occno(m)*(m_cdg100(m)*m_cdg001(m)+m_cdg000(m)*m_cdg101(m));
      value(1,2) += 2*m_occno(m)*(m_cdg010(m)*m_cdg001(m)+m_cdg000(m)*m_cdg011(m));
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

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    m_cdg200.setZero();
    m_cdg020.setZero();
    m_cdg002.setZero();
    m_cdg110.setZero();
    m_cdg101.setZero();
    m_cdg011.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);
        qint64 aax2=m_xamom(p)*(m_xamom(p)-1);
        qint64 aay2=m_yamom(p)*(m_yamom(p)-1);
        qint64 aaz2=m_zamom(p)*(m_zamom(p)-1);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( m_xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( m_xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*ipow(xx0,m_xamom(p)-2);
        }

        if     ( m_yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( m_yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*ipow(yy0,m_yamom(p)-2);
        }

        if     ( m_zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( m_zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*ipow(zz0,m_zamom(p)-2);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*m_alpha(p)*xx0;
        qreal by1 = -2*m_alpha(p)*yy0;
        qreal bz1 = -2*m_alpha(p)*zz0;
        qreal bx2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(xx0,2));
        qreal by2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(yy0,2));
        qreal bz2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(zz0,2));

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

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
          m_cdg200(m) += m_coef(m,p) * dg200;
          m_cdg020(m) += m_coef(m,p) * dg020;
          m_cdg002(m) += m_coef(m,p) * dg002;
          m_cdg110(m) += m_coef(m,p) * dg110;
          m_cdg101(m) += m_coef(m,p) * dg101;
          m_cdg011(m) += m_coef(m,p) * dg011;
        }

      }
    }

    gValue.setZero();
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      gValue(0) += m_occno(m)*m_cdg100(m)*m_cdg000(m);
      gValue(1) += m_occno(m)*m_cdg010(m)*m_cdg000(m);
      gValue(2) += m_occno(m)*m_cdg001(m)*m_cdg000(m);
    }

    hValue.setZero();
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      hValue(0,0) += 2*m_occno(m)*(ipow(m_cdg100(m),2)+m_cdg000(m)*m_cdg200(m));
      hValue(1,1) += 2*m_occno(m)*(ipow(m_cdg010(m),2)+m_cdg000(m)*m_cdg020(m));
      hValue(2,2) += 2*m_occno(m)*(ipow(m_cdg001(m),2)+m_cdg000(m)*m_cdg002(m));
      hValue(0,1) += 2*m_occno(m)*(m_cdg100(m)*m_cdg010(m)+m_cdg000(m)*m_cdg110(m));
      hValue(0,2) += 2*m_occno(m)*(m_cdg100(m)*m_cdg001(m)+m_cdg000(m)*m_cdg101(m));
      hValue(1,2) += 2*m_occno(m)*(m_cdg010(m)*m_cdg001(m)+m_cdg000(m)*m_cdg011(m));
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

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    m_cdg200.setZero();
    m_cdg020.setZero();
    m_cdg002.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);
        qint64 aax2=m_xamom(p)*(m_xamom(p)-1);
        qint64 aay2=m_yamom(p)*(m_yamom(p)-1);
        qint64 aaz2=m_zamom(p)*(m_zamom(p)-1);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( m_xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( m_xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*ipow(xx0,m_xamom(p)-2);
        }

        if     ( m_yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( m_yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*ipow(yy0,m_yamom(p)-2);
        }

        if     ( m_zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( m_zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*ipow(zz0,m_zamom(p)-2);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*m_alpha(p)*xx0;
        qreal by1 = -2*m_alpha(p)*yy0;
        qreal bz1 = -2*m_alpha(p)*zz0;
        qreal bx2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(xx0,2));
        qreal by2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(yy0,2));
        qreal bz2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(zz0,2));

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
          m_cdg200(m) += m_coef(m,p) * dg200;
          m_cdg020(m) += m_coef(m,p) * dg020;
          m_cdg002(m) += m_coef(m,p) * dg002;
        }

      }
    }

    value=0.0;
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      value +=    2*m_occno(m)*(ipow(m_cdg100(m),2)+m_cdg000(m)*m_cdg200(m))
                 +2*m_occno(m)*(ipow(m_cdg010(m),2)+m_cdg000(m)*m_cdg020(m))
                 +2*m_occno(m)*(ipow(m_cdg001(m),2)+m_cdg000(m)*m_cdg002(m));
    }

    return value;

  }


  const Matrix<qreal,3,1> QTAIMWavefunctionEvaluator::gradientOfElectronDensityLaplacian( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,1> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    m_cdg200.setZero();
    m_cdg020.setZero();
    m_cdg002.setZero();
    m_cdg110.setZero();
    m_cdg101.setZero();
    m_cdg011.setZero();
    m_cdg300.setZero();
    m_cdg120.setZero();
    m_cdg102.setZero();
    m_cdg210.setZero();
    m_cdg030.setZero();
    m_cdg012.setZero();
    m_cdg201.setZero();
    m_cdg021.setZero();
    m_cdg003.setZero();
    // m_cdg111.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);
        qint64 aax2=m_xamom(p)*(m_xamom(p)-1);
        qint64 aay2=m_yamom(p)*(m_yamom(p)-1);
        qint64 aaz2=m_zamom(p)*(m_zamom(p)-1);
        qint64 aax3=m_xamom(p)*(m_xamom(p)-1)*(m_xamom(p)-2);
        qint64 aay3=m_yamom(p)*(m_yamom(p)-1)*(m_yamom(p)-2);
        qint64 aaz3=m_zamom(p)*(m_zamom(p)-1)*(m_zamom(p)-2);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( m_xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( m_xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*ipow(xx0,m_xamom(p)-2);
        }

        if     ( m_yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( m_yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*ipow(yy0,m_yamom(p)-2);
        }

        if     ( m_zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( m_zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*ipow(zz0,m_zamom(p)-2);
        }

        qreal ax3;
        qreal ay3;
        qreal az3;
        if     ( m_xamom(p) <  3 )
        {
          ax3=zero;
        }
        else if( m_xamom(p) == 3 )
        {
          ax3=one;
        }
        else
        {
          ax3=aax3*ipow(xx0,m_xamom(p)-3);
        }

        if     ( m_yamom(p) <  3 )
        {
          ay3=zero;
        }
        else if( m_yamom(p) == 3 )
        {
          ay3=one;
        }
        else
        {
          ay3=aay3*ipow(yy0,m_yamom(p)-3);
        }

        if     ( m_zamom(p) <  3 )
        {
          az3=zero;
        }
        else if( m_zamom(p) == 3 )
        {
          az3=one;
        }
        else
        {
          az3=aaz3*ipow(zz0,m_zamom(p)-3);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*m_alpha(p)*xx0;
        qreal by1 = -2*m_alpha(p)*yy0;
        qreal bz1 = -2*m_alpha(p)*zz0;
        qreal bx2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(xx0,2));
        qreal by2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(yy0,2));
        qreal bz2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(zz0,2));
        qreal bx3 = (12*ipow(m_alpha(p),2)*xx0)-(8*ipow(m_alpha(p),3) * ipow(xx0,3));
        qreal by3 = (12*ipow(m_alpha(p),2)*yy0)-(8*ipow(m_alpha(p),3) * ipow(yy0,3));
        qreal bz3 = (12*ipow(m_alpha(p),2)*zz0)-(8*ipow(m_alpha(p),3) * ipow(zz0,3));

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

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
          m_cdg200(m) += m_coef(m,p) * dg200;
          m_cdg020(m) += m_coef(m,p) * dg020;
          m_cdg002(m) += m_coef(m,p) * dg002;
          m_cdg110(m) += m_coef(m,p) * dg110;
          m_cdg101(m) += m_coef(m,p) * dg101;
          m_cdg011(m) += m_coef(m,p) * dg011;
          m_cdg300(m) += m_coef(m,p) * dg300;
          m_cdg030(m) += m_coef(m,p) * dg030;
          m_cdg003(m) += m_coef(m,p) * dg003;
          m_cdg210(m) += m_coef(m,p) * dg210;
          m_cdg201(m) += m_coef(m,p) * dg201;
          m_cdg120(m) += m_coef(m,p) * dg120;
          m_cdg021(m) += m_coef(m,p) * dg021;
          m_cdg102(m) += m_coef(m,p) * dg102;
          m_cdg012(m) += m_coef(m,p) * dg012;
          // m_cdg111(m) += m_coef(m,p) * dg111;
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
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      deriv300+=(m_occno(m)*( 6*m_cdg100(m)*m_cdg200(m)+2*m_cdg000(m)*m_cdg300(m) ));
      deriv030+=(m_occno(m)*( 6*m_cdg010(m)*m_cdg020(m)+2*m_cdg000(m)*m_cdg030(m) ));
      deriv003+=(m_occno(m)*( 6*m_cdg001(m)*m_cdg002(m)+2*m_cdg000(m)*m_cdg003(m) ));
      deriv210+=(m_occno(m)*( 2*(2*m_cdg100(m)*m_cdg110(m)+m_cdg010(m)*m_cdg200(m)+m_cdg000(m)*m_cdg210(m)) ));
      deriv201+=(m_occno(m)*( 2*(2*m_cdg100(m)*m_cdg101(m)+m_cdg001(m)*m_cdg200(m)+m_cdg000(m)*m_cdg201(m)) ));
      deriv120+=(m_occno(m)*( 2*(m_cdg020(m)*m_cdg100(m)+2*m_cdg010(m)*m_cdg110(m)+m_cdg000(m)*m_cdg120(m)) ));
      deriv021+=(m_occno(m)*( 2*(2*m_cdg010(m)*m_cdg011(m)+m_cdg001(m)*m_cdg020(m)+m_cdg000(m)*m_cdg021(m)) ));
      deriv102+=(m_occno(m)*( 2*(m_cdg002(m)*m_cdg100(m)+2*m_cdg001(m)*m_cdg101(m)+m_cdg000(m)*m_cdg102(m)) ));
      deriv012+=(m_occno(m)*( 2*(m_cdg002(m)*m_cdg010(m)+2*m_cdg001(m)*m_cdg011(m)+m_cdg000(m)*m_cdg012(m)) ));
      // deriv111+=(m_occno(m)*( 2*(m_cdg011(m)*m_cdg100(m)+m_cdg010(m)*m_cdg101(m)+m_cdg001(m)*m_cdg110(m)+m_cdg000(m)*m_cdg111(m)) ));
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

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    m_cdg200.setZero();
    m_cdg020.setZero();
    m_cdg002.setZero();
    m_cdg110.setZero();
    m_cdg101.setZero();
    m_cdg011.setZero();
    m_cdg300.setZero();
    m_cdg120.setZero();
    m_cdg102.setZero();
    m_cdg210.setZero();
    m_cdg030.setZero();
    m_cdg012.setZero();
    m_cdg201.setZero();
    m_cdg021.setZero();
    m_cdg003.setZero();
    m_cdg111.setZero();
    m_cdg400.setZero();
    m_cdg040.setZero();
    m_cdg004.setZero();
    m_cdg310.setZero();
    m_cdg301.setZero();
    m_cdg130.setZero();
    m_cdg031.setZero();
    m_cdg103.setZero();
    m_cdg013.setZero();
    m_cdg220.setZero();
    m_cdg202.setZero();
    m_cdg022.setZero();
    m_cdg211.setZero();
    m_cdg121.setZero();
    m_cdg112.setZero();

    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);
        qint64 aax2=m_xamom(p)*(m_xamom(p)-1);
        qint64 aay2=m_yamom(p)*(m_yamom(p)-1);
        qint64 aaz2=m_zamom(p)*(m_zamom(p)-1);
        qint64 aax3=m_xamom(p)*(m_xamom(p)-1)*(m_xamom(p)-2);
        qint64 aay3=m_yamom(p)*(m_yamom(p)-1)*(m_yamom(p)-2);
        qint64 aaz3=m_zamom(p)*(m_zamom(p)-1)*(m_zamom(p)-2);
        qint64 aax4=m_xamom(p)*(m_xamom(p)-1)*(m_xamom(p)-2)*(m_xamom(p)-3);
        qint64 aay4=m_yamom(p)*(m_yamom(p)-1)*(m_yamom(p)-2)*(m_xamom(p)-3);
        qint64 aaz4=m_zamom(p)*(m_zamom(p)-1)*(m_zamom(p)-2)*(m_xamom(p)-3);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( m_xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( m_xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*ipow(xx0,m_xamom(p)-2);
        }

        if     ( m_yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( m_yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*ipow(yy0,m_yamom(p)-2);
        }

        if     ( m_zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( m_zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*ipow(zz0,m_zamom(p)-2);
        }

        qreal ax3;
        qreal ay3;
        qreal az3;
        if     ( m_xamom(p) <  3 )
        {
          ax3=zero;
        }
        else if( m_xamom(p) == 3 )
        {
          ax3=one;
        }
        else
        {
          ax3=aax3*ipow(xx0,m_xamom(p)-3);
        }

        if     ( m_yamom(p) <  3 )
        {
          ay3=zero;
        }
        else if( m_yamom(p) == 3 )
        {
          ay3=one;
        }
        else
        {
          ay3=aay3*ipow(yy0,m_yamom(p)-3);
        }

        if     ( m_zamom(p) <  3 )
        {
          az3=zero;
        }
        else if( m_zamom(p) == 3 )
        {
          az3=one;
        }
        else
        {
          az3=aaz3*ipow(zz0,m_zamom(p)-3);
        }

        qreal ax4;
        qreal ay4;
        qreal az4;
        if     ( m_xamom(p) <  4 )
        {
          ax4=zero;
        }
        else if( m_xamom(p) == 4 )
        {
          ax4=one;
        }
        else
        {
          ax4=aax4*ipow(xx0,m_xamom(p)-4);
        }

        if     ( m_yamom(p) <  4 )
        {
          ay4=zero;
        }
        else if( m_yamom(p) == 4 )
        {
          ay4=one;
        }
        else
        {
          ay4=aay4*ipow(yy0,m_yamom(p)-4);
        }

        if     ( m_zamom(p) <  4 )
        {
          az4=zero;
        }
        else if( m_zamom(p) == 4 )
        {
          az4=one;
        }
        else
        {
          az4=aaz4*ipow(zz0,m_zamom(p)-4);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*m_alpha(p)*xx0;
        qreal by1 = -2*m_alpha(p)*yy0;
        qreal bz1 = -2*m_alpha(p)*zz0;
        qreal bx2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(xx0,2));
        qreal by2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(yy0,2));
        qreal bz2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(zz0,2));
        qreal bx3 = (12*ipow(m_alpha(p),2)*xx0)-(8*ipow(m_alpha(p),3) * ipow(xx0,3));
        qreal by3 = (12*ipow(m_alpha(p),2)*yy0)-(8*ipow(m_alpha(p),3) * ipow(yy0,3));
        qreal bz3 = (12*ipow(m_alpha(p),2)*zz0)-(8*ipow(m_alpha(p),3) * ipow(zz0,3));
        qreal bx4 = (12*ipow(m_alpha(p),2))-(48*ipow(m_alpha(p),3) * ipow(xx0,2))+(16*ipow(m_alpha(p),4) * ipow(xx0,4));
        qreal by4 = (12*ipow(m_alpha(p),2))-(48*ipow(m_alpha(p),3) * ipow(yy0,2))+(16*ipow(m_alpha(p),4) * ipow(yy0,4));
        qreal bz4 = (12*ipow(m_alpha(p),2))-(48*ipow(m_alpha(p),3) * ipow(zz0,2))+(16*ipow(m_alpha(p),4) * ipow(zz0,4));

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

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
          m_cdg200(m) += m_coef(m,p) * dg200;
          m_cdg020(m) += m_coef(m,p) * dg020;
          m_cdg002(m) += m_coef(m,p) * dg002;
          m_cdg110(m) += m_coef(m,p) * dg110;
          m_cdg101(m) += m_coef(m,p) * dg101;
          m_cdg011(m) += m_coef(m,p) * dg011;
          m_cdg300(m) += m_coef(m,p) * dg300;
          m_cdg030(m) += m_coef(m,p) * dg030;
          m_cdg003(m) += m_coef(m,p) * dg003;
          m_cdg210(m) += m_coef(m,p) * dg210;
          m_cdg201(m) += m_coef(m,p) * dg201;
          m_cdg120(m) += m_coef(m,p) * dg120;
          m_cdg021(m) += m_coef(m,p) * dg021;
          m_cdg102(m) += m_coef(m,p) * dg102;
          m_cdg012(m) += m_coef(m,p) * dg012;
          m_cdg111(m) += m_coef(m,p) * dg111;
          m_cdg400(m) += m_coef(m,p) * dg400;
          m_cdg040(m) += m_coef(m,p) * dg040;
          m_cdg004(m) += m_coef(m,p) * dg004;
          m_cdg310(m) += m_coef(m,p) * dg310;
          m_cdg301(m) += m_coef(m,p) * dg301;
          m_cdg130(m) += m_coef(m,p) * dg130;
          m_cdg031(m) += m_coef(m,p) * dg031;
          m_cdg103(m) += m_coef(m,p) * dg103;
          m_cdg013(m) += m_coef(m,p) * dg013;
          m_cdg220(m) += m_coef(m,p) * dg220;
          m_cdg202(m) += m_coef(m,p) * dg202;
          m_cdg022(m) += m_coef(m,p) * dg022;
          m_cdg211(m) += m_coef(m,p) * dg211;
          m_cdg121(m) += m_coef(m,p) * dg121;
          m_cdg112(m) += m_coef(m,p) * dg112;
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
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      deriv400+=(m_occno(m)*(6*ipow(m_cdg200(m),2)+8*m_cdg100(m)*m_cdg300(m)+2*m_cdg000(m)*m_cdg400(m)));
      deriv040+=(m_occno(m)*(6*ipow(m_cdg020(m),2)+8*m_cdg010(m)*m_cdg030(m)+2*m_cdg000(m)*m_cdg040(m)));
      deriv004+=(m_occno(m)*(6*ipow(m_cdg002(m),2)+8*m_cdg001(m)*m_cdg003(m)+2*m_cdg000(m)*m_cdg004(m)));
      deriv310+=(m_occno(m)*(2*(3*m_cdg110(m)*m_cdg200(m)+3*m_cdg100(m)*m_cdg210(m)+m_cdg010(m)*m_cdg300(m)+m_cdg000(m)*m_cdg310(m))));
      deriv301+=(m_occno(m)*(2*(3*m_cdg101(m)*m_cdg200(m)+3*m_cdg100(m)*m_cdg201(m)+m_cdg001(m)*m_cdg300(m)+m_cdg000(m)*m_cdg301(m))));
      deriv130+=(m_occno(m)*(2*(m_cdg030(m)*m_cdg100(m)+3*m_cdg020(m)*m_cdg110(m)+3*m_cdg010(m)*m_cdg120(m)+m_cdg000(m)*m_cdg130(m))));
      deriv031+=(m_occno(m)*(2*(3*m_cdg011(m)*m_cdg020(m)+3*m_cdg010(m)*m_cdg021(m)+m_cdg001(m)*m_cdg030(m)+m_cdg000(m)*m_cdg031(m))));
      deriv103+=(m_occno(m)*(2*(m_cdg003(m)*m_cdg100(m)+3*m_cdg002(m)*m_cdg101(m)+3*m_cdg001(m)*m_cdg102(m)+m_cdg000(m)*m_cdg103(m))));
      deriv013+=(m_occno(m)*(2*(m_cdg003(m)*m_cdg010(m)+3*m_cdg002(m)*m_cdg011(m)+3*m_cdg001(m)*m_cdg012(m)+m_cdg000(m)*m_cdg013(m))));
      deriv220+=(m_occno(m)*(2*(2*ipow(m_cdg110(m),2)+2*m_cdg100(m)*m_cdg120(m)+m_cdg020(m)*m_cdg200(m)+2*m_cdg010(m)*m_cdg210(m)+m_cdg000(m)*m_cdg220(m))));
      deriv202+=(m_occno(m)*(2*(2*ipow(m_cdg101(m),2)+2*m_cdg100(m)*m_cdg102(m)+m_cdg002(m)*m_cdg200(m)+2*m_cdg001(m)*m_cdg201(m)+m_cdg000(m)*m_cdg202(m))));
      deriv022+=(m_occno(m)*(2*(2*ipow(m_cdg011(m),2)+2*m_cdg010(m)*m_cdg012(m)+m_cdg002(m)*m_cdg020(m)+2*m_cdg001(m)*m_cdg021(m)+m_cdg000(m)*m_cdg022(m))));
      deriv211+=(m_occno(m)*(2*(2*m_cdg101(m)*m_cdg110(m)+2*m_cdg100(m)*m_cdg111(m)+m_cdg011(m)*m_cdg200(m)+m_cdg010(m)*m_cdg201(m)+m_cdg001(m)*m_cdg210(m)+m_cdg000(m)*m_cdg211(m))));
      deriv121+=(m_occno(m)*(2*(m_cdg021(m)*m_cdg100(m)+m_cdg020(m)*m_cdg101(m)+2*m_cdg011(m)*m_cdg110(m)+2*m_cdg010(m)*m_cdg111(m)+m_cdg001(m)*m_cdg120(m)+m_cdg000(m)*m_cdg121(m))));
      deriv112+=(m_occno(m)*(2*(m_cdg012(m)*m_cdg100(m)+2*m_cdg011(m)*m_cdg101(m)+m_cdg010(m)*m_cdg102(m)+m_cdg002(m)*m_cdg110(m)+2*m_cdg001(m)*m_cdg111(m)+m_cdg000(m)*m_cdg112(m))));
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

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    m_cdg200.setZero();
    m_cdg020.setZero();
    m_cdg002.setZero();
    m_cdg110.setZero();
    m_cdg101.setZero();
    m_cdg011.setZero();
    m_cdg300.setZero();
    m_cdg120.setZero();
    m_cdg102.setZero();
    m_cdg210.setZero();
    m_cdg030.setZero();
    m_cdg012.setZero();
    m_cdg201.setZero();
    m_cdg021.setZero();
    m_cdg003.setZero();
    m_cdg111.setZero();
    m_cdg400.setZero();
    m_cdg040.setZero();
    m_cdg004.setZero();
    m_cdg310.setZero();
    m_cdg301.setZero();
    m_cdg130.setZero();
    m_cdg031.setZero();
    m_cdg103.setZero();
    m_cdg013.setZero();
    m_cdg220.setZero();
    m_cdg202.setZero();
    m_cdg022.setZero();
    m_cdg211.setZero();
    m_cdg121.setZero();
    m_cdg112.setZero();

    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);
        qint64 aax2=m_xamom(p)*(m_xamom(p)-1);
        qint64 aay2=m_yamom(p)*(m_yamom(p)-1);
        qint64 aaz2=m_zamom(p)*(m_zamom(p)-1);
        qint64 aax3=m_xamom(p)*(m_xamom(p)-1)*(m_xamom(p)-2);
        qint64 aay3=m_yamom(p)*(m_yamom(p)-1)*(m_yamom(p)-2);
        qint64 aaz3=m_zamom(p)*(m_zamom(p)-1)*(m_zamom(p)-2);
        qint64 aax4=m_xamom(p)*(m_xamom(p)-1)*(m_xamom(p)-2)*(m_xamom(p)-3);
        qint64 aay4=m_yamom(p)*(m_yamom(p)-1)*(m_yamom(p)-2)*(m_xamom(p)-3);
        qint64 aaz4=m_zamom(p)*(m_zamom(p)-1)*(m_zamom(p)-2)*(m_xamom(p)-3);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( m_xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( m_xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*ipow(xx0,m_xamom(p)-2);
        }

        if     ( m_yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( m_yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*ipow(yy0,m_yamom(p)-2);
        }

        if     ( m_zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( m_zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*ipow(zz0,m_zamom(p)-2);
        }

        qreal ax3;
        qreal ay3;
        qreal az3;
        if     ( m_xamom(p) <  3 )
        {
          ax3=zero;
        }
        else if( m_xamom(p) == 3 )
        {
          ax3=one;
        }
        else
        {
          ax3=aax3*ipow(xx0,m_xamom(p)-3);
        }

        if     ( m_yamom(p) <  3 )
        {
          ay3=zero;
        }
        else if( m_yamom(p) == 3 )
        {
          ay3=one;
        }
        else
        {
          ay3=aay3*ipow(yy0,m_yamom(p)-3);
        }

        if     ( m_zamom(p) <  3 )
        {
          az3=zero;
        }
        else if( m_zamom(p) == 3 )
        {
          az3=one;
        }
        else
        {
          az3=aaz3*ipow(zz0,m_zamom(p)-3);
        }

        qreal ax4;
        qreal ay4;
        qreal az4;
        if     ( m_xamom(p) <  4 )
        {
          ax4=zero;
        }
        else if( m_xamom(p) == 4 )
        {
          ax4=one;
        }
        else
        {
          ax4=aax4*ipow(xx0,m_xamom(p)-4);
        }

        if     ( m_yamom(p) <  4 )
        {
          ay4=zero;
        }
        else if( m_yamom(p) == 4 )
        {
          ay4=one;
        }
        else
        {
          ay4=aay4*ipow(yy0,m_yamom(p)-4);
        }

        if     ( m_zamom(p) <  4 )
        {
          az4=zero;
        }
        else if( m_zamom(p) == 4 )
        {
          az4=one;
        }
        else
        {
          az4=aaz4*ipow(zz0,m_zamom(p)-4);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*m_alpha(p)*xx0;
        qreal by1 = -2*m_alpha(p)*yy0;
        qreal bz1 = -2*m_alpha(p)*zz0;
        qreal bx2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(xx0,2));
        qreal by2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(yy0,2));
        qreal bz2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(zz0,2));
        qreal bx3 = (12*ipow(m_alpha(p),2)*xx0)-(8*ipow(m_alpha(p),3) * ipow(xx0,3));
        qreal by3 = (12*ipow(m_alpha(p),2)*yy0)-(8*ipow(m_alpha(p),3) * ipow(yy0,3));
        qreal bz3 = (12*ipow(m_alpha(p),2)*zz0)-(8*ipow(m_alpha(p),3) * ipow(zz0,3));
        qreal bx4 = (12*ipow(m_alpha(p),2))-(48*ipow(m_alpha(p),3) * ipow(xx0,2))+(16*ipow(m_alpha(p),4) * ipow(xx0,4));
        qreal by4 = (12*ipow(m_alpha(p),2))-(48*ipow(m_alpha(p),3) * ipow(yy0,2))+(16*ipow(m_alpha(p),4) * ipow(yy0,4));
        qreal bz4 = (12*ipow(m_alpha(p),2))-(48*ipow(m_alpha(p),3) * ipow(zz0,2))+(16*ipow(m_alpha(p),4) * ipow(zz0,4));

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

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
          m_cdg200(m) += m_coef(m,p) * dg200;
          m_cdg020(m) += m_coef(m,p) * dg020;
          m_cdg002(m) += m_coef(m,p) * dg002;
          m_cdg110(m) += m_coef(m,p) * dg110;
          m_cdg101(m) += m_coef(m,p) * dg101;
          m_cdg011(m) += m_coef(m,p) * dg011;
          m_cdg300(m) += m_coef(m,p) * dg300;
          m_cdg030(m) += m_coef(m,p) * dg030;
          m_cdg003(m) += m_coef(m,p) * dg003;
          m_cdg210(m) += m_coef(m,p) * dg210;
          m_cdg201(m) += m_coef(m,p) * dg201;
          m_cdg120(m) += m_coef(m,p) * dg120;
          m_cdg021(m) += m_coef(m,p) * dg021;
          m_cdg102(m) += m_coef(m,p) * dg102;
          m_cdg012(m) += m_coef(m,p) * dg012;
          m_cdg111(m) += m_coef(m,p) * dg111;
          m_cdg400(m) += m_coef(m,p) * dg400;
          m_cdg040(m) += m_coef(m,p) * dg040;
          m_cdg004(m) += m_coef(m,p) * dg004;
          m_cdg310(m) += m_coef(m,p) * dg310;
          m_cdg301(m) += m_coef(m,p) * dg301;
          m_cdg130(m) += m_coef(m,p) * dg130;
          m_cdg031(m) += m_coef(m,p) * dg031;
          m_cdg103(m) += m_coef(m,p) * dg103;
          m_cdg013(m) += m_coef(m,p) * dg013;
          m_cdg220(m) += m_coef(m,p) * dg220;
          m_cdg202(m) += m_coef(m,p) * dg202;
          m_cdg022(m) += m_coef(m,p) * dg022;
          m_cdg211(m) += m_coef(m,p) * dg211;
          m_cdg121(m) += m_coef(m,p) * dg121;
          m_cdg112(m) += m_coef(m,p) * dg112;
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
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      deriv300+=(m_occno(m)*( 6*m_cdg100(m)*m_cdg200(m)+2*m_cdg000(m)*m_cdg300(m) ));
      deriv030+=(m_occno(m)*( 6*m_cdg010(m)*m_cdg020(m)+2*m_cdg000(m)*m_cdg030(m) ));
      deriv003+=(m_occno(m)*( 6*m_cdg001(m)*m_cdg002(m)+2*m_cdg000(m)*m_cdg003(m) ));
      deriv210+=(m_occno(m)*( 2*(2*m_cdg100(m)*m_cdg110(m)+m_cdg010(m)*m_cdg200(m)+m_cdg000(m)*m_cdg210(m)) ));
      deriv201+=(m_occno(m)*( 2*(2*m_cdg100(m)*m_cdg101(m)+m_cdg001(m)*m_cdg200(m)+m_cdg000(m)*m_cdg201(m)) ));
      deriv120+=(m_occno(m)*( 2*(m_cdg020(m)*m_cdg100(m)+2*m_cdg010(m)*m_cdg110(m)+m_cdg000(m)*m_cdg120(m)) ));
      deriv021+=(m_occno(m)*( 2*(2*m_cdg010(m)*m_cdg011(m)+m_cdg001(m)*m_cdg020(m)+m_cdg000(m)*m_cdg021(m)) ));
      deriv102+=(m_occno(m)*( 2*(m_cdg002(m)*m_cdg100(m)+2*m_cdg001(m)*m_cdg101(m)+m_cdg000(m)*m_cdg102(m)) ));
      deriv012+=(m_occno(m)*( 2*(m_cdg002(m)*m_cdg010(m)+2*m_cdg001(m)*m_cdg011(m)+m_cdg000(m)*m_cdg012(m)) ));
      // deriv111+=(m_occno(m)*( 2*(m_cdg011(m)*m_cdg100(m)+m_cdg010(m)*m_cdg101(m)+m_cdg001(m)*m_cdg110(m)+m_cdg000(m)*m_cdg111(m)) ));
      deriv400+=(m_occno(m)*(6*ipow(m_cdg200(m),2)+8*m_cdg100(m)*m_cdg300(m)+2*m_cdg000(m)*m_cdg400(m)));
      deriv040+=(m_occno(m)*(6*ipow(m_cdg020(m),2)+8*m_cdg010(m)*m_cdg030(m)+2*m_cdg000(m)*m_cdg040(m)));
      deriv004+=(m_occno(m)*(6*ipow(m_cdg002(m),2)+8*m_cdg001(m)*m_cdg003(m)+2*m_cdg000(m)*m_cdg004(m)));
      deriv310+=(m_occno(m)*(2*(3*m_cdg110(m)*m_cdg200(m)+3*m_cdg100(m)*m_cdg210(m)+m_cdg010(m)*m_cdg300(m)+m_cdg000(m)*m_cdg310(m))));
      deriv301+=(m_occno(m)*(2*(3*m_cdg101(m)*m_cdg200(m)+3*m_cdg100(m)*m_cdg201(m)+m_cdg001(m)*m_cdg300(m)+m_cdg000(m)*m_cdg301(m))));
      deriv130+=(m_occno(m)*(2*(m_cdg030(m)*m_cdg100(m)+3*m_cdg020(m)*m_cdg110(m)+3*m_cdg010(m)*m_cdg120(m)+m_cdg000(m)*m_cdg130(m))));
      deriv031+=(m_occno(m)*(2*(3*m_cdg011(m)*m_cdg020(m)+3*m_cdg010(m)*m_cdg021(m)+m_cdg001(m)*m_cdg030(m)+m_cdg000(m)*m_cdg031(m))));
      deriv103+=(m_occno(m)*(2*(m_cdg003(m)*m_cdg100(m)+3*m_cdg002(m)*m_cdg101(m)+3*m_cdg001(m)*m_cdg102(m)+m_cdg000(m)*m_cdg103(m))));
      deriv013+=(m_occno(m)*(2*(m_cdg003(m)*m_cdg010(m)+3*m_cdg002(m)*m_cdg011(m)+3*m_cdg001(m)*m_cdg012(m)+m_cdg000(m)*m_cdg013(m))));
      deriv220+=(m_occno(m)*(2*(2*ipow(m_cdg110(m),2)+2*m_cdg100(m)*m_cdg120(m)+m_cdg020(m)*m_cdg200(m)+2*m_cdg010(m)*m_cdg210(m)+m_cdg000(m)*m_cdg220(m))));
      deriv202+=(m_occno(m)*(2*(2*ipow(m_cdg101(m),2)+2*m_cdg100(m)*m_cdg102(m)+m_cdg002(m)*m_cdg200(m)+2*m_cdg001(m)*m_cdg201(m)+m_cdg000(m)*m_cdg202(m))));
      deriv022+=(m_occno(m)*(2*(2*ipow(m_cdg011(m),2)+2*m_cdg010(m)*m_cdg012(m)+m_cdg002(m)*m_cdg020(m)+2*m_cdg001(m)*m_cdg021(m)+m_cdg000(m)*m_cdg022(m))));
      deriv211+=(m_occno(m)*(2*(2*m_cdg101(m)*m_cdg110(m)+2*m_cdg100(m)*m_cdg111(m)+m_cdg011(m)*m_cdg200(m)+m_cdg010(m)*m_cdg201(m)+m_cdg001(m)*m_cdg210(m)+m_cdg000(m)*m_cdg211(m))));
      deriv121+=(m_occno(m)*(2*(m_cdg021(m)*m_cdg100(m)+m_cdg020(m)*m_cdg101(m)+2*m_cdg011(m)*m_cdg110(m)+2*m_cdg010(m)*m_cdg111(m)+m_cdg001(m)*m_cdg120(m)+m_cdg000(m)*m_cdg121(m))));
      deriv112+=(m_occno(m)*(2*(m_cdg012(m)*m_cdg100(m)+2*m_cdg011(m)*m_cdg101(m)+m_cdg010(m)*m_cdg102(m)+m_cdg002(m)*m_cdg110(m)+2*m_cdg001(m)*m_cdg111(m)+m_cdg000(m)*m_cdg112(m))));
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

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal b0 = exp(b0arg);

        qreal bx1= -2*m_alpha(p)*xx0;
        qreal by1= -2*m_alpha(p)*yy0;
        qreal bz1= -2*m_alpha(p)*zz0;

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg100 = ay0*az0*b0*(ax1+ax0*bx1);
        qreal dg010 = ax0*az0*b0*(ay1+ay0*by1);
        qreal dg001 = ax0*ay0*b0*(az1+az0*bz1);

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
        }

      }
    }

    value=zero;
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      value += (0.5)*(m_occno(m)*(ipow(m_cdg100(m),2)+ipow(m_cdg010(m),2)+ipow(m_cdg001(m),2)));
    }

    return value;

  }

  const qreal QTAIMWavefunctionEvaluator::kineticEnergyDensityK( const Matrix<qreal,3,1> xyz )
  {

    qreal value;

    const qreal zero=0.0;
    const qreal one =1.0;

    m_cdg000.setZero();
    m_cdg200.setZero();
    m_cdg020.setZero();
    m_cdg002.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);
        qint64 aax2=m_xamom(p)*(m_xamom(p)-1);
        qint64 aay2=m_yamom(p)*(m_yamom(p)-1);
        qint64 aaz2=m_zamom(p)*(m_zamom(p)-1);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( m_xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( m_xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*ipow(xx0,m_xamom(p)-2);
        }

        if     ( m_yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( m_yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*ipow(yy0,m_yamom(p)-2);
        }

        if     ( m_zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( m_zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*ipow(zz0,m_zamom(p)-2);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*m_alpha(p)*xx0;
        qreal by1 = -2*m_alpha(p)*yy0;
        qreal bz1 = -2*m_alpha(p)*zz0;
        qreal bx2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(xx0,2));
        qreal by2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(yy0,2));
        qreal bz2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(zz0,2));

        qreal dg000 = ax0*ay0*az0*b0;
        qreal dg200 = ay0*az0*b0*(ax2+2*ax1*bx1+ax0*bx2);
        qreal dg020 = ax0*az0*b0*(ay2+2*ay1*by1+ay0*by2);
        qreal dg002 = ax0*ay0*b0*(az2+2*az1*bz1+az0*bz2);

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg200(m) += m_coef(m,p) * dg200;
          m_cdg020(m) += m_coef(m,p) * dg020;
          m_cdg002(m) += m_coef(m,p) * dg002;
        }

      }
    }

    value=0.0;
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      value += (0.25)*(m_occno(m)*(2*m_cdg000(m)*(m_cdg200(m)+m_cdg020(m)+m_cdg002(m))));
    }

    return value;

  }

  const Matrix<qreal,3,3> QTAIMWavefunctionEvaluator::quantumStressTensor( const Matrix<qreal,3,1> xyz )
  {

    Matrix<qreal,3,3> value;

    const qreal zero=0.0;
    const qreal one =1.0;

    m_cdg000.setZero();
    m_cdg100.setZero();
    m_cdg010.setZero();
    m_cdg001.setZero();
    m_cdg200.setZero();
    m_cdg020.setZero();
    m_cdg002.setZero();
    m_cdg110.setZero();
    m_cdg101.setZero();
    m_cdg011.setZero();
    for( qint64 p=0 ; p < m_nprim ; ++p )
    {
      qreal xx0 = xyz(0) - m_X0(p);
      qreal yy0 = xyz(1) - m_Y0(p);
      qreal zz0 = xyz(2) - m_Z0(p);

      qreal b0arg = -m_alpha(p)*(xx0*xx0 + yy0*yy0 + zz0*zz0 );

      if( b0arg > m_cutoff )
      {
        qint64 aax0=1;
        qint64 aay0=1;
        qint64 aaz0=1;
        qint64 aax1=m_xamom(p);
        qint64 aay1=m_yamom(p);
        qint64 aaz1=m_zamom(p);
        qint64 aax2=m_xamom(p)*(m_xamom(p)-1);
        qint64 aay2=m_yamom(p)*(m_yamom(p)-1);
        qint64 aaz2=m_zamom(p)*(m_zamom(p)-1);

        qreal ax0 = aax0*ipow( xx0, m_xamom(p) );
        qreal ay0 = aay0*ipow( yy0, m_yamom(p) );
        qreal az0 = aaz0*ipow( zz0, m_zamom(p) );

        qreal ax1;
        qreal ay1;
        qreal az1;
        if     ( m_xamom(p) <  1 )
        {
          ax1=zero;
        }
        else if( m_xamom(p) == 1 )
        {
          ax1=one;
        }
        else
        {
          ax1=aax1*ipow(xx0,m_xamom(p)-1);
        }

        if     ( m_yamom(p) <  1 )
        {
          ay1=zero;
        }
        else if( m_yamom(p) == 1 )
        {
          ay1=one;
        }
        else
        {
          ay1=aay1*ipow(yy0,m_yamom(p)-1);
        }

        if     ( m_zamom(p) <  1 )
        {
          az1=zero;
        }
        else if( m_zamom(p) == 1 )
        {
          az1=one;
        }
        else
        {
          az1=aaz1*ipow(zz0,m_zamom(p)-1);
        }

        qreal ax2;
        qreal ay2;
        qreal az2;
        if     ( m_xamom(p) <  2 )
        {
          ax2=zero;
        }
        else if( m_xamom(p) == 2 )
        {
          ax2=one;
        }
        else
        {
          ax2=aax2*ipow(xx0,m_xamom(p)-2);
        }

        if     ( m_yamom(p) <  2 )
        {
          ay2=zero;
        }
        else if( m_yamom(p) == 2 )
        {
          ay2=one;
        }
        else
        {
          ay2=aay2*ipow(yy0,m_yamom(p)-2);
        }

        if     ( m_zamom(p) <  2 )
        {
          az2=zero;
        }
        else if( m_zamom(p) == 2 )
        {
          az2=one;
        }
        else
        {
          az2=aaz2*ipow(zz0,m_zamom(p)-2);
        }

        qreal b0 = exp(b0arg);

        qreal bx1 = -2*m_alpha(p)*xx0;
        qreal by1 = -2*m_alpha(p)*yy0;
        qreal bz1 = -2*m_alpha(p)*zz0;
        qreal bx2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(xx0,2));
        qreal by2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(yy0,2));
        qreal bz2 = -2*m_alpha(p) + 4*(ipow(m_alpha(p),2) * ipow(zz0,2));

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

        for( qint64 m=0 ; m < m_nmo ; ++m )
        {
          m_cdg000(m) += m_coef(m,p) * dg000;
          m_cdg100(m) += m_coef(m,p) * dg100;
          m_cdg010(m) += m_coef(m,p) * dg010;
          m_cdg001(m) += m_coef(m,p) * dg001;
          m_cdg200(m) += m_coef(m,p) * dg200;
          m_cdg020(m) += m_coef(m,p) * dg020;
          m_cdg002(m) += m_coef(m,p) * dg002;
          m_cdg110(m) += m_coef(m,p) * dg110;
          m_cdg101(m) += m_coef(m,p) * dg101;
          m_cdg011(m) += m_coef(m,p) * dg011;
        }

      }
    }

    value.setZero();
    for( qint64 m=0 ; m < m_nmo ; ++m )
    {
      value(0,0)+=(m_occno(m)*(2*m_cdg000(m)*m_cdg200(m)-2*ipow(m_cdg100(m),2)));
      value(0,1)+=(m_occno(m)*(2*m_cdg000(m)*m_cdg110(m)-2*m_cdg100(m)*m_cdg010(m)));
      value(0,2)+=(m_occno(m)*(2*m_cdg000(m)*m_cdg101(m)-2*m_cdg100(m)*m_cdg001(m)));
      value(1,1)+=(m_occno(m)*(2*m_cdg000(m)*m_cdg020(m)-2*ipow(m_cdg010(m),2)));
      value(1,2)+=(m_occno(m)*(2*m_cdg000(m)*m_cdg011(m)-2*m_cdg010(m)*m_cdg001(m)));
      value(2,2)+=(m_occno(m)*(2*m_cdg000(m)*m_cdg002(m)-2*ipow(m_cdg001(m),2) ));
    }
    value(1,0)=value(0,1);
    value(2,0)=value(0,2);
    value(2,1)=value(1,2);

    return 0.25*value;

  }

} // namespace Avogadro
