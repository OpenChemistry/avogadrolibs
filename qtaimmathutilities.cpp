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

#include "qtaimmathutilities.h"

namespace Avogadro {
  
  Matrix<qreal,3,1> QTAIMMathUtilities::eigenvaluesOfASymmetricThreeByThreeMatrix( Matrix<qreal,3,3> A )
  {
    SelfAdjointEigenSolver<Matrix<qreal,3,3> > eigensolver(A);
    return eigensolver.eigenvalues();
  }
  
  Matrix<qreal,3,3> QTAIMMathUtilities::eigenvectorsOfASymmetricThreeByThreeMatrix( Matrix<qreal,3,3> A )
  {
    SelfAdjointEigenSolver<Matrix<qreal,3,3> > eigensolver(A);
    return eigensolver.eigenvectors();
  }
  
  Matrix<qreal,4,1> QTAIMMathUtilities::eigenvaluesOfASymmetricFourByFourMatrix( Matrix<qreal,4,4> A )
  {
    SelfAdjointEigenSolver<Matrix<qreal,4,4> > eigensolver(A);
    return eigensolver.eigenvalues();
  }
  
  Matrix<qreal,4,4> QTAIMMathUtilities::eigenvectorsOfASymmetricFourByFourMatrix( Matrix<qreal,4,4> A )
  {
    SelfAdjointEigenSolver<Matrix<qreal,4,4> > eigensolver(A);
    return eigensolver.eigenvectors();
  }
  
  qint64 QTAIMMathUtilities::signOfARealNumber( qreal x )
  {
    if      (x > 0.  )
    {
      return  1;
    }
    else if (x == 0. )
    {
      return  0;
    }
    else
    {
      return -1;
    }
  }
  
  qint64 QTAIMMathUtilities::signatureOfASymmetricThreeByThreeMatrix( Matrix<qreal,3,3> A )
  {
    SelfAdjointEigenSolver<Matrix<qreal,3,3> > eigensolver(A);
    Matrix<qreal,3,1> eigenvalues=eigensolver.eigenvalues();
    
    return QTAIMMathUtilities::signOfARealNumber(eigenvalues(0)) +
      QTAIMMathUtilities::signOfARealNumber(eigenvalues(1)) +
      QTAIMMathUtilities::signOfARealNumber(eigenvalues(2));
  }
  
  qreal QTAIMMathUtilities::ellipticityOfASymmetricThreeByThreeMatrix( Matrix<qreal,3,3> A )
  {
    SelfAdjointEigenSolver<Matrix<qreal,3,3> > eigensolver(A);
    Matrix<qreal,3,1> eigenvalues=eigensolver.eigenvalues();
    
    return (eigenvalues(0)/eigenvalues(1)) - 1.0 ;
  }
  
  qreal QTAIMMathUtilities::distance( Matrix<qreal,3,1> a, Matrix<qreal,3,1> b  )
  {
    return sqrt( pow(a(0)-b(0),2) +
                 pow(a(1)-b(1),2) +
                 pow(a(2)-b(2),2) );
  }
  
  Matrix<qreal,3,1> QTAIMMathUtilities::sphericalToCartesian( Matrix<qreal,3,1> rtp, Matrix<qreal,3,1> x0y0z0 )
  {
    qreal r=rtp(0);
    qreal theta=rtp(1);
    qreal phi=rtp(2);
    
    qreal x0=x0y0z0(0);
    qreal y0=x0y0z0(1);
    qreal z0=x0y0z0(2);
    
    qreal costheta = cos(theta);
    qreal cosphi   = cos(phi);
    qreal sintheta = sin(theta);
    qreal sinphi   = sin(phi);
    
    Matrix<qreal,3,1> xyz( r*cosphi*sintheta + x0,
                           r*sintheta*sinphi + y0,
                           r*costheta        + z0);
    
    return xyz;
  }
  
  Matrix<qreal,3,1> QTAIMMathUtilities::sphericalToCartesian( Matrix<qreal,3,1> rtp )
  {
    Matrix<qreal,3,1> x0y0z0(0.,0.,0.);
    
    return  QTAIMMathUtilities::sphericalToCartesian( rtp, x0y0z0 );
  }
  
  Matrix<qreal,3,1> QTAIMMathUtilities::cartesianToSpherical( Matrix<qreal,3,1> xyz, Matrix<qreal,3,1> x0y0z0 )
  {
    qreal x=xyz(0);
    qreal y=xyz(1);
    qreal z=xyz(2);
    
    qreal x0=x0y0z0(0);
    qreal y0=x0y0z0(1);
    qreal z0=x0y0z0(2);
    
    qreal xshift = x - x0;
    qreal yshift = y - y0;
    qreal zshift = z - z0;
    
    qreal length = sqrt( pow(xshift,2) + pow(yshift,2) + pow(zshift,2) );
    
    Matrix<qreal,3,1> rtp;
    
    if (length == 0.)
    {
      rtp << x0,y0,z0 ;
    }
    else if (xshift == 0. && yshift == 0.)
    {
      rtp << length, acos(zshift/length), 0.;
    }
    else
    {
      rtp << length, acos(zshift/length), atan2(xshift,yshift);
    }
    
    return rtp;
  }
  
  Matrix<qreal,3,1> QTAIMMathUtilities::cartesianToSpherical( Matrix<qreal,3,1> xyz )
  {
    Matrix<qreal,3,1> x0y0z0(0.,0.,0.);
    
    return  QTAIMMathUtilities::cartesianToSpherical( xyz, x0y0z0 );
  }


  // Cerjan-Miller-Baker-Popelier Methods
  //
  // Based on:
  // Popelier, P.L.A. Comput. Phys. Comm. 1996, 93, 212.

  Matrix<qreal,3,1> QTAIMMathUtilities::minusThreeSignatureLocatorGradient( Matrix<qreal,3,1> g, Matrix<qreal,3,3> H )
  {
    
    Matrix<qreal,3,1> value;
    
    Matrix<qreal,3,1> b=QTAIMMathUtilities::eigenvaluesOfASymmetricThreeByThreeMatrix( H );
    Matrix<qreal,3,3> U=QTAIMMathUtilities::eigenvectorsOfASymmetricThreeByThreeMatrix( H );
    
    Matrix<qreal,3,1> F=U.transpose()*g;
    
    Matrix<qreal,4,4> A;
    A <<  b(0), 0.  , 0.  , F(0),
          0.  , b(1), 0.  , F(1),
          0.  , 0.  , b(2), F(2),
          F(0), F(1), F(2), 0.   ;
    
    Matrix<qreal,4,1> eval=QTAIMMathUtilities::eigenvaluesOfASymmetricFourByFourMatrix( A );
    Matrix<qreal,4,4> evec=QTAIMMathUtilities::eigenvectorsOfASymmetricFourByFourMatrix( A );

    Matrix<qreal,3,1> lambda;
    lambda << eval(3), eval(3), eval(3);

    Matrix<qreal,3,1> denom;
    denom = b-lambda;

    for( qint64 i=0; i < 3; ++i)
    {
      if( denom(i) < SMALL )
      {
        denom(i)=denom(i)+SMALL;
      }
    }

    Matrix<qreal,3,1> h;
    h << 0., 0., 0.;

    for( qint64 j=0; j < 3; ++j)
    {
      for( qint64 i=0; i < 3; ++i)
      {
        h(j)=h(j) + ( -F(i) * U(j,i) ) / denom(i);
      }
    }

    value=h;

    return value;

  }

  Matrix<qreal,3,1> QTAIMMathUtilities::minusOneSignatureLocatorGradient( Matrix<qreal,3,1> g, Matrix<qreal,3,3> H )
  {

    Matrix<qreal,3,1> value;

    Matrix<qreal,3,1> b=QTAIMMathUtilities::eigenvaluesOfASymmetricThreeByThreeMatrix( H );
    Matrix<qreal,3,3> U=QTAIMMathUtilities::eigenvectorsOfASymmetricThreeByThreeMatrix( H );

    Matrix<qreal,3,1> F=U.transpose()*g;

    Matrix<qreal,3,3> A;
    A <<  b(0), 0.  ,  F(0),
          0.  , b(1),  F(1),
          F(0), F(1),  0.   ;

    Matrix<qreal,3,1> eval=QTAIMMathUtilities::eigenvaluesOfASymmetricThreeByThreeMatrix( A );
    Matrix<qreal,3,3> evec=QTAIMMathUtilities::eigenvectorsOfASymmetricThreeByThreeMatrix( A );

    Matrix<qreal,3,1> lambda;
    lambda << eval(2), eval(2), (0.5) * (b(2)-sqrt( pow(b(2),2) + 4.0 * pow(F(2),2)  ) ) ;

    Matrix<qreal,3,1> denom;
    denom = b-lambda;

    for( qint64 i=0; i < 3; ++i)
    {
      if( denom(i) < SMALL )
      {
        denom(i)=denom(i)+SMALL;
      }
    }

    Matrix<qreal,3,1> h;
    h << 0., 0., 0.;

    for( qint64 j=0; j < 3; ++j)
    {
      for( qint64 i=0; i < 3; ++i)
      {
        h(j)=h(j) + ( -F(i) * U(j,i) ) / denom(i);
      }
    }

    value=h;

    return value;

  }

  Matrix<qreal,3,1> QTAIMMathUtilities::plusOneSignatureLocatorGradient( Matrix<qreal,3,1> g, Matrix<qreal,3,3> H )
  {

    Matrix<qreal,3,1> value;

    Matrix<qreal,3,1> b=QTAIMMathUtilities::eigenvaluesOfASymmetricThreeByThreeMatrix( H );
    Matrix<qreal,3,3> U=QTAIMMathUtilities::eigenvectorsOfASymmetricThreeByThreeMatrix( H );

    Matrix<qreal,3,1> F=U*g;

    Matrix<qreal,3,3> A;
    A <<  b(1), 0.  ,  F(1),
          0.  , b(2),  F(2),
          F(1), F(2),  0.   ;

    Matrix<qreal,3,1> eval=QTAIMMathUtilities::eigenvaluesOfASymmetricThreeByThreeMatrix( A );
    Matrix<qreal,3,3> evec=QTAIMMathUtilities::eigenvectorsOfASymmetricThreeByThreeMatrix( A );

    Matrix<qreal,3,1> lambda;
    lambda << eval(2), eval(2), (0.5) * (b(0)+sqrt( pow(b(0),2) + 4.0 * pow(F(0),2)  ) ) ;

    Matrix<qreal,3,1> denom;
    denom = b-lambda;

    for( qint64 i=0; i < 3; ++i)
    {
      if( denom(i) < SMALL )
      {
        denom(i)=denom(i)+SMALL;
      }
    }

    Matrix<qreal,3,1> h;
    h << 0., 0., 0.;

    for( qint64 j=0; j < 3; ++j)
    {
      for( qint64 i=0; i < 3; ++i)
      {
        h(j)=h(j) + ( -F(i) * U(i,j) ) / denom(i);
      }
    }

    value=h;

    return value;

  }

  Matrix<qreal,3,1> QTAIMMathUtilities::plusThreeSignatureLocatorGradient( Matrix<qreal,3,1> g, Matrix<qreal,3,3> H )
  {

    Matrix<qreal,3,1> value;

    Matrix<qreal,3,1> b=QTAIMMathUtilities::eigenvaluesOfASymmetricThreeByThreeMatrix( H );
    Matrix<qreal,3,3> U=QTAIMMathUtilities::eigenvectorsOfASymmetricThreeByThreeMatrix( H );

    Matrix<qreal,3,1> F=U*g;

    Matrix<qreal,4,4> A;
    A <<  b(0), 0.  , 0.  , F(0),
          0.  , b(1), 0.  , F(1),
          0.  , 0.  , b(2), F(2),
          F(0), F(1), F(2), 0.   ;

    Matrix<qreal,4,1> eval=QTAIMMathUtilities::eigenvaluesOfASymmetricFourByFourMatrix( A );
    Matrix<qreal,4,4> evec=QTAIMMathUtilities::eigenvectorsOfASymmetricFourByFourMatrix( A );

    Matrix<qreal,3,1> lambda;
    lambda << eval(0), eval(0), eval(0);

    Matrix<qreal,3,1> denom;
    denom = b-lambda;

    for( qint64 i=0; i < 3; ++i)
    {
      if( denom(i) < SMALL )
      {
        denom(i)=denom(i)+SMALL;
      }
    }

    Matrix<qreal,3,1> h;
    h << 0., 0., 0.;

    for( qint64 j=0; j < 3; ++j)
    {
      for( qint64 i=0; i < 3; ++i)
      {
        h(j)=h(j) + ( -F(i) * U(i,j) ) / denom(i);
      }
    }

    value=h;

    return value;

  }

} // namespace Avogadro
