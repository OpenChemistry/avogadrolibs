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

/*
   Based on codes written by Herman Watts, Lawrence Shampine, and John Burkardt.
*/

#include "qtaimodeintegrator.h"

namespace Avogadro
{
  QTAIMODEIntegrator::QTAIMODEIntegrator(QTAIMWavefunctionEvaluator &eval, const qint64 mode)
  {
    m_eval=&eval;
    m_mode=mode;

    m_betaSpheres.empty();
    m_associatedSphere=0;
  }

  QVector3D QTAIMODEIntegrator::integrate( QVector3D x0y0z0 )
  {
    qreal x0=x0y0z0.x();
    qreal y0=x0y0z0.y();
    qreal z0=x0y0z0.z();

    const qint64 NEQN=3;

    abserr_save = -1.0;
    flag_save = -1000;
    h = -1.0;
    init = -1000;
    kflag = -1000;
    kop = -1;
    nfe = -1;
    relerr_save = -1.0;
    remin = 1.0e-12;

    qreal  abserr;
    qint64 flag;
    qint64 i_step;
    qint64 n_step;
    qreal  relerr;
    qreal  t;
    qreal  t_out;
    qreal  t_start;
    qreal  t_stop;
    qreal  y[3];
    qreal  yp[3];

    switch (m_mode)
    {
    case SteepestAscentPathInElectronDensity:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 10.0;
      n_step  = t_stop * 20;
      break;
    case CMBPMinusThreeGradientInElectronDensity:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 1.0;
      n_step  = t_stop * 1000;
      break;
    case CMBPMinusOneGradientInElectronDensity:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 1.0;
      n_step  = t_stop * 100;
      break;
    case CMBPPlusOneGradientInElectronDensity:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 1.0;
      n_step  = t_stop * 200;
      break;
    case CMBPPlusThreeGradientInElectronDensity:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 1.0;
      n_step  = t_stop * 200;
      break;
    case CMBPMinusThreeGradientInElectronDensityLaplacian:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 1.0;
      n_step  = t_stop * 200;
      break;
    case CMBPMinusOneGradientInElectronDensityLaplacian:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 1.0;
      n_step  = t_stop * 200;
      break;
    case CMBPPlusOneGradientInElectronDensityLaplacian:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 1.0;
      n_step  = t_stop * 200;
      break;
    case CMBPPlusThreeGradientInElectronDensityLaplacian:
      abserr =      sqrt ( r8_epsilon ( ) );
      relerr =      sqrt ( r8_epsilon ( ) );
      t_start = 0.0;
      t_stop  = 1.0;
      n_step  = t_stop * 200;
      break;
    default:
      qDebug() << "Catastrophic: No ODE parameters for this property." ;
      exit(1);
      break;
    }

    y[0]=x0; y[1]=y0; y[2]=z0;

    m_path.clear();
    m_path.append(QVector3D(y[0],y[1],y[2]));

    flag=1;

    for ( i_step = 1; i_step <= n_step; i_step++ )
    {
      t = ( ( qreal ) ( n_step - i_step + 1 ) * t_start
            + ( qreal ) (          i_step - 1 ) * t_stop )
          / ( qreal ) ( n_step              );

      t_out = ( ( qreal ) ( n_step - i_step ) * t_start
                + ( qreal ) (          i_step ) * t_stop )
              / ( qreal ) ( n_step          );

      flag = QTAIMODEIntegrator::r8_rkf45( NEQN, y, yp, &t, t_out, &relerr, abserr, flag );

      m_status=flag;
      m_path.append(QVector3D(y[0],y[1],y[2]));

      if( flag == 7)
      {
        flag=2;
        m_status=flag;
      }

      if( flag != 2 )
      {
        m_status=flag;
        return QVector3D(y[0],y[1],y[2]) ;
      }

      if( m_betaSpheres.length() > 0 )
      {
        for( qint64 n=0 ; n < m_betaSpheres.length() ; ++n )
        {
          Matrix<qreal,3,1> a(y[0],y[1],y[2]);
          Matrix<qreal,3,1> b(m_betaSpheres.at(n).first.x(),
                              m_betaSpheres.at(n).first.y(),
                              m_betaSpheres.at(n).first.z() );

          qreal distance=QTAIMMathUtilities::distance(a,b);

          if( distance < m_betaSpheres.at(n).second )
          {
            m_status=0;
            m_associatedSphere=n;
            return QVector3D( m_betaSpheres.at(n).first.x(),
                              m_betaSpheres.at(n).first.y(),
                              m_betaSpheres.at(n).first.z() );
          }
        }
      } // beta spheres

    } // ODE step

    return QVector3D(y[0],y[1],y[2]);
  }

  void QTAIMODEIntegrator::r8_f ( qreal t, qreal y[], qreal yp[] )
  {

    t=t; // suppress warning

    Matrix<qreal,3,1> gradient;

    Matrix<qreal,3,4> gH;
    Matrix<qreal,3,1> g;
    Matrix<qreal,3,3> H;

    Matrix<qreal,3,1> xyz;
    xyz << y[0],y[1],y[2];

    if(m_mode ==  SteepestAscentPathInElectronDensity )
    {
      g=m_eval->gradientOfElectronDensity(xyz);
    }
    else
    {
      if( m_mode == 1 || m_mode ==2 || m_mode ==3 || m_mode == 4 )
      {
        gH=m_eval->gradientAndHessianOfElectronDensity(xyz);
      }
      else
      {
        gH=m_eval->gradientAndHessianOfElectronDensityLaplacian(xyz);
      }

      g(0)=gH(0,0);
      g(1)=gH(1,0);
      g(2)=gH(2,0);
      H(0,0)=gH(0,1);
      H(1,0)=gH(1,1);
      H(2,0)=gH(2,1);
      H(0,1)=gH(0,2);
      H(1,1)=gH(1,2);
      H(2,1)=gH(2,2);
      H(0,2)=gH(0,3);
      H(1,2)=gH(1,3);
      H(2,2)=gH(2,3);
    }

    switch (m_mode)
    {
    case SteepestAscentPathInElectronDensity:
      gradient=g;
      break;
    case CMBPMinusThreeGradientInElectronDensity:
      gradient=QTAIMMathUtilities::minusThreeSignatureLocatorGradient(g,H);
      break;
    case CMBPMinusOneGradientInElectronDensity:
      gradient=QTAIMMathUtilities::minusOneSignatureLocatorGradient(g,H);
      break;
    case CMBPPlusOneGradientInElectronDensity:
      gradient=QTAIMMathUtilities::plusOneSignatureLocatorGradient(g,H);
      break;
    case CMBPPlusThreeGradientInElectronDensity:
      gradient=QTAIMMathUtilities::plusThreeSignatureLocatorGradient(g,H);
      break;
    case CMBPMinusThreeGradientInElectronDensityLaplacian:
      gradient=QTAIMMathUtilities::minusThreeSignatureLocatorGradient(g,H);
      break;
    case CMBPMinusOneGradientInElectronDensityLaplacian:
      gradient=QTAIMMathUtilities::minusOneSignatureLocatorGradient(g,H);
      break;
    case CMBPPlusOneGradientInElectronDensityLaplacian:
      gradient=QTAIMMathUtilities::plusOneSignatureLocatorGradient(g,H);
      break;
    case CMBPPlusThreeGradientInElectronDensityLaplacian:
      gradient=QTAIMMathUtilities::plusThreeSignatureLocatorGradient(g,H);
      break;
    default:
      qDebug() << "Catastrophic: No ODE parameters for this property." ;
      exit(1);
      break;
    }

    qreal normGradient=sqrt( gradient(0)*gradient(0) + gradient(1)*gradient(1) + gradient(2)*gradient(2)  );

    yp[0]= gradient(0) / normGradient;
    yp[1]= gradient(1) / normGradient;
    yp[2]= gradient(2) / normGradient;

  }

  //****************************************************************************80

  qreal QTAIMODEIntegrator::r8_abs ( qreal x )

  //****************************************************************************80
  //
  //  Purpose:
  //
  //    R8_ABS returns the absolute value of an R8.
  //
  //  Licensing:
  //
  //    This code is distributed under the GNU LGPL license.
  //
  //  Modified:
  //
  //    02 April 2005
  //
  //  Author:
  //
  //    John Burkardt
  //
  //  Parameters:
  //
  //    Input, qreal X, the quantity whose absolute value is desired.
  //
  //    Output, qreal R8_ABS, the absolute value of X.
  //
  {
    if ( 0.0 <= x )
    {
      return x;
    }
    else
    {
      return ( -x );
    }
  }
  //****************************************************************************80

  qreal QTAIMODEIntegrator::r8_epsilon ( )

  //****************************************************************************80
  //
  //  Purpose:
  //
  //    R8_EPSILON returns the R8 round off unit.
  //
  //  Discussion:
  //
  //    R8_EPSILON is a number R which is a power of 2 with the property that,
  //    to the precision of the computer's arithmetic,
  //      1 < 1 + R
  //    but
  //      1 = ( 1 + R / 2 )
  //
  //  Licensing:
  //
  //    This code is distributed under the GNU LGPL license.
  //
  //  Modified:
  //
  //    06 May 2003
  //
  //  Author:
  //
  //    John Burkardt
  //
  //  Parameters:
  //
  //    Output, qreal R8_EPSILON, the R8 round-off unit.
  //
  {
    qreal r;

    r = 1.0;

    while ( 1.0 < ( qreal ) ( 1.0 + r )  )
    {
      r = r / 2.0;
    }

    return ( 2.0 * r );
  }
  //****************************************************************************80

  void QTAIMODEIntegrator::r8_fehl ( qint64 neqn,
                                            qreal y[], qreal t, qreal h, qreal yp[], qreal f1[], qreal f2[],
                                            qreal f3[], qreal f4[], qreal f5[], qreal s[] )

  //****************************************************************************80
  //
  //  Purpose:
  //
  //    R8_FEHL takes one Fehlberg fourth-fifth order step.
  //
  //  Discussion:
  //
  //    This version of the routine uses qreal real arithemtic.
  //
  //    This routine integrates a system of NEQN first order ordinary differential
  //    equations of the form
  //      dY(i)/dT = F(T,Y(1:NEQN))
  //    where the initial values Y and the initial derivatives
  //    YP are specified at the starting point T.
  //
  //    The routine advances the solution over the fixed step H and returns
  //    the fifth order (sixth order accurate locally) solution
  //    approximation at T+H in array S.
  //
  //    The formulas have been grouped to control loss of significance.
  //    The routine should be called with an H not smaller than 13 units of
  //    roundoff in T so that the various independent arguments can be
  //    distinguished.
  //
  //  Licensing:
  //
  //    This code is distributed under the GNU LGPL license.
  //
  //  Modified:
  //
  //    27 March 2004
  //
  //  Author:
  //
  //    Original FORTRAN77 version by Herman Watts, Lawrence Shampine.
  //    C++ version by John Burkardt.
  //
  //  Reference:
  //
  //    Erwin Fehlberg,
  //    Low-order Classical Runge-Kutta Formulas with Stepsize Control,
  //    NASA Technical Report R-315, 1969.
  //
  //    Lawrence Shampine, Herman Watts, S Davenport,
  //    Solving Non-stiff Ordinary Differential Equations - The State of the Art,
  //    SIAM Review,
  //    Volume 18, pages 376-411, 1976.
  //
  //  Parameters:
  //
  //    Input, external F, a user-supplied subroutine to evaluate the
  //    derivatives Y'(T), of the form:
  //
  //      void f ( qreal t, qreal y[], qreal yp[] )
  //
  //    Input, qint64 NEQN, the number of equations to be integrated.
  //
  //    Input, qreal Y[NEQN], the current value of the dependent variable.
  //
  //    Input, qreal T, the current value of the independent variable.
  //
  //    Input, qreal H, the step size to take.
  //
  //    Input, qreal YP[NEQN], the current value of the derivative of the
  //    dependent variable.
  //
  //    Output, qreal F1[NEQN], F2[NEQN], F3[NEQN], F4[NEQN], F5[NEQN], derivative
  //    values needed for the computation.
  //
  //    Output, qreal S[NEQN], the estimate of the solution at T+H.
  //
  {
    qreal ch;
    qint64 i;

    ch = h / 4.0;

    for ( i = 0; i < neqn; i++ )
    {
      f5[i] = y[i] + ch * yp[i];
    }

    QTAIMODEIntegrator::r8_f (t + ch, f5, f1 );

    ch = 3.0 * h / 32.0;

    for ( i = 0; i < neqn; i++ )
    {
      f5[i] = y[i] + ch * ( yp[i] + 3.0 * f1[i] );
    }

    QTAIMODEIntegrator::r8_f ( t + 3.0 * h / 8.0, f5, f2 );

    ch = h / 2197.0;

    for ( i = 0; i < neqn; i++ )
    {
      f5[i] = y[i] + ch *
              ( 1932.0 * yp[i]
                + ( 7296.0 * f2[i] - 7200.0 * f1[i] )
                );
    }

    QTAIMODEIntegrator::r8_f ( t + 12.0 * h / 13.0, f5, f3 );

    ch = h / 4104.0;

    for ( i = 0; i < neqn; i++ )
    {
      f5[i] = y[i] + ch *
              (
                  ( 8341.0 * yp[i] - 845.0 * f3[i] )
                  + ( 29440.0 * f2[i] - 32832.0 * f1[i] )
                  );
    }

    QTAIMODEIntegrator::r8_f ( t + h, f5, f4 );

    ch = h / 20520.0;

    for ( i = 0; i < neqn; i++ )
    {
      f1[i] = y[i] + ch *
              (
                  ( -6080.0 * yp[i]
                    + ( 9295.0 * f3[i] - 5643.0 * f4[i] )
                    )
                  + ( 41040.0 * f1[i] - 28352.0 * f2[i] )
                  );
    }

    QTAIMODEIntegrator::r8_f ( t + h / 2.0, f1, f5 );
    //
    //  Ready to compute the approximate solution at T+H.
    //
    ch = h / 7618050.0;

    for ( i = 0; i < neqn; i++ )
    {
      s[i] = y[i] + ch *
             (
                 ( 902880.0 * yp[i]
                   + ( 3855735.0 * f3[i] - 1371249.0 * f4[i] ) )
                 + ( 3953664.0 * f2[i] + 277020.0 * f5[i] )
                 );
    }

    return;
  }
  //****************************************************************************80

  qreal QTAIMODEIntegrator::r8_max ( qreal x, qreal y )

      //****************************************************************************80
      //
      //  Purpose:
      //
      //    R8_MAX returns the maximum of two R8's.
      //
      //  Licensing:
      //
      //    This code is distributed under the GNU LGPL license.
      //
      //  Modified:
      //
      //    10 January 2002
      //
      //  Author:
      //
      //    John Burkardt
      //
      //  Parameters:
      //
      //    Input, qreal X, Y, the quantities to compare.
      //
      //    Output, qreal R8_MAX, the maximum of X and Y.
      //
  {
    if ( y < x )
    {
      return x;
    }
    else
    {
      return y;
    }
  }
  //****************************************************************************80

  qreal QTAIMODEIntegrator::r8_min ( qreal x, qreal y )

  //****************************************************************************80
  //
  //  Purpose:
  //
  //    R8_MIN returns the minimum of two R8's.
  //
  //  Licensing:
  //
  //    This code is distributed under the GNU LGPL license.
  //
  //  Modified:
  //
  //    09 May 2003
  //
  //  Author:
  //
  //    John Burkardt
  //
  //  Parameters:
  //
  //    Input, qreal X, Y, the quantities to compare.
  //
  //    Output, qreal R8_MIN, the minimum of X and Y.
  //
  {
    if ( y < x )
    {
      return y;
    }
    else
    {
      return x;
    }
  }
  //****************************************************************************80

  qint64 QTAIMODEIntegrator::r8_rkf45 ( qint64 neqn,
                                               qreal y[], qreal yp[], qreal *t, qreal tout, qreal *relerr,
                                               qreal abserr, qint64 flag )

  //****************************************************************************80
  //
  //  Purpose:
  //
  //    R8_RKF45 carries out the Runge-Kutta-Fehlberg method.
  //
  //  Discussion:
  //
  //    This version of the routine uses qreal real arithmetic.
  //
  //    This routine is primarily designed to solve non-stiff and mildly stiff
  //    differential equations when derivative evaluations are inexpensive.
  //    It should generally not be used when the user is demanding
  //    high accuracy.
  //
  //    This routine integrates a system of NEQN first-order ordinary differential
  //    equations of the form:
  //
  //      dY(i)/dT = F(T,Y(1),Y(2),...,Y(NEQN))
  //
  //    where the Y(1:NEQN) are given at T.
  //
  //    Typically the subroutine is used to integrate from T to TOUT but it
  //    can be used as a one-step integrator to advance the solution a
  //    single step in the direction of TOUT.  On return, the parameters in
  //    the call list are set for continuing the integration.  The user has
  //    only to call again (and perhaps define a new value for TOUT).
  //
  //    Before the first call, the user must
  //
  //    * supply the subroutine F(T,Y,YP) to evaluate the right hand side;
  //      and declare F in an EXTERNAL statement;
  //
  //    * initialize the parameters:
  //      NEQN, Y(1:NEQN), T, TOUT, RELERR, ABSERR, FLAG.
  //      In particular, T should initially be the starting point for integration,
  //      Y should be the value of the initial conditions, and FLAG should
  //      normally be +1.
  //
  //    Normally, the user only sets the value of FLAG before the first call, and
  //    thereafter, the program manages the value.  On the first call, FLAG should
  //    normally be +1 (or -1 for single step mode.)  On normal return, FLAG will
  //    have been reset by the program to the value of 2 (or -2 in single
  //    step mode), and the user can continue to call the routine with that
  //    value of FLAG.
  //
  //    (When the input magnitude of FLAG is 1, this indicates to the program
  //    that it is necessary to do some initialization work.  An input magnitude
  //    of 2 lets the program know that that initialization can be skipped,
  //    and that useful information was computed earlier.)
  //
  //    The routine returns with all the information needed to continue
  //    the integration.  If the integration reached TOUT, the user need only
  //    define a new TOUT and call again.  In the one-step integrator
  //    mode, returning with FLAG = -2, the user must keep in mind that
  //    each step taken is in the direction of the current TOUT.  Upon
  //    reaching TOUT, indicated by the output value of FLAG switching to 2,
  //    the user must define a new TOUT and reset FLAG to -2 to continue
  //    in the one-step integrator mode.
  //
  //    In some cases, an error or difficulty occurs during a call.  In that case,
  //    the output value of FLAG is used to indicate that there is a problem
  //    that the user must address.  These values include:
  //
  //    * 3, integration was not completed because the input value of RELERR, the
  //      relative error tolerance, was too small.  RELERR has been increased
  //      appropriately for continuing.  If the user accepts the output value of
  //      RELERR, then simply reset FLAG to 2 and continue.
  //
  //    * 4, integration was not completed because more than MAXNFE derivative
  //      evaluations were needed.  This is approximately (MAXNFE/6) steps.
  //      The user may continue by simply calling again.  The function counter
  //      will be reset to 0, and another MAXNFE function evaluations are allowed.
  //
  //    * 5, integration was not completed because the solution vanished,
  //      making a pure relative error test impossible.  The user must use
  //      a non-zero ABSERR to continue.  Using the one-step integration mode
  //      for one step is a good way to proceed.
  //
  //    * 6, integration was not completed because the requested accuracy
  //      could not be achieved, even using the smallest allowable stepsize.
  //      The user must increase the error tolerances ABSERR or RELERR before
  //      continuing.  It is also necessary to reset FLAG to 2 (or -2 when
  //      the one-step integration mode is being used).  The occurrence of
  //      FLAG = 6 indicates a trouble spot.  The solution is changing
  //      rapidly, or a singularity may be present.  It often is inadvisable
  //      to continue.
  //
  //    * 7, it is likely that this routine is inefficient for solving
  //      this problem.  Too much output is restricting the natural stepsize
  //      choice.  The user should use the one-step integration mode with
  //      the stepsize determined by the code.  If the user insists upon
  //      continuing the integration, reset FLAG to 2 before calling
  //      again.  Otherwise, execution will be terminated.
  //
  //    * 8, invalid input parameters, indicates one of the following:
  //      NEQN <= 0;
  //      T = TOUT and |FLAG| /= 1;
  //      RELERR < 0 or ABSERR < 0;
  //      FLAG == 0  or FLAG < -2 or 8 < FLAG.
  //
  //  Licensing:
  //
  //    This code is distributed under the GNU LGPL license.
  //
  //  Modified:
  //
  //    27 March 2004
  //
  //  Author:
  //
  //    Original FORTRAN77 version by Herman Watts, Lawrence Shampine.
  //    C++ version by John Burkardt.
  //
  //  Reference:
  //
  //    Erwin Fehlberg,
  //    Low-order Classical Runge-Kutta Formulas with Stepsize Control,
  //    NASA Technical Report R-315, 1969.
  //
  //    Lawrence Shampine, Herman Watts, S Davenport,
  //    Solving Non-stiff Ordinary Differential Equations - The State of the Art,
  //    SIAM Review,
  //    Volume 18, pages 376-411, 1976.
  //
  //  Parameters:
  //
  //    Input, external F, a user-supplied subroutine to evaluate the
  //    derivatives Y'(T), of the form:
  //
  //      void f ( qreal t, qreal y[], qreal yp[] )
  //
  //    Input, qint64 NEQN, the number of equations to be integrated.
  //
  //    Input/output, qreal Y[NEQN], the current solution vector at T.
  //
  //    Input/output, qreal YP[NEQN], the derivative of the current solution
  //    vector at T.  The user should not set or alter this information!
  //
  //    Input/output, qreal *T, the current value of the independent variable.
  //
  //    Input, qreal TOUT, the output point at which solution is desired.
  //    TOUT = T is allowed on the first call only, in which case the routine
  //    returns with FLAG = 2 if continuation is possible.
  //
  //    Input, qreal *RELERR, ABSERR, the relative and absolute error tolerances
  //    for the local error test.  At each step the code requires:
  //      abs ( local error ) <= RELERR * abs ( Y ) + ABSERR
  //    for each component of the local error and the solution vector Y.
  //    RELERR cannot be "too small".  If the routine believes RELERR has been
  //    set too small, it will reset RELERR to an acceptable value and return
  //    immediately for user action.
  //
  //    Input, qint64 FLAG, indicator for status of integration. On the first call,
  //    set FLAG to +1 for normal use, or to -1 for single step mode.  On
  //    subsequent continuation steps, FLAG should be +2, or -2 for single
  //    step mode.
  //
  //    Output, qint64 RKF45_D, indicator for status of integration.  A value of 2
  //    or -2 indicates normal progress, while any other value indicates a
  //    problem that should be addressed.
  //
  {
    // ECB: originally 3000
#define MAXNFE 1000

    qreal ae;
    qreal dt;
    qreal ee;
    qreal eeoet;
    qreal eps;
    qreal esttol;
    qreal et;
    qreal *f1;
    qreal *f2;
    qreal *f3;
    qreal *f4;
    qreal *f5;
    bool hfaild;
    qreal hmin;
    qint64 i;
    qint64 k;
    qint64 mflag;
    bool output;
    qreal relerr_min;
    qreal s;
    qreal scale;
    qreal tol;
    qreal toln;
    qreal ypk;
    //
    //  Check the input parameters.
    //
    eps = r8_epsilon ( );

    if ( neqn < 1 )
    {
      return 8;
    }

    if ( (*relerr) < 0.0 )
    {
      return 8;
    }

    if ( abserr < 0.0 )
    {
      return 8;
    }

    if ( flag == 0 || 8 < flag  || flag < -2 )
    {
      return 8;
    }

    mflag = abs ( flag );
    //
    //  Is this a continuation call?
    //
    if ( mflag != 1 )
    {
      if ( *t == tout && kflag != 3 )
      {
        return 8;
      }
      //
      //  FLAG = -2 or +2:
      //
      if ( mflag == 2 )
      {
        if ( kflag == 3 )
        {
          flag = flag_save;
          mflag = abs ( flag );
        }
        else if ( init == 0 )
        {
          flag = flag_save;
        }
        else if ( kflag == 4 )
        {
          nfe = 0;
        }
        else if ( kflag == 5 && abserr == 0.0 )
        {
          exit ( 1 );
        }
        else if ( kflag == 6 && (*relerr) <= relerr_save && abserr <= abserr_save )
        {
          exit ( 1 );
        }
      }
      //
      //  FLAG = 3, 4, 5, 6, 7 or 8.
      //
      else
      {
        if ( flag == 3 )
        {
          flag = flag_save;
          if ( kflag == 3 )
          {
            mflag = abs ( flag );
          }
        }
        else if ( flag == 4 )
        {
          nfe = 0;
          flag = flag_save;
          if ( kflag == 3 )
          {
            mflag = abs ( flag );
          }
        }
        else if ( flag == 5 && 0.0 < abserr )
        {
          flag = flag_save;
          if ( kflag == 3 )
          {
            mflag = abs ( flag );
          }
        }
        //
        //  Integration cannot be continued because the user did not respond to
        //  the instructions pertaining to FLAG = 5, 6, 7 or 8.
        //
        else
        {
          exit ( 1 );
        }
      }
    }
    //
    //  Save the input value of FLAG.
    //  Set the continuation flag KFLAG for subsequent input checking.
    //
    flag_save = flag;
    kflag = 0;
    //
    //  Save RELERR and ABSERR for checking input on subsequent calls.
    //
    relerr_save = (*relerr);
    abserr_save = abserr;
    //
    //  Restrict the relative error tolerance to be at least
    //
    //    2*EPS+REMIN
    //
    //  to avoid limiting precision difficulties arising from impossible
    //  accuracy requests.
    //
    relerr_min = 2.0 * r8_epsilon ( ) + remin;
    //
    //  Is the relative error tolerance too small?
    //
    if ( (*relerr) < relerr_min )
    {
      (*relerr) = relerr_min;
      kflag = 3;
      return 3;
    }

    dt = tout - *t;
    //
    //  Initialization:
    //
    //  Set the initialization completion indicator, INIT;
    //  set the indicator for too many output points, KOP;
    //  evaluate the initial derivatives
    //  set the counter for function evaluations, NFE;
    //  estimate the starting stepsize.
    //
    f1 = new qreal[neqn];
    f2 = new qreal[neqn];
    f3 = new qreal[neqn];
    f4 = new qreal[neqn];
    f5 = new qreal[neqn];

    if ( mflag == 1 )
    {
      init = 0;
      kop = 0;
      QTAIMODEIntegrator::r8_f ( *t, y, yp );
      nfe = 1;

      if ( *t == tout )
      {
        return 2;
      }

    }

    if ( init == 0 )
    {
      init = 1;
      h = r8_abs ( dt );
      toln = 0.0;

      for ( k = 0; k < neqn; k++ )
      {
        tol = (*relerr) * r8_abs ( y[k] ) + abserr;
        if ( 0.0 < tol )
        {
          toln = tol;
          ypk = r8_abs ( yp[k] );
          if ( tol < ypk * pow ( h, 5 ) )
          {
            h = pow ( ( tol / ypk ), 0.2 );
          }
        }
      }

      if ( toln <= 0.0 )
      {
        h = 0.0;
      }

      h = r8_max ( h, 26.0 * eps * r8_max ( r8_abs ( *t ), r8_abs ( dt ) ) );

      if ( flag < 0 )
      {
        flag_save = -2;
      }
      else
      {
        flag_save = 2;
      }
    }
    //
    //  Set stepsize for integration in the direction from T to TOUT.
    //
    h = r8_sign ( dt ) * r8_abs ( h );
    //
    //  Test to see if too may output points are being requested.
    //
    if ( 2.0 * r8_abs ( dt ) <= r8_abs ( h ) )
    {
      kop = kop + 1;
    }
    //
    //  Unnecessary frequency of output.
    //
    if ( kop == 100 )
    {
      kop = 0;
      delete [] f1;
      delete [] f2;
      delete [] f3;
      delete [] f4;
      delete [] f5;
      return 7;
    }
    //
    //  If we are too close to the output point, then simply extrapolate and return.
    //
    if ( r8_abs ( dt ) <= 26.0 * eps * r8_abs ( *t ) )
    {
      *t = tout;
      for ( i = 0; i < neqn; i++ )
      {
        y[i] = y[i] + dt * yp[i];
      }
      QTAIMODEIntegrator::r8_f ( *t, y, yp );
      nfe = nfe + 1;

      delete [] f1;
      delete [] f2;
      delete [] f3;
      delete [] f4;
      delete [] f5;
      return 2;
    }
    //
    //  Initialize the output point indicator.
    //
    output = false;
    //
    //  To avoid premature underflow in the error tolerance function,
    //  scale the error tolerances.
    //
    scale = 2.0 / (*relerr);
    ae = scale * abserr;
    //
    //  Step by step integration.
    //
    for ( ; ; )
    {
      hfaild = false;
      //
      //  Set the smallest allowable stepsize.
      //
      hmin = 26.0 * eps * r8_abs ( *t );
      //
      //  Adjust the stepsize if necessary to hit the output point.
      //
      //  Look ahead two steps to avoid drastic changes in the stepsize and
      //  thus lessen the impact of output points on the code.
      //
      dt = tout - *t;

      if ( 2.0 * r8_abs ( h ) <= r8_abs ( dt ) )
      {
      }
      else
        //
        //  Will the next successful step complete the integration to the output point?
        //
      {
        if ( r8_abs ( dt ) <= r8_abs ( h ) )
        {
          output = true;
          h = dt;
        }
        else
        {
          h = 0.5 * dt;
        }

      }
      //
      //  Here begins the core integrator for taking a single step.
      //
      //  The tolerances have been scaled to avoid premature underflow in
      //  computing the error tolerance function ET.
      //  To avoid problems with zero crossings, relative error is measured
      //  using the average of the magnitudes of the solution at the
      //  beginning and end of a step.
      //  The error estimate formula has been grouped to control loss of
      //  significance.
      //
      //  To distinguish the various arguments, H is not permitted
      //  to become smaller than 26 units of roundoff in T.
      //  Practical limits on the change in the stepsize are enforced to
      //  smooth the stepsize selection process and to avoid excessive
      //  chattering on problems having discontinuities.
      //  To prevent unnecessary failures, the code uses 9/10 the stepsize
      //  it estimates will succeed.
      //
      //  After a step failure, the stepsize is not allowed to increase for
      //  the next attempted step.  This makes the code more efficient on
      //  problems having discontinuities and more effective in general
      //  since local extrapolation is being used and extra caution seems
      //  warranted.
      //
      //  Test the number of derivative function evaluations.
      //  If okay, try to advance the integration from T to T+H.
      //
      for ( ; ; )
      {
        //
        //  Have we done too much work?
        //
        if ( MAXNFE < nfe )
        {
          kflag = 4;
          delete [] f1;
          delete [] f2;
          delete [] f3;
          delete [] f4;
          delete [] f5;
          return 4;
        }
        //
        //  Advance an approximate solution over one step of length H.
        //
        r8_fehl ( neqn, y, *t, h, yp, f1, f2, f3, f4, f5, f1 );
        nfe = nfe + 5;
        //
        //  Compute and test allowable tolerances versus local error estimates
        //  and remove scaling of tolerances.  The relative error is
        //  measured with respect to the average of the magnitudes of the
        //  solution at the beginning and end of the step.
        //
        eeoet = 0.0;

        for ( k = 0; k < neqn; k++ )
        {
          et = r8_abs ( y[k] ) + r8_abs ( f1[k] ) + ae;

          if ( et <= 0.0 )
          {
            delete [] f1;
            delete [] f2;
            delete [] f3;
            delete [] f4;
            delete [] f5;
            return 5;
          }

          ee = r8_abs
               ( ( -2090.0 * yp[k]
                   + ( 21970.0 * f3[k] - 15048.0 * f4[k] )
                   )
                 + ( 22528.0 * f2[k] - 27360.0 * f5[k] )
                            );

          eeoet = r8_max ( eeoet, ee / et );

        }

        esttol = r8_abs ( h ) * eeoet * scale / 752400.0;

        if ( esttol <= 1.0 )
        {
          break;
        }
        //
        //  Unsuccessful step.  Reduce the stepsize, try again.
        //  The decrease is limited to a factor of 1/10.
        //
        hfaild = true;
        output = false;

        if ( esttol < 59049.0 )
        {
          s = 0.9 / pow ( esttol, 0.2 );
        }
        else
        {
          s = 0.1;
        }

        h = s * h;

        if ( r8_abs ( h ) < hmin )
        {
          kflag = 6;
          delete [] f1;
          delete [] f2;
          delete [] f3;
          delete [] f4;
          delete [] f5;
          return 6;
        }

      }
      //
      //  We exited the loop because we took a successful step.
      //  Store the solution for T+H, and evaluate the derivative there.
      //
      *t = *t + h;
      for ( i = 0; i < neqn; i++ )
      {
        y[i] = f1[i];
      }
      QTAIMODEIntegrator::r8_f ( *t, y, yp );
      nfe = nfe + 1;
      //
      //  Choose the next stepsize.  The increase is limited to a factor of 5.
      //  If the step failed, the next stepsize is not allowed to increase.
      //
      if ( 0.0001889568 < esttol )
      {
        s = 0.9 / pow ( esttol, 0.2 );
      }
      else
      {
        s = 5.0;
      }

      if ( hfaild )
      {
        s = r8_min ( s, 1.0 );
      }

      h = r8_sign ( h ) * r8_max ( s * r8_abs ( h ), hmin );
      //
      //  End of core integrator
      //
      //  Should we take another step?
      //
      if ( output )
      {
        *t = tout;
        delete [] f1;
        delete [] f2;
        delete [] f3;
        delete [] f4;
        delete [] f5;
        return 2;
      }

      if ( flag <= 0 )
      {
        delete [] f1;
        delete [] f2;
        delete [] f3;
        delete [] f4;
        delete [] f5;
        return (-2);
      }

    }
# undef MAXNFE
  }
  //****************************************************************************80

  qreal QTAIMODEIntegrator::r8_sign ( qreal x )

  //****************************************************************************80
  //
  //  Purpose:
  //
  //    R8_SIGN returns the sign of an R8.
  //
  //  Licensing:
  //
  //    This code is distributed under the GNU LGPL license.
  //
  //  Modified:
  //
  //    27 March 2004
  //
  //  Author:
  //
  //    John Burkardt
  //
  //  Parameters:
  //
  //    Input, qreal X, the number whose sign is desired.
  //
  //    Output, qreal R8_SIGN, the sign of X.
  //
  {
    if ( x < 0.0 )
    {
      return ( -1.0 );
    }
    else
    {
      return ( +1.0 );
    }
  }
  //****************************************************************************80



} // namespace Avogadro
