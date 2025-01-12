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

#ifndef QTAIMLSODAINTEGRATOR_H
#define QTAIMLSODAINTEGRATOR_H

#include "qtaimwavefunctionevaluator.h"

#include <QDebug>
#include <QList>
#include <QPair>
#include <QVector3D>

#include <Eigen/Core>

#include <cmath>
#include <cstdio>

namespace Avogadro::QtPlugins {

class QTAIMLSODAIntegrator
{

public:
  enum
  {
    SteepestAscentPathInElectronDensity = 0,
    CMBPMinusThreeGradientInElectronDensity = 1,
    CMBPMinusOneGradientInElectronDensity = 2,
    CMBPPlusOneGradientInElectronDensity = 3,
    CMBPPlusThreeGradientInElectronDensity = 4,
    CMBPMinusThreeGradientInElectronDensityLaplacian = 5,
    CMBPMinusOneGradientInElectronDensityLaplacian = 6,
    CMBPPlusOneGradientInElectronDensityLaplacian = 7,
    CMBPPlusThreeGradientInElectronDensityLaplacian = 8
  };

  explicit QTAIMLSODAIntegrator(QTAIMWavefunctionEvaluator& eval,
                                const qint64 mode);

  QVector3D integrate(QVector3D x0y0z0);

  qint64 status() const { return m_status; }
  const QList<QVector3D> path() const { return m_path; }

  void setBetaSpheres(QList<QPair<QVector3D, qreal>> betaSpheres)
  {
    m_betaSpheres = betaSpheres;
  }
  qint64 associatedSphere() const { return m_associatedSphere; }

private:
  QTAIMWavefunctionEvaluator* m_eval;
  qint64 m_mode;

  qint64 m_status;
  QList<QVector3D> m_path;

  QList<QPair<QVector3D, qreal>> m_betaSpheres;
  qint64 m_associatedSphere;

  // LSODA integrator

  void f(int neq, double t, double* y, double* ydot);

  void daxpy(int n, double da, double* dx, int incx, double* dy, int incy);
  double ddot(int n, double* dx, int incx, double* dy, int incy);
  void dgefa(double** a, int n, int* ipvt, int* info);
  void dgesl(double** a, int n, int* ipvt, double* b, int job);
  void dscal(int n, double da, double* dx, int incx);
  int idamax(int n, double* dx, int incx);

  void terminate(int* istate);
  void terminate2(double* y, double* t);
  void successreturn(double* y, double* t, int itask, int ihit, double tcrit,
                     int* istate);
  void lsoda(int neq, double* y, double* t, double tout, int itol, double* rtol,
             double* atol, int itask, int* istate, int iopt, int jt, int iwork1,
             int iwork2, int iwork5, int iwork6, int iwork7, int iwork8,
             int iwork9, double rwork1, double rwork5, double rwork6,
             double rwork7);
  void stoda(int neq, double* y);
  void ewset(int itol, double* rtol, double* atol, double* ycur);
  void intdy(double t, int k, double* dky, int* iflag);
  void cfode(int meth);
  void scaleh(double* rh, double* pdh);
  void prja(int neq, double* y);
  double vmnorm(int n, double* v, double* w);
  double fnorm(int n, double** a, double* w);
  // double bnorm();
  void correction(int neq, double* y, int* corflag, double pnorm, double* del,
                  double* delp, double* told, int* ncf, double* rh, int* m);
  void corfailure(double* told, double* rh, int* ncf, int* corflag);
  void solsy(double* y);
  void methodswitch(double dsm, double pnorm, double* pdh, double* rh);
  void endstoda();
  void orderswitch(double* rhup, double dsm, double* pdh, double* rh,
                   int* orderflag);
  void resetcoeff();
  void freevectors();

  /* newly added static variables */

  int ml, mu, imxer;
  int mord[3];
  double sqrteta, *yp1, *yp2;
  double sm1[13];

  /* static variables for lsoda() */

  double ccmax, el0, h, hmin, hmxi, hu, rc, tn;
  int illin, init, mxstep, mxhnil, nhnil, ntrep, nslast, nyh, ierpj, iersl,
    jcur, jstart, kflag, l, meth, miter, maxord, maxcor, msbp, mxncf, n, nq,
    nst, nfe, nje, nqu;
  double tsw, pdnorm;
  int ixpr, jtyp, mused, mxordn, mxords;

  /* no static variable for prja(), solsy() */
  /* static variables for stoda() */

  double conit, crate, el[14], elco[13][14], hold, rmax, tesco[13][4];
  int ialth, ipup, lmax, meo, nslp;
  double pdest, pdlast, ratio, cm1[13], cm2[6];
  int icount, irflag;

  /* static variable for block data */

  int mesflg;

  /* static variables for various vectors and the Jacobian. */

  double **yh, **wm, *ewt, *savf, *acor;
  int* ipvt;

  int m_lenyh;
  int m_nyh;
};

} // namespace Avogadro::QtPlugins

#endif // QTAIMLSODAINTEGRATOR_H
