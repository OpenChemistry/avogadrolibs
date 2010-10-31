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

/* Based on */

/* Adaptive multidimensional integration of a vector of integrands.
 *
 * Copyright (c) 2005-2009 Steven G. Johnson
 *
 * Portions (see comments) based on HIntLib (also distributed under
 * the GNU GPL, v2 or later), copyright (c) 2002-2005 Rudolf Schuerer.
 *     (http://www.cosy.sbg.ac.at/~rschuer/hintlib/)
 *
 * Portions (see comments) based on GNU GSL (also distributed under
 * the GNU GPL, v2 or later), copyright (c) 1996-2000 Brian Gough.
 *     (http://www.gnu.org/software/gsl/)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef QTAIMCUBATURE_H
#define QTAIMCUBATURE_H

//#ifdef __cplusplus
//extern "C"
//{
//#endif /* __cplusplus */

/* USAGE: Call adapt_integrate with your function as described below.

    To compile a test program, compile cubature.c with
    -DTEST_INTEGRATOR as described at the end. */

/* a vector integrand - evaluates the function at the given point x
   (an array of length ndim) and returns the result in fval (an array
   of length fdim).   The void* parameter is there in case you have
   to pass any additional data through to your function (it corresponds
   to the fdata parameter you pass to adapt_integrate). */
typedef void (*integrand) (unsigned int ndim, const double *x, void *,
         unsigned int fdim, double *fval);

/* a vector integrand of a vector of npt points: x[i*ndim + j] is the
   j-th coordinate of the i-th point, and the k-th function evaluation
   for the i-th point is returned in fval[k*npt + i]. */
typedef void (*integrand_v) (unsigned int ndim, unsigned int npt,
           const double *x, void *,
           unsigned int fdim, double *fval);

/* Integrate the function f from xmin[dim] to xmax[dim], with at most
   maxEval function evaluations (0 for no limit), until the given
   absolute or relative error is achieved.  val returns the integral,
   and err returns the estimate for the absolute error in val; both
   of these are arrays of length fdim, the dimension of the vector
   integrand f(x). The return value of the function is 0 on success
   and non-zero if there  was an error. */
int adapt_integrate(unsigned int fdim, integrand f, void *fdata,
        unsigned int dim, const double *xmin, const double *xmax,
        unsigned int maxEval, double reqAbsError, double reqRelError,
        double *val, double *err);

/* as adapt_integrate, but vectorized integrand */
int adapt_integrate_v(unsigned int fdim, integrand_v f, void *fdata,
          unsigned int dim, const double *xmin, const double *xmax,
         unsigned int maxEval, double reqAbsError, double reqRelError,
          double *val, double *err);

//#ifdef __cplusplus
//}  /* extern "C" */
//#endif /* __cplusplus */

#include "qtaimwavefunction.h"
#include "qtaimwavefunctionevaluator.h"
#include "qtaimcriticalpointlocator.h"
#include "qtaimodeintegrator.h"
#include "qtaimlsodaintegrator.h"
#include "qtaimmathutilities.h"

namespace Avogadro
{

  class QTAIMCubature
  {
  public:
    enum
    {
      ElectronDensity=0,
      ElectronDensityLaplacian=1
    };

    explicit QTAIMCubature(QTAIMWavefunction &wfn, qint64 mode, QList<qint64> basins);
    ~QTAIMCubature();

    void setMode(qint64 mode);

  private:
    QTAIMWavefunction *m_wfn;
    qint64 m_mode;
    QList<qint64> m_basins;

    QString m_temporaryFileName;
    QString temporaryFileName();



  };

} /* namespace Avogadro */

#endif /* QTAIMCUBATURE_H */
