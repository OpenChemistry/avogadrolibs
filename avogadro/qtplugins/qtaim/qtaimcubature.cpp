/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright (C) 2010 Eric C. Brown

  This source code is released under the GPL v3 or later (the "License").

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
  Street, Fifth Floor, Boston, MA 02110-1301, USA.

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

/* Based on */

/* http://ab-initio.mit.edu/cubature/cubature-20101018.tgz */
/* Adaptive multidimensional integration of a vector of integrands.
 *
 * Copyright (c) 2005-2010 Steven G. Johnson
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

#include <QDataStream>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QTemporaryFile>
#include <QTextStream>

#include <QPair>
#include <QVariantList>
#include <QVector3D>

#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFuture>
#include <QFutureWatcher>
#include <QList>
#include <QProgressDialog>
#include <QTemporaryFile>
#include <QVariant>
#include <QtConcurrent/QtConcurrentMap>

#include <cfloat>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

/* Adaptive multidimensional integration on hypercubes (or, really,
   hyper-rectangles) using cubature rules.

   A cubature rule takes a function and a hypercube and evaluates
   the function at a small number of points, returning an estimate
   of the integral as well as an estimate of the error, and also
   a suggested dimension of the hypercube to subdivide.

   Given such a rule, the adaptive integration is simple:

   1) Evaluate the cubature rule on the hypercube(s).
      Stop if converged.

   2) Pick the hypercube with the largest estimated error,
      and divide it in two along the suggested dimension.

   3) Goto (1).

 The basic algorithm is based on the adaptive cubature described in

     A. C. Genz and A. A. Malik, "An adaptive algorithm for numeric
     integration over an N-dimensional rectangular region,"
     J. Comput. Appl. Math. 6 (4), 295-302 (1980).

 and subsequently extended to integrating a vector of integrands in

     J. Berntsen, T. O. Espelid, and A. Genz, "An adaptive algorithm
     for the approximate calculation of multiple integrals,"
     ACM Trans. Math. Soft. 17 (4), 437-451 (1991).

 Note, however, that we do not use any of code from the above authors
 (in part because their code is Fortran 77, but mostly because it is
 under the restrictive ACM copyright license).  I did make use of some
 GPL code from Rudolf Schuerer's HIntLib and from the GNU Scientific
 Library as listed in the copyright notice above, on the other hand.

 I am also grateful to Dmitry Turbiner <dturbiner@alum.mit.edu>, who
 implemented an initial prototype of the "vectorized" functionality
 for evaluating multiple points in a single call (as opposed to
 multiple functions in a single call).  (Although Dmitry implemented
 a working version, I ended up re-implementing this feature from
 scratch as part of a larger code-cleanup, and in order to have
 a single code path for the vectorized and non-vectorized APIs.  I
 subsequently implemented the algorithm by Gladwell to extract
 even more parallelism by evalutating many hypercubes at once.)

 TODO:

   * Putting these routines into the GNU GSL library would be nice.

   * A Python interface would be nice.  (Also a Matlab interface,
     a GNU Octave interface, ...)

   * For high-dimensional integrals, it would be nice to implement
     a sparse-grid cubature scheme using Clenshaw-Curtis quadrature.
     Currently, for dimensions > 7 or so, quasi Monte Carlo methods win.

   * Berntsen et. al also describe a "two-level" error estimation scheme
     that they claim makes the algorithm more robust.  It might be
     nice to implement this, at least as an option (although I seem
     to remember trying it once and it made the number of evaluations
     substantially worse for my test integrands).

*/

/* USAGE: Call adapt_integrate with your function as described in cubature.h.

    To compile a test program, compile cubature.c with
    -DTEST_INTEGRATOR as described at the end. */

#include "qtaimcubature.h"

using namespace Avogadro::QtPlugins;

/* error return codes */
#define SUCCESS 0
#define FAILURE 1

/***************************************************************************/
/* Basic datatypes */

typedef struct
{
  double val, err;
} esterr;

static double relError(esterr ee)
{
  return (ee.val == 0.0 ? HUGE_VAL : fabs(ee.err / ee.val));
}

static double errMax(unsigned int fdim, const esterr* ee)
{
  double errmax = 0;
  unsigned int k;
  for (k = 0; k < fdim; ++k)
    if (ee[k].err > errmax)
      errmax = ee[k].err;
  return errmax;
}

typedef struct
{
  unsigned int dim;
  double* data; /* length 2*dim = center followed by half-widths */
  double vol;   /* cache volume = product of widths */
} hypercube;

static double compute_vol(const hypercube* h)
{
  unsigned int i;
  double vol = 1;
  for (i = 0; i < h->dim; ++i)
    vol *= 2 * h->data[i + h->dim];
  return vol;
}

static hypercube make_hypercube(unsigned int dim, const double* center,
                                const double* halfwidth)
{
  unsigned int i;
  hypercube h;
  h.dim = dim;
  h.data = (double*)malloc(sizeof(double) * dim * 2);
  h.vol = 0;
  if (h.data) {
    for (i = 0; i < dim; ++i) {
      h.data[i] = center[i];
      h.data[i + dim] = halfwidth[i];
    }
    h.vol = compute_vol(&h);
  }
  return h;
}

static hypercube make_hypercube_range(unsigned int dim, const double* xmin,
                                      const double* xmax)
{
  hypercube h = make_hypercube(dim, xmin, xmax);
  unsigned int i;
  if (h.data) {
    for (i = 0; i < dim; ++i) {
      h.data[i] = 0.5 * (xmin[i] + xmax[i]);
      h.data[i + dim] = 0.5 * (xmax[i] - xmin[i]);
    }
    h.vol = compute_vol(&h);
  }
  return h;
}

static void destroy_hypercube(hypercube* h)
{
  free(h->data);
  h->dim = 0;
}

typedef struct
{
  hypercube h;
  unsigned int splitDim;
  unsigned int fdim; /* dimensionality of vector integrand */
  esterr* ee;        /* array of length fdim */
  double errmax;     /* max ee[k].err */
} region;

static region make_region(const hypercube* h, unsigned int fdim)
{
  region R;
  R.h = make_hypercube(h->dim, h->data, h->data + h->dim);
  R.splitDim = 0;
  R.fdim = fdim;
  R.ee = R.h.data ? (esterr*)malloc(sizeof(esterr) * fdim) : nullptr;
  return R;
}

static void destroy_region(region* R)
{
  destroy_hypercube(&R->h);
  free(R->ee);
  R->ee = nullptr;
}

static int cut_region(region* R, region* R2)
{
  unsigned int d = R->splitDim, dim = R->h.dim;
  *R2 = *R;
  R->h.data[d + dim] *= 0.5;
  R->h.vol *= 0.5;
  R2->h = make_hypercube(dim, R->h.data, R->h.data + dim);
  if (!R2->h.data)
    return FAILURE;
  R->h.data[d] -= R->h.data[d + dim];
  R2->h.data[d] += R->h.data[d + dim];
  R2->ee = (esterr*)malloc(sizeof(esterr) * R2->fdim);
  return R2->ee == nullptr;
}

struct rule_s; /* forward declaration */

typedef int (*evalError_func)(struct rule_s* r, unsigned int fdim,
                              integrand_v f, void* fdata, unsigned int nR,
                              region* R);
typedef void (*destroy_func)(struct rule_s* r);

typedef struct rule_s
{
  unsigned int dim, fdim;   /* the dimensionality & number of functions */
  unsigned int num_points;  /* number of evaluation points */
  unsigned int num_regions; /* max number of regions evaluated at once */
  double* pts;              /* points to eval: num_regions * num_points * dim */
  double* vals;             /* num_regions * num_points * fdim */
  evalError_func evalError;
  destroy_func destroy;
} rule;

static void destroy_rule(rule* r)
{
  if (r) {
    if (r->destroy)
      r->destroy(r);
    free(r->pts);
    free(r);
  }
}

static int alloc_rule_pts(rule* r, unsigned int num_regions)
{
  if (num_regions > r->num_regions) {
    free(r->pts);
    r->pts = r->vals = nullptr;
    r->num_regions = 0;
    num_regions *= 2; /* allocate extra so that
             repeatedly calling alloc_rule_pts with
             growing num_regions only needs
             a logarithmic number of allocations */
    r->pts = (double*)malloc(
      sizeof(double) * (num_regions * r->num_points * (r->dim + r->fdim)));
    if (r->fdim + r->dim > 0 && !r->pts)
      return FAILURE;
    r->vals = r->pts + num_regions * r->num_points * r->dim;
    r->num_regions = num_regions;
  }
  return SUCCESS;
}

static rule* make_rule(size_t sz, /* >= sizeof(rule) */
                       unsigned int dim, unsigned int fdim,
                       unsigned int num_points, evalError_func evalError,
                       destroy_func destroy)
{
  rule* r;

  if (sz < sizeof(rule))
    return nullptr;
  r = (rule*)malloc(sz);
  if (!r)
    return nullptr;
  r->pts = r->vals = nullptr;
  r->num_regions = 0;
  r->dim = dim;
  r->fdim = fdim;
  r->num_points = num_points;
  r->evalError = evalError;
  r->destroy = destroy;
  return r;
}

/* note: all regions must have same fdim */
static int eval_regions(unsigned int nR, region* R, integrand_v f, void* fdata,
                        rule* r)
{
  unsigned int iR;
  if (nR == 0)
    return SUCCESS; /* nothing to evaluate */
  if (r->evalError(r, R->fdim, f, fdata, nR, R))
    return FAILURE;
  for (iR = 0; iR < nR; ++iR)
    R[iR].errmax = errMax(R->fdim, R[iR].ee);
  return SUCCESS;
}

/***************************************************************************/
/* Functions to loop over points in a hypercube. */

/* Based on orbitrule.cpp in HIntLib-0.0.10 */

/* ls0 returns the least-significant 0 bit of n (e.g. it returns
   0 if the LSB is 0, it returns 1 if the 2 LSBs are 01, etcetera). */

static unsigned int ls0(unsigned int n)
{
#if defined(__GNUC__) &&                                                       \
  ((__GNUC__ == 3 && __GNUC_MINOR__ >= 4) || __GNUC__ > 3)
  return __builtin_ctz(~n); /* gcc builtin for version >= 3.4 */
#else
  const unsigned int bits[256] = {
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3,
    0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3,
    0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3,
    0, 1, 0, 2, 0, 1, 0, 7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3,
    0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3,
    0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,
    0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 8,
  };
  unsigned int bit = 0;
  while ((n & 0xff) == 0xff) {
    n >>= 8;
    bit += 8;
  }
  return bit + bits[n & 0xff];
#endif
}

/**
 *  Evaluate the integration points for all 2^n points (+/-r,...+/-r)
 *
 *  A Gray-code ordering is used to minimize the number of coordinate updates
 *  in p, although this doesn't matter as much now that we are saving all pts.
 */
static void evalR_Rfs(double* pts, unsigned int dim, double* p, const double* c,
                      const double* r)
{
  unsigned int i;
  unsigned int signs = 0; /* 0/1 bit = +/- for corresponding element of r[] */

  /* We start with the point where r is ADDed in every coordinate
        (this implies signs=0). */
  for (i = 0; i < dim; ++i)
    p[i] = c[i] + r[i];

  /* Loop through the points in Gray-code ordering */
  for (i = 0;; ++i) {
    unsigned int mask, d;

    memcpy(pts, p, sizeof(double) * dim);
    pts += dim;

    d = ls0(i); /* which coordinate to flip */
    if (d >= dim)
      break;

    /* flip the d-th bit and add/subtract r[d] */
    mask = 1U << d;
    signs ^= mask;
    p[d] = (signs & mask) ? c[d] - r[d] : c[d] + r[d];
  }
}

static void evalRR0_0fs(double* pts, unsigned int dim, double* p,
                        const double* c, const double* r)
{
  unsigned int i, j;

  for (i = 0; i < dim - 1; ++i) {
    p[i] = c[i] - r[i];
    for (j = i + 1; j < dim; ++j) {
      p[j] = c[j] - r[j];
      memcpy(pts, p, sizeof(double) * dim);
      pts += dim;
      p[i] = c[i] + r[i];
      memcpy(pts, p, sizeof(double) * dim);
      pts += dim;
      p[j] = c[j] + r[j];
      memcpy(pts, p, sizeof(double) * dim);
      pts += dim;
      p[i] = c[i] - r[i];
      memcpy(pts, p, sizeof(double) * dim);
      pts += dim;

      p[j] = c[j]; /* Done with j -> Restore p[j] */
    }
    p[i] = c[i]; /* Done with i -> Restore p[i] */
  }
}

static void evalR0_0fs4d(double* pts, unsigned int dim, double* p,
                         const double* c, const double* r1, const double* r2)
{
  unsigned int i;

  memcpy(pts, p, sizeof(double) * dim);
  pts += dim;

  for (i = 0; i < dim; i++) {
    p[i] = c[i] - r1[i];
    memcpy(pts, p, sizeof(double) * dim);
    pts += dim;

    p[i] = c[i] + r1[i];
    memcpy(pts, p, sizeof(double) * dim);
    pts += dim;

    p[i] = c[i] - r2[i];
    memcpy(pts, p, sizeof(double) * dim);
    pts += dim;

    p[i] = c[i] + r2[i];
    memcpy(pts, p, sizeof(double) * dim);
    pts += dim;

    p[i] = c[i];
  }
}

#define num0_0(dim) (1U)
#define numR0_0fs(dim) (2 * (dim))
#define numRR0_0fs(dim) (2 * (dim) * (dim - 1))
#define numR_Rfs(dim) (1U << (dim))

/***************************************************************************/
/* Based on rule75genzmalik.cpp in HIntLib-0.0.10: An embedded
   cubature rule of degree 7 (embedded rule degree 5) due to A. C. Genz
   and A. A. Malik.  See:

         A. C. Genz and A. A. Malik, "An imbedded [sic] family of fully
         symmetric numerical integration rules," SIAM
         J. Numer. Anal. 20 (3), 580-588 (1983).
*/

typedef struct
{
  rule parent;

  /* temporary arrays of length dim */
  double *widthLambda, *widthLambda2, *p;

  /* dimension-dependent constants */
  double weight1, weight3, weight5;
  double weightE1, weightE3;
} rule75genzmalik;

#define real(x) ((double)(x))
#define to_int(n) ((int)(n))

static int isqr(int x)
{
  return x * x;
}

static void destroy_rule75genzmalik(rule* r_)
{
  rule75genzmalik* r = (rule75genzmalik*)r_;
  free(r->p);
}

static int rule75genzmalik_evalError(rule* r_, unsigned int fdim, integrand_v f,
                                     void* fdata, unsigned int nR, region* R)
{
  /* lambda2 = sqrt(9/70), lambda4 = sqrt(9/10), lambda5 = sqrt(9/19) */
  const double lambda2 = 0.3585685828003180919906451539079374954541;
  const double lambda4 = 0.9486832980505137995996680633298155601160;
  const double lambda5 = 0.6882472016116852977216287342936235251269;
  const double weight2 = 980. / 6561.;
  const double weight4 = 200. / 19683.;
  const double weightE2 = 245. / 486.;
  const double weightE4 = 25. / 729.;
  const double ratio = (lambda2 * lambda2) / (lambda4 * lambda4);

  rule75genzmalik* r = (rule75genzmalik*)r_;
  unsigned int i, j, iR, dim = r_->dim, npts = 0;
  double *diff, *pts, *vals;

  if (alloc_rule_pts(r_, nR))
    return FAILURE;
  pts = r_->pts;
  vals = r_->vals;

  for (iR = 0; iR < nR; ++iR) {
    const double* center = R[iR].h.data;
    const double* halfwidth = R[iR].h.data + dim;

    for (i = 0; i < dim; ++i)
      r->p[i] = center[i];

    for (i = 0; i < dim; ++i)
      r->widthLambda2[i] = halfwidth[i] * lambda2;
    for (i = 0; i < dim; ++i)
      r->widthLambda[i] = halfwidth[i] * lambda4;

    /* Evaluate points in the center, in (lambda2,0,...,0) and
       (lambda3=lambda4, 0,...,0).  */
    evalR0_0fs4d(pts + npts * dim, dim, r->p, center, r->widthLambda2,
                 r->widthLambda);
    npts += num0_0(dim) + 2 * numR0_0fs(dim);

    /* Calculate points for (lambda4, lambda4, 0, ...,0) */
    evalRR0_0fs(pts + npts * dim, dim, r->p, center, r->widthLambda);
    npts += numRR0_0fs(dim);

    /* Calculate points for (lambda5, lambda5, ..., lambda5) */
    for (i = 0; i < dim; ++i)
      r->widthLambda[i] = halfwidth[i] * lambda5;
    evalR_Rfs(pts + npts * dim, dim, r->p, center, r->widthLambda);
    npts += numR_Rfs(dim);
  }

  /* Evaluate the integrand function(s) at all the points */
  f(dim, npts, pts, fdata, fdim, vals);

  /* we are done with the points, and so we can re-use the pts
  array to store the maximum difference diff[i] in each dimension
  for each hypercube */
  diff = pts;
  for (i = 0; i < dim * nR; ++i)
    diff[i] = 0;

  for (j = 0; j < fdim; ++j) {
    for (iR = 0; iR < nR; ++iR) {
      double result, res5th;
      double val0, sum2 = 0, sum3 = 0, sum4 = 0, sum5 = 0;
      unsigned int k, k0 = 0;

      /* accumulate j-th function values into j-th integrals
         NOTE: this relies on the ordering of the eval functions
         above, as well as on the internal structure of
         the evalR0_0fs4d function */

      val0 = vals[0]; /* central point */
      k0 += 1;

      for (k = 0; k < dim; ++k) {
        double v0 = vals[k0 + 4 * k];
        double v1 = vals[(k0 + 4 * k) + 1];
        double v2 = vals[(k0 + 4 * k) + 2];
        double v3 = vals[(k0 + 4 * k) + 3];

        sum2 += v0 + v1;
        sum3 += v2 + v3;

        diff[iR * dim + k] +=
          fabs(v0 + v1 - 2 * val0 - ratio * (v2 + v3 - 2 * val0));
      }
      k0 += 4 * k;

      for (k = 0; k < numRR0_0fs(dim); ++k)
        sum4 += vals[k0 + k];
      k0 += k;

      for (k = 0; k < numR_Rfs(dim); ++k)
        sum5 += vals[k0 + k];

      /* Calculate fifth and seventh order results */
      result =
        R[iR].h.vol * (r->weight1 * val0 + weight2 * sum2 + r->weight3 * sum3 +
                       weight4 * sum4 + r->weight5 * sum5);
      res5th = R[iR].h.vol * (r->weightE1 * val0 + weightE2 * sum2 +
                              r->weightE3 * sum3 + weightE4 * sum4);

      R[iR].ee[j].val = result;
      R[iR].ee[j].err = fabs(res5th - result);

      vals += r_->num_points;
    }
  }

  /* figure out dimension to split: */
  for (iR = 0; iR < nR; ++iR) {
    double maxdiff = 0;
    unsigned int dimDiffMax = 0;

    for (i = 0; i < dim; ++i)
      if (diff[iR * dim + i] > maxdiff) {
        maxdiff = diff[iR * dim + i];
        dimDiffMax = i;
      }
    R[iR].splitDim = dimDiffMax;
  }
  return SUCCESS;
}

static rule* make_rule75genzmalik(unsigned int dim, unsigned int fdim)
{
  rule75genzmalik* r;

  if (dim < 2)
    return nullptr; /* this rule does not support 1d integrals */

  /* Because of the use of a bit-field in evalR_Rfs, we are limited
  to be < 32 dimensions (or however many bits are in unsigned int).
  This is not a practical limitation...long before you reach
  32 dimensions, the Genz-Malik cubature becomes excruciatingly
  slow and is superseded by other methods (e.g. Monte-Carlo). */
  if (dim >= sizeof(unsigned int) * 8)
    return nullptr;

  r = (rule75genzmalik*)make_rule(
    sizeof(rule75genzmalik), dim, fdim,
    num0_0(dim) + 2 * numR0_0fs(dim) + numRR0_0fs(dim) + numR_Rfs(dim),
    rule75genzmalik_evalError, destroy_rule75genzmalik);
  if (!r)
    return nullptr;

  r->weight1 =
    (real(12824 - 9120 * to_int(dim) + 400 * isqr(to_int(dim))) / real(19683));
  r->weight3 = real(1820 - 400 * to_int(dim)) / real(19683);
  r->weight5 = real(6859) / real(19683) / real(1U << dim);
  r->weightE1 =
    (real(729 - 950 * to_int(dim) + 50 * isqr(to_int(dim))) / real(729));
  r->weightE3 = real(265 - 100 * to_int(dim)) / real(1458);

  r->p = (double*)malloc(sizeof(double) * dim * 3);
  if (!r->p) {
    destroy_rule((rule*)r);
    return nullptr;
  }
  r->widthLambda = r->p + dim;
  r->widthLambda2 = r->p + 2 * dim;

  return (rule*)r;
}

/***************************************************************************/
/* 1d 15-point Gaussian quadrature rule, based on qk15.c and qk.c in
   GNU GSL (which in turn is based on QUADPACK). */

static int rule15gauss_evalError(rule* r, unsigned int fdim, integrand_v f,
                                 void* fdata, unsigned int nR, region* R)
{
  /* Gauss quadrature weights and kronrod quadrature abscissae and
  weights as evaluated with 80 decimal digit arithmetic by
  L. W. Fullerton, Bell Labs, Nov. 1981. */
  const unsigned int n = 8;
  const double xgk[8] = {
    /* abscissae of the 15-point kronrod rule */
    0.991455371120812639206854697526329, 0.949107912342758524526189684047851,
    0.864864423359769072789712788640926, 0.741531185599394439863864773280788,
    0.586087235467691130294144838258730, 0.405845151377397166906606412076961,
    0.207784955007898467600689403773245, 0.000000000000000000000000000000000
    /* xgk[1], xgk[3], ... abscissae of the 7-point gauss rule.
       xgk[0], xgk[2], ... to optimally extend the 7-point gauss rule */
  };
  static const double wg[4] = {
    /* weights of the 7-point gauss rule */
    0.129484966168869693270611432679082, 0.279705391489276667901467771423780,
    0.381830050505118944950369775488975, 0.417959183673469387755102040816327
  };
  static const double wgk[8] = {
    /* weights of the 15-point kronrod rule */
    0.022935322010529224963732008058970, 0.063092092629978553290700663189204,
    0.104790010322250183839876322541518, 0.140653259715525918745189590510238,
    0.169004726639267902826583426598550, 0.190350578064785409913256402421014,
    0.204432940075298892414161999234649, 0.209482141084727828012999174891714
  };
  unsigned int j, k, iR, npts = 0;
  double *pts, *vals;

  if (alloc_rule_pts(r, nR))
    return FAILURE;
  pts = r->pts;
  vals = r->vals;

  for (iR = 0; iR < nR; ++iR) {
    const double center = R[iR].h.data[0];
    const double halfwidth = R[iR].h.data[1];

    pts[npts++] = center;

    for (j = 0; j < (n - 1) / 2; ++j) {
      int j2 = 2 * j + 1;
      double w = halfwidth * xgk[j2];
      pts[npts++] = center - w;
      pts[npts++] = center + w;
    }
    for (j = 0; j < n / 2; ++j) {
      int j2 = 2 * j;
      double w = halfwidth * xgk[j2];
      pts[npts++] = center - w;
      pts[npts++] = center + w;
    }

    R[iR].splitDim = 0; /* no choice but to divide 0th dimension */
  }

  f(1, npts, pts, fdata, fdim, vals);

  for (k = 0; k < fdim; ++k) {
    for (iR = 0; iR < nR; ++iR) {
      const double halfwidth = R[iR].h.data[1];
      double result_gauss = vals[0] * wg[n / 2 - 1];
      double result_kronrod = vals[0] * wgk[n - 1];
      double result_abs = fabs(result_kronrod);
      double result_asc, mean, err;

      /* accumulate integrals */
      npts = 1;
      for (j = 0; j < (n - 1) / 2; ++j) {
        int j2 = 2 * j + 1;
        double v = vals[npts] + vals[npts + 1];
        result_gauss += wg[j] * v;
        result_kronrod += wgk[j2] * v;
        result_abs += wgk[j2] * (fabs(vals[npts]) + fabs(vals[npts + 1]));
        npts += 2;
      }
      for (j = 0; j < n / 2; ++j) {
        int j2 = 2 * j;
        result_kronrod += wgk[j2] * (vals[npts] + vals[npts + 1]);
        result_abs += wgk[j2] * (fabs(vals[npts]) + fabs(vals[npts + 1]));
        npts += 2;
      }

      /* integration result */
      R[iR].ee[k].val = result_kronrod * halfwidth;

      /* error estimate
      (from GSL, probably dates back to QUADPACK
      ... not completely clear to me why we don't just use
            fabs(result_kronrod - result_gauss) * halfwidth */
      mean = result_kronrod * 0.5;
      result_asc = wgk[n - 1] * fabs(vals[0] - mean);
      npts = 1;
      for (j = 0; j < (n - 1) / 2; ++j) {
        int j2 = 2 * j + 1;
        result_asc +=
          wgk[j2] * (fabs(vals[npts] - mean) + fabs(vals[npts + 1] - mean));
        npts += 2;
      }
      for (j = 0; j < n / 2; ++j) {
        int j2 = 2 * j;
        result_asc +=
          wgk[j2] * (fabs(vals[npts] - mean) + fabs(vals[npts + 1] - mean));
        npts += 2;
      }
      err = fabs(result_kronrod - result_gauss) * halfwidth;
      result_abs *= halfwidth;
      result_asc *= halfwidth;
      if (result_asc != 0 && err != 0) {
        double scale = pow((200 * err / result_asc), 1.5);
        err = (scale < 1) ? result_asc * scale : result_asc;
      }
      if (result_abs > DBL_MIN / (50 * DBL_EPSILON)) {
        double min_err = 50 * DBL_EPSILON * result_abs;
        if (min_err > err)
          err = min_err;
      }
      R[iR].ee[k].err = err;

      /* increment vals to point to next batch of results */
      vals += 15;
    }
  }
  return SUCCESS;
}

static rule* make_rule15gauss(unsigned int dim, unsigned int fdim)
{
  if (dim != 1)
    return nullptr; /* this rule is only for 1d integrals */

  return make_rule(sizeof(rule), dim, fdim, 15, rule15gauss_evalError, nullptr);
}

/***************************************************************************/
/* binary heap implementation (ala _Introduction to Algorithms_ by
   Cormen, Leiserson, and Rivest), for use as a priority queue of
   regions to integrate. */

typedef region heap_item;
#define KEY(hi) ((hi).errmax)

typedef struct
{
  unsigned int n, nalloc;
  heap_item* items;
  unsigned int fdim;
  esterr* ee; /* array of length fdim of the total integrand & error */
} heap;

static void heap_resize(heap* h, unsigned int nalloc)
{
  h->nalloc = nalloc;
  h->items = (heap_item*)realloc(h->items, sizeof(heap_item) * nalloc);
}

static heap heap_alloc(unsigned int nalloc, unsigned int fdim)
{
  heap h;
  unsigned int i;
  h.n = 0;
  h.nalloc = 0;
  h.items = nullptr;
  h.fdim = fdim;
  h.ee = (esterr*)malloc(sizeof(esterr) * fdim);
  if (h.ee) {
    for (i = 0; i < fdim; ++i)
      h.ee[i].val = h.ee[i].err = 0;
    heap_resize(&h, nalloc);
  }
  return h;
}

/* note that heap_free does not deallocate anything referenced by the items */
static void heap_free(heap* h)
{
  h->n = 0;
  heap_resize(h, 0);
  h->fdim = 0;
  free(h->ee);
}

static int heap_push(heap* h, heap_item hi)
{
  int insert;
  unsigned int i, fdim = h->fdim;

  for (i = 0; i < fdim; ++i) {
    h->ee[i].val += hi.ee[i].val;
    h->ee[i].err += hi.ee[i].err;
  }
  insert = h->n;
  if (++(h->n) > h->nalloc) {
    heap_resize(h, h->n * 2);
    if (!h->items)
      return FAILURE;
  }

  while (insert) {
    int parent = (insert - 1) / 2;
    if (KEY(hi) <= KEY(h->items[parent]))
      break;
    h->items[insert] = h->items[parent];
    insert = parent;
  }
  h->items[insert] = hi;
  return SUCCESS;
}

static int heap_push_many(heap* h, unsigned int ni, heap_item* hi)
{
  unsigned int i;
  for (i = 0; i < ni; ++i)
    if (heap_push(h, hi[i]))
      return FAILURE;
  return SUCCESS;
}

static heap_item heap_pop(heap* h)
{
  heap_item ret;
  int i, n, child;

  if (!(h->n)) {
    fprintf(stderr, "attempted to pop an empty heap\n");
    return ret; // error
  }

  ret = h->items[0];
  h->items[i = 0] = h->items[n = --(h->n)];
  while ((child = i * 2 + 1) < n) {
    int largest;
    heap_item swap;

    if (KEY(h->items[child]) <= KEY(h->items[i]))
      largest = i;
    else
      largest = child;
    if (++child < n && KEY(h->items[largest]) < KEY(h->items[child]))
      largest = child;
    if (largest == i)
      break;
    swap = h->items[i];
    h->items[i] = h->items[largest];
    h->items[i = largest] = swap;
  }

  {
    unsigned int i_, fdim = h->fdim;
    for (i_ = 0; i_ < fdim; ++i_) {
      h->ee[i_].val -= ret.ee[i_].val;
      h->ee[i_].err -= ret.ee[i_].err;
    }
  }
  return ret;
}

/***************************************************************************/

/* adaptive integration, analogous to adaptintegrator.cpp in HIntLib */

static int ruleadapt_integrate(rule* r, unsigned int fdim, integrand_v f,
                               void* fdata, const hypercube* h,
                               unsigned int maxEval, double reqAbsError,
                               double reqRelError, double* val, double* err,
                               int parallel)
{
  unsigned int numEval = 0;
  heap regions;
  unsigned int i, j;
  region* R = nullptr; /* array of regions to evaluate */
  unsigned int nR_alloc = 0;
  esterr* ee = nullptr;

  regions = heap_alloc(1, fdim);
  if (!regions.ee || !regions.items)
    goto bad;

  ee = (esterr*)malloc(sizeof(esterr) * fdim);
  if (!ee)
    goto bad;

  nR_alloc = 2;
  R = (region*)malloc(sizeof(region) * nR_alloc);
  if (!R)
    goto bad;
  R[0] = make_region(h, fdim);
  if (!R[0].ee || eval_regions(1, R, f, fdata, r) || heap_push(&regions, R[0]))
    goto bad;
  numEval += r->num_points;

  while (numEval < maxEval || !maxEval) {
    for (j = 0; j < fdim && (regions.ee[j].err <= reqAbsError ||
                             relError(regions.ee[j]) <= reqRelError);
         ++j)
      ;
    if (j == fdim)
      break; /* convergence */

    if (parallel) { /* maximize potential parallelism */
      /* adapted from I. Gladwell, "Vectorization of one
      dimensional quadrature codes," pp. 230--238 in
      _Numerical Integration. Recent Developments,
      Software and Applications_, G. Fairweather and
      P. M. Keast, eds., NATO ASI Series C203, Dordrecht
      (1987), as described in J. M. Bull and
      T. L. Freeman, "Parallel Globally Adaptive
      Algorithms for Multi-dimensional Integration,"
      http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.42.6638
      (1994).

      Basically, this evaluates in one shot all regions
      that *must* be evaluated in order to reduce the
      error to the requested bound: the minimum set of
      largest-error regions whose errors push the total
      error over the bound.

      [Note: Bull and Freeman claim that the Gladwell
      approach is intrinsically inefficient because it
      "requires sorting", and propose an alternative
      algorithm that "only" requires three passes over the
      entire set of regions.  Apparently, they didn't
      realize that one could use a heap data structure, in
      which case the time to pop K biggest-error regions
      out of N is only O(K log N), much better than the
      O(N) cost of the Bull and Freeman algorithm if K <<
      N, and it is also much simpler.] */
      unsigned int nR = 0;
      for (j = 0; j < fdim; ++j)
        ee[j] = regions.ee[j];
      do {
        if (nR + 2 > nR_alloc) {
          nR_alloc = (nR + 2) * 2;
          R = (region*)realloc(R, nR_alloc * sizeof(region));
          if (!R)
            goto bad;
        }
        R[nR] = heap_pop(&regions);
        for (j = 0; j < fdim; ++j)
          ee[j].err -= R[nR].ee[j].err;
        if (cut_region(R + nR, R + nR + 1))
          goto bad;
        numEval += r->num_points * 2;
        nR += 2;
        for (j = 0; j < fdim && (ee[j].err <= reqAbsError ||
                                 relError(ee[j]) <= reqRelError);
             ++j)
          ;
        if (j == fdim)
          break; /* other regions have small errs */
      } while (regions.n > 0 && (numEval < maxEval || !maxEval));
      if (eval_regions(nR, R, f, fdata, r) || heap_push_many(&regions, nR, R))
        goto bad;
    } else {                     /* minimize number of function evaluations */
      R[0] = heap_pop(&regions); /* get worst region */
      if (cut_region(R, R + 1) || eval_regions(2, R, f, fdata, r) ||
          heap_push_many(&regions, 2, R))
        goto bad;
      numEval += r->num_points * 2;
    }
  }

  /* re-sum integral and errors */
  for (j = 0; j < fdim; ++j)
    val[j] = err[j] = 0;
  for (i = 0; i < regions.n; ++i) {
    for (j = 0; j < fdim; ++j) {
      val[j] += regions.items[i].ee[j].val;
      err[j] += regions.items[i].ee[j].err;
    }
    destroy_region(&regions.items[i]);
  }

  /* printf("regions.nalloc = %d\n", regions.nalloc); */
  free(ee);
  heap_free(&regions);
  free(R);
  return SUCCESS;

bad:
  free(ee);
  heap_free(&regions);
  free(R);
  return FAILURE;
}

static int integrate(unsigned int fdim, integrand_v f, void* fdata,
                     unsigned int dim, const double* xmin, const double* xmax,
                     unsigned int maxEval, double reqAbsError,
                     double reqRelError, double* val, double* err, int parallel)
{
  rule* r;
  hypercube h;
  int status;
  unsigned int i;

  if (fdim == 0) /* nothing to do */
    return SUCCESS;
  if (dim == 0) { /* trivial integration */
    f(0, 1, xmin, fdata, fdim, val);
    for (i = 0; i < fdim; ++i)
      err[i] = 0;
    return SUCCESS;
  }
  r = dim == 1 ? make_rule15gauss(dim, fdim) : make_rule75genzmalik(dim, fdim);
  if (!r) {
    for (i = 0; i < fdim; ++i) {
      val[i] = 0;
      err[i] = HUGE_VAL;
    }
    return FAILURE;
  }
  h = make_hypercube_range(dim, xmin, xmax);
  status = !h.data
             ? FAILURE
             : ruleadapt_integrate(r, fdim, f, fdata, &h, maxEval, reqAbsError,
                                   reqRelError, val, err, parallel);
  destroy_hypercube(&h);
  destroy_rule(r);
  return status;
}

int adapt_integrate_v(unsigned int fdim, integrand_v f, void* fdata,
                      unsigned int dim, const double* xmin, const double* xmax,
                      unsigned int maxEval, double reqAbsError,
                      double reqRelError, double* val, double* err)
{
  return integrate(fdim, f, fdata, dim, xmin, xmax, maxEval, reqAbsError,
                   reqRelError, val, err, 1);
}

/* wrapper around non-vectorized integrand */
typedef struct fv_data_s
{
  integrand f;
  void* fdata;
  double* fval1;
} fv_data;
static void fv(unsigned int ndim, unsigned int npt, const double* x, void* d_,
               unsigned int fdim, double* fval)
{
  fv_data* d = (fv_data*)d_;
  double* fval1 = d->fval1;
  unsigned int i, k;
  /* printf("npt = %u\n", npt); */
  for (i = 0; i < npt; ++i) {
    d->f(ndim, x + i * ndim, d->fdata, fdim, fval1);
    for (k = 0; k < fdim; ++k)
      fval[k * npt + i] = fval1[k];
  }
}

int adapt_integrate(unsigned int fdim, integrand f, void* fdata,
                    unsigned int dim, const double* xmin, const double* xmax,
                    unsigned int maxEval, double reqAbsError,
                    double reqRelError, double* val, double* err)
{
  int ret;
  fv_data d;

  if (fdim == 0)
    return SUCCESS; /* nothing to do */

  d.f = f;
  d.fdata = fdata;
  d.fval1 = (double*)malloc(sizeof(double) * fdim);
  if (!d.fval1) {
    unsigned int i;
    for (i = 0; i < fdim; ++i) {
      val[i] = 0;
      err[i] = HUGE_VAL;
    }
    return -2; /* ERROR */
  }
  ret = integrate(fdim, fv, &d, dim, xmin, xmax, maxEval, reqAbsError,
                  reqRelError, val, err, 0);
  free(d.fval1);
  return ret;
}

// TODO: Consider QVariantList. For now, mimic what is known to work.
QList<QVariant> QTAIMEvaluateProperty(QList<QVariant> variantList)
{
  /*
     Order of variantList:
     QString wfnFileName
     qreal x0
     qreal y0
     qreal z0
     qint64 nncp
     qint64 xncp1
     qint64 yncp1
     qint64 zncp1
     qint64 xncp2
     qint64 yncp2
     qint64 zncp2
     ...
     qint64 nmode
     qint64 mode1
     qint64 mode2
     ...
     qint64 nbasin
     qint64 basin1
     qint64 basin2
     ...
  */
  qint64 counter = 0;
  QString wfnFileName = variantList.at(counter).toString();
  counter++;
  qreal x0 = variantList.at(counter).toDouble();
  counter++;
  qreal y0 = variantList.at(counter).toDouble();
  counter++;
  qreal z0 = variantList.at(counter).toDouble();
  counter++;

  qint64 nncp = variantList.at(counter).toLongLong();
  counter++;
  QList<QVector3D> ncpList;
  for (qint64 n = 0; n < nncp; ++n) {
    qreal x = variantList.at(counter).toDouble();
    counter++;
    qreal y = variantList.at(counter).toDouble();
    counter++;
    qreal z = variantList.at(counter).toDouble();
    counter++;

    ncpList.append(QVector3D(x, y, z));
  }

  qint64 nmode = variantList.at(counter).toLongLong();
  counter++;
  QList<qint64> modeList;
  for (qint64 m = 0; m < nmode; ++m) {
    qint64 mode = variantList.at(counter).toLongLong();
    counter++;
    modeList.append(mode);
  }

  qint64 nbasin = variantList.at(counter).toLongLong();
  counter++;
  QList<qint64> basinList;
  for (qint64 b = 0; b < nbasin; ++b) {
    qint64 basin = variantList.at(counter).toLongLong();
    counter++;
    basinList.append(basin);
  }
  QSet<qint64> basinSet = basinList.toSet();

  QTAIMWavefunction wfn;
  wfn.loadFromBinaryFile(wfnFileName);

  QTAIMWavefunctionEvaluator eval(wfn);

  QList<QVariant> valueList;

  double initialElectronDensity =
    eval.electronDensity(Eigen::Vector3d(x0, y0, z0));

  // if less than some small value, then return zero for all integrands.
  if (initialElectronDensity < 1.e-5) {
    for (qint64 m = 0; m < nmode; ++m) {
      qreal zero = 0.0;
      valueList.append(zero);
    }
  } else {
    QList<QPair<QVector3D, qreal>> betaSpheres;
    for (qint64 i = 0; i < nncp; ++i) {
      QPair<QVector3D, qreal> thisBetaSphere;
      thisBetaSphere.first =
        QVector3D(ncpList.at(i).x(), ncpList.at(i).y(), ncpList.at(i).z());
      thisBetaSphere.second = 0.10;
      betaSpheres.append(thisBetaSphere);
    }

    QTAIMLSODAIntegrator ode(eval, 0);
    //  Avogadro::QTAIMODEIntegrator ode(eval,0);

    ode.setBetaSpheres(betaSpheres);

    QVector3D endpoint = ode.integrate(QVector3D(x0, y0, z0));
// QList<QVector3D> path=ode.path();

#define HUGE_REAL_NUMBER 1.e20
    qreal smallestDistance = HUGE_REAL_NUMBER;
    qint64 smallestDistanceIndex = -1;

    for (qint64 n = 0; n < betaSpheres.length(); ++n) {
      Matrix<qreal, 3, 1> a(endpoint.x(), endpoint.y(), endpoint.z());
      Matrix<qreal, 3, 1> b(betaSpheres.at(n).first.x(),
                            betaSpheres.at(n).first.y(),
                            betaSpheres.at(n).first.z());

      qreal distance = QTAIMMathUtilities::distance(a, b);

      if (distance < smallestDistance) {
        smallestDistance = distance;
        smallestDistanceIndex = n;
      }
    }
    qint64 nucleusIndex = smallestDistanceIndex;

    if (basinSet.contains(nucleusIndex)) {
      //      if(nucleusIndex==0)
      //      {
      //        QFile file("/scratch/brown/0.txt");
      //        file.open(QIODevice::WriteOnly | QIODevice::Append);
      //        QTextStream out(&file);
      //        out << x0 << " " << y0 << " " << z0 << "\n";
      //        file.close();
      //      }
      for (qint64 m = 0; m < nmode; ++m) {
        if (modeList.at(m) == 0) {
          valueList.append(eval.electronDensity(Eigen::Vector3d(x0, y0, z0)));
        } else {
          qDebug() << "mode not defined";
          qreal zero = 0.0;
          valueList.append(zero);
        }
      }
    } else {
      for (qint64 m = 0; m < nmode; ++m) {
        qreal zero = 0.0;
        valueList.append(zero);
      }
    }
  }

  return valueList;
}

void property_v(unsigned int /* ndim */, unsigned int npts, const double* xyz,
                void* param, unsigned int /* dim */, double* fval)
{

  QVariantList* paramVariantListPtr = (QVariantList*)param;
  QVariantList paramVariantList = *paramVariantListPtr;

  qint64 counter = 0;
  QString wfnFileName = paramVariantList.at(counter).toString();
  counter++;

  qint64 nncp = paramVariantList.at(counter).toLongLong();
  counter++;
  QList<QVector3D> ncpList;
  for (qint64 i = 0; i < nncp; ++i) {
    qreal x = paramVariantList.at(counter).toDouble();
    counter++;
    qreal y = paramVariantList.at(counter).toDouble();
    counter++;
    qreal z = paramVariantList.at(counter).toDouble();
    counter++;

    ncpList.append(QVector3D(x, y, z));
  }
  qint64 nmode = 1;
  qint64 mode = paramVariantList.at(counter).toLongLong();
  counter++;
  QList<qint64> basinList;
  for (qint64 i = counter; i < paramVariantList.length(); ++i) {
    basinList.append(paramVariantList.at(i).toLongLong());
    counter++;
  }

  // prepare input

  QList<QList<QVariant>> inputList;

  for (unsigned int i = 0; i < npts; ++i) {

    double x0 = xyz[i * 3 + 0];
    double y0 = xyz[i * 3 + 1];
    double z0 = xyz[i * 3 + 2];

    QList<QVariant> variantList;

    variantList.append(wfnFileName);

    variantList.append(x0);
    variantList.append(y0);
    variantList.append(z0);

    variantList.append(nncp);
    for (qint64 n = 0; n < nncp; ++n) {
      variantList.append(ncpList.at(n).x());
      variantList.append(ncpList.at(n).y());
      variantList.append(ncpList.at(n).z());
    }

    variantList.append(nmode); // for now, one mode
    for (qint64 m = 0; m < nmode; ++m) {
      variantList.append(mode);
    }

    qint64 nbasin = basinList.length();
    variantList.append(nbasin);
    for (qint64 b = 0; b < basinList.length(); ++b) {
      variantList.append(basinList.at(b));
    }

    inputList.append(variantList);
  }

  // calculate

  QProgressDialog dialog;
  dialog.setWindowTitle("QTAIM");
  dialog.setLabelText(QString("Atomic Basin Integration"));

  QFutureWatcher<void> futureWatcher;
  QObject::connect(&futureWatcher, SIGNAL(finished()), &dialog, SLOT(reset()));
  QObject::connect(&dialog, SIGNAL(canceled()), &futureWatcher, SLOT(cancel()));
  QObject::connect(&futureWatcher, SIGNAL(progressRangeChanged(int, int)),
                   &dialog, SLOT(setRange(int, int)));
  QObject::connect(&futureWatcher, SIGNAL(progressValueChanged(int)), &dialog,
                   SLOT(setValue(int)));

  QFuture<QList<QVariant>> future =
    QtConcurrent::mapped(inputList, QTAIMEvaluateProperty);
  futureWatcher.setFuture(future);
  dialog.exec();
  futureWatcher.waitForFinished();

  QList<QList<QVariant>> results;
  if (futureWatcher.future().isCanceled()) {
    results.clear();
  } else {
    results = future.results();
  }

  // harvest results
  for (qint64 i = 0; i < npts; ++i) {
    for (qint64 m = 0; m < nmode; ++m) {
      fval[m * nmode + i] = results.at(i).at(m).toDouble();
    }
  }
}

// TODO: Consider QVariantList. For now, mimic what is known to work.
// This version performs integration in Spherical Polar Coordinates.
// Note that the basin limits are not explicitly determined.
QList<QVariant> QTAIMEvaluatePropertyRTP(QList<QVariant> variantList)
{
  /*
     Order of variantList:
     QString wfnFileName
     qreal r0
     qreal t0
     qreal p0
     qint64 nncp
     qint64 xncp1
     qint64 yncp1
     qint64 zncp1
     qint64 xncp2
     qint64 yncp2
     qint64 zncp2
     ...
     qint64 nmode
     qint64 mode1
     qint64 mode2
     ...
     qint64 nbasin
     qint64 basin1
     qint64 basin2
     ...
  */
  qint64 counter = 0;
  QString wfnFileName = variantList.at(counter).toString();
  counter++;
  qreal r0 = variantList.at(counter).toDouble();
  counter++;
  qreal t0 = variantList.at(counter).toDouble();
  counter++;
  qreal p0 = variantList.at(counter).toDouble();
  counter++;

  qint64 nncp = variantList.at(counter).toLongLong();
  counter++;
  QList<QVector3D> ncpList;
  for (qint64 n = 0; n < nncp; ++n) {
    qreal x = variantList.at(counter).toDouble();
    counter++;
    qreal y = variantList.at(counter).toDouble();
    counter++;
    qreal z = variantList.at(counter).toDouble();
    counter++;

    ncpList.append(QVector3D(x, y, z));
  }

  qint64 nmode = variantList.at(counter).toLongLong();
  counter++;
  QList<qint64> modeList;
  for (qint64 m = 0; m < nmode; ++m) {
    qint64 mode = variantList.at(counter).toLongLong();
    counter++;
    modeList.append(mode);
  }

  qint64 nbasin = variantList.at(counter).toLongLong();
  counter++;
  QList<qint64> basinList;
  for (qint64 b = 0; b < nbasin; ++b) {
    qint64 basin = variantList.at(counter).toLongLong();
    counter++;
    basinList.append(basin);
  }
  QSet<qint64> basinSet = basinList.toSet();

  Matrix<qreal, 3, 1> r0t0p0;
  r0t0p0 << r0, t0, p0;
  Matrix<qreal, 3, 1> origin;
  origin << ncpList.at(basinList.at(0)).x(), ncpList.at(basinList.at(0)).y(),
    ncpList.at(basinList.at(0)).z();

  Matrix<qreal, 3, 1> x0y0z0 =
    QTAIMMathUtilities::sphericalToCartesian(r0t0p0, origin);

  qreal x0 = x0y0z0(0);
  qreal y0 = x0y0z0(1);
  qreal z0 = x0y0z0(2);

  QTAIMWavefunction wfn;
  wfn.loadFromBinaryFile(wfnFileName);

  QTAIMWavefunctionEvaluator eval(wfn);

  QList<QVariant> valueList;

  double initialElectronDensity =
    eval.electronDensity(Eigen::Vector3d(x0, y0, z0));

  // if less than some small value, then return zero for all integrands.
  if (initialElectronDensity < 1.e-5) {
    for (qint64 m = 0; m < nmode; ++m) {
      qreal zero = 0.0;
      valueList.append(zero);
    }
  } else {
    QList<QPair<QVector3D, qreal>> betaSpheres;
    for (qint64 i = 0; i < nncp; ++i) {
      QPair<QVector3D, qreal> thisBetaSphere;
      thisBetaSphere.first =
        QVector3D(ncpList.at(i).x(), ncpList.at(i).y(), ncpList.at(i).z());
      thisBetaSphere.second = 0.10;
      betaSpheres.append(thisBetaSphere);
    }

    QTAIMLSODAIntegrator ode(eval, 0);
    //  Avogadro::QTAIMODEIntegrator ode(eval,0);

    ode.setBetaSpheres(betaSpheres);

    QVector3D endpoint = ode.integrate(QVector3D(x0, y0, z0));
// QList<QVector3D> path=ode.path();

#define HUGE_REAL_NUMBER 1.e20
    qreal smallestDistance = HUGE_REAL_NUMBER;
    qint64 smallestDistanceIndex = -1;

    for (qint64 n = 0; n < betaSpheres.length(); ++n) {
      Matrix<qreal, 3, 1> a(endpoint.x(), endpoint.y(), endpoint.z());
      Matrix<qreal, 3, 1> b(betaSpheres.at(n).first.x(),
                            betaSpheres.at(n).first.y(),
                            betaSpheres.at(n).first.z());

      qreal distance = QTAIMMathUtilities::distance(a, b);

      if (distance < smallestDistance) {
        smallestDistance = distance;
        smallestDistanceIndex = n;
      }
    }
    qint64 nucleusIndex = smallestDistanceIndex;

    if (basinSet.contains(nucleusIndex)) {
      //      if(nucleusIndex==0)
      //      {
      //        QFile file("/scratch/brown/0.txt");
      //        file.open(QIODevice::WriteOnly | QIODevice::Append);
      //        QTextStream out(&file);
      //        out << x0 << " " << y0 << " " << z0 << "\n";
      ////        out << r0 << " " << t0 << " " << p0 << "\n";
      //        file.close();
      //      }
      for (qint64 m = 0; m < nmode; ++m) {
        if (modeList.at(m) == 0) {
          valueList.append(

            r0 * r0 * sin(t0) *
            eval.electronDensity(Eigen::Vector3d(x0, y0, z0))

              );
        } else {
          qDebug() << "mode not defined";
          qreal zero = 0.0;
          valueList.append(zero);
        }
      }
    } else {
      for (qint64 m = 0; m < nmode; ++m) {
        qreal zero = 0.0;
        valueList.append(zero);
      }
    }
  }

  return valueList;
}

void property_v_rtp(unsigned int /* ndim */, unsigned int npts,
                    const double* xyz, void* param, unsigned int /* fdim */,
                    double* fval)
{

  QVariantList* paramVariantListPtr = (QVariantList*)param;
  QVariantList paramVariantList = *paramVariantListPtr;

  qint64 counter = 0;
  QString wfnFileName = paramVariantList.at(counter).toString();
  counter++;

  qint64 nncp = paramVariantList.at(counter).toLongLong();
  counter++;
  QList<QVector3D> ncpList;
  for (qint64 i = 0; i < nncp; ++i) {
    qreal x = paramVariantList.at(counter).toDouble();
    counter++;
    qreal y = paramVariantList.at(counter).toDouble();
    counter++;
    qreal z = paramVariantList.at(counter).toDouble();
    counter++;

    ncpList.append(QVector3D(x, y, z));
  }
  qint64 nmode = 1;
  qint64 mode = paramVariantList.at(counter).toLongLong();
  counter++;
  QList<qint64> basinList;
  for (qint64 i = counter; i < paramVariantList.length(); ++i) {
    basinList.append(paramVariantList.at(i).toLongLong());
    counter++;
  }

  // prepare input

  QList<QList<QVariant>> inputList;

  for (unsigned int i = 0; i < npts; ++i) {

    double x0 = xyz[i * 3 + 0];
    double y0 = xyz[i * 3 + 1];
    double z0 = xyz[i * 3 + 2];

    QList<QVariant> variantList;

    variantList.append(wfnFileName);

    variantList.append(x0);
    variantList.append(y0);
    variantList.append(z0);

    variantList.append(nncp);
    for (qint64 n = 0; n < nncp; ++n) {
      variantList.append(ncpList.at(n).x());
      variantList.append(ncpList.at(n).y());
      variantList.append(ncpList.at(n).z());
    }

    variantList.append(nmode); // for now, one mode
    for (qint64 m = 0; m < nmode; ++m) {
      variantList.append(mode);
    }

    qint64 nbasin = basinList.length();
    variantList.append(nbasin);
    for (qint64 b = 0; b < basinList.length(); ++b) {
      variantList.append(basinList.at(b));
    }

    inputList.append(variantList);
  }

  // calculate

  QProgressDialog dialog;
  dialog.setWindowTitle("QTAIM");
  dialog.setLabelText(QString("Atomic Basin Integration"));

  QFutureWatcher<void> futureWatcher;
  QObject::connect(&futureWatcher, SIGNAL(finished()), &dialog, SLOT(reset()));
  QObject::connect(&dialog, SIGNAL(canceled()), &futureWatcher, SLOT(cancel()));
  QObject::connect(&futureWatcher, SIGNAL(progressRangeChanged(int, int)),
                   &dialog, SLOT(setRange(int, int)));
  QObject::connect(&futureWatcher, SIGNAL(progressValueChanged(int)), &dialog,
                   SLOT(setValue(int)));

  QFuture<QList<QVariant>> future =
    QtConcurrent::mapped(inputList, QTAIMEvaluatePropertyRTP);
  futureWatcher.setFuture(future);
  dialog.exec();
  futureWatcher.waitForFinished();

  QList<QList<QVariant>> results;
  if (futureWatcher.future().isCanceled()) {
    results.clear();
  } else {
    results = future.results();
  }

  // harvest results
  for (qint64 i = 0; i < npts; ++i) {
    for (qint64 m = 0; m < nmode; ++m) {
      fval[m * nmode + i] = results.at(i).at(m).toDouble();
    }
  }
}

void property_r(unsigned int ndim, const double* xyz, void* param,
                unsigned int fdim, double* fval)
{

  ndim = ndim;
  fdim = fdim;

  QVariantList* paramVariantListPtr = (QVariantList*)param;
  QVariantList paramVariantList = *paramVariantListPtr;

  qint64 counter = 0;
  QString wfnFileName = paramVariantList.at(counter).toString();
  counter++;

  qreal r = xyz[0];
  qreal t = paramVariantList.at(counter).toDouble();
  counter++;
  qreal p = paramVariantList.at(counter).toDouble();
  counter++;

  qint64 nncp = paramVariantList.at(counter).toLongLong();
  counter++;
  QList<QVector3D> ncpList;
  for (qint64 i = 0; i < nncp; ++i) {
    qreal x = paramVariantList.at(counter).toDouble();
    counter++;
    qreal y = paramVariantList.at(counter).toDouble();
    counter++;
    qreal z = paramVariantList.at(counter).toDouble();
    counter++;

    ncpList.append(QVector3D(x, y, z));
  }
  qint64 nmode = 1;
  qint64 mode = paramVariantList.at(counter).toLongLong();
  counter++;
  QList<qint64> basinList;
  for (qint64 i = counter; i < paramVariantList.length(); ++i) {
    basinList.append(paramVariantList.at(i).toLongLong());
    counter++;
  }

  Matrix<qreal, 3, 1> rtp;
  rtp << r, t, p;
  Matrix<qreal, 3, 1> origin;
  origin << ncpList.at(basinList.at(0)).x(), ncpList.at(basinList.at(0)).y(),
    ncpList.at(basinList.at(0)).z();

  Matrix<qreal, 3, 1> XYZ =
    QTAIMMathUtilities::sphericalToCartesian(rtp, origin);

  qreal x = XYZ(0);
  qreal y = XYZ(1);
  qreal z = XYZ(2);

  // This routine reads the wavefunction file repeatedly.
  // Let's hope that this time is dwarfed by the time
  // taken to delineate the atomic basins in the calling routine.
  QTAIMWavefunction wfn;
  wfn.loadFromBinaryFile(wfnFileName);
  QTAIMWavefunctionEvaluator eval(wfn);

  for (qint64 m = 0; m < nmode; ++m) {
    if (mode == 0) {
      fval[m] = r * r * eval.electronDensity(Eigen::Vector3d(x, y, z));
    }
  }
}

QList<QVariant> QTAIMEvaluatePropertyTP(QList<QVariant> variantList)
{

  /*
     Order of variantList:
     QString wfnFileName
     qreal t
     qreal p
     qint64 nncp
     qint64 xncp1
     qint64 yncp1
     qint64 zncp1
     qint64 xncp2
     qint64 yncp2
     qint64 zncp2
     ...
     qint64 nmode
     qint64 mode1
     qint64 mode2
     ...
     qint64 nbasin
     qint64 basin1
     qint64 basin2
     ...
  */
  qint64 counter = 0;
  QString wfnFileName = variantList.at(counter).toString();
  counter++;
  qreal t = variantList.at(counter).toDouble();
  counter++;
  qreal p = variantList.at(counter).toDouble();
  counter++;

  qint64 nncp = variantList.at(counter).toLongLong();
  counter++;
  QList<QVector3D> ncpList;
  for (qint64 n = 0; n < nncp; ++n) {
    qreal x = variantList.at(counter).toDouble();
    counter++;
    qreal y = variantList.at(counter).toDouble();
    counter++;
    qreal z = variantList.at(counter).toDouble();
    counter++;

    ncpList.append(QVector3D(x, y, z));
  }

  qint64 nmode = variantList.at(counter).toLongLong();
  counter++;
  QList<qint64> modeList;
  for (qint64 m = 0; m < nmode; ++m) {
    qint64 mode = variantList.at(counter).toLongLong();
    counter++;
    modeList.append(mode);
  }

  qint64 nbasin = variantList.at(counter).toLongLong();
  counter++;
  QList<qint64> basinList;
  for (qint64 b = 0; b < nbasin; ++b) {
    qint64 basin = variantList.at(counter).toLongLong();
    counter++;
    basinList.append(basin);
  }
  QSet<qint64> basinSet = basinList.toSet();

  QTAIMWavefunction wfn;
  wfn.loadFromBinaryFile(wfnFileName);
  QTAIMWavefunctionEvaluator eval(wfn);

  // Set up steepest ascent integrator and beta spheres
  QList<QPair<QVector3D, qreal>> betaSpheres;
  for (qint64 i = 0; i < nncp; ++i) {
    QPair<QVector3D, qreal> thisBetaSphere;
    thisBetaSphere.first =
      QVector3D(ncpList.at(i).x(), ncpList.at(i).y(), ncpList.at(i).z());
    thisBetaSphere.second = 0.10;
    betaSpheres.append(thisBetaSphere);
  }

  QTAIMLSODAIntegrator ode(eval, 0);
  //  Avogadro::QTAIMODEIntegrator ode(eval,0);

  ode.setBetaSpheres(betaSpheres);

  // Determine radial basin limit via bisection
  // Bisection Algorithm courtesey of Wikipedia

  qint64 thisBasin = basinList.at(0);
  Matrix<qreal, 3, 1> origin;
  origin << ncpList.at(thisBasin).x(), ncpList.at(thisBasin).y(),
    ncpList.at(thisBasin).z();

  const qreal rmin = betaSpheres.at(thisBasin).second;
  const qreal rmax = 8.0;
  const qreal epsilon = 1.e-3;

  qreal left = rmin;
  qreal right = rmax;

  Matrix<qreal, 3, 1> rtpl;
  rtpl << left, t, p;
  Matrix<qreal, 3, 1> xyzl =
    QTAIMMathUtilities::sphericalToCartesian(rtpl, origin);

  qreal fleft;
  qreal x = xyzl(0);
  qreal y = xyzl(1);
  qreal z = xyzl(2);
  qreal leftElectronDensity = eval.electronDensity(Eigen::Vector3d(x, y, z));

  if (leftElectronDensity < 1.e-5) {
    fleft = -1.0;
  } else {
    QVector3D endpoint = ode.integrate(QVector3D(x, y, z));

#define HUGE_REAL_NUMBER 1.e20
    qreal smallestDistance = HUGE_REAL_NUMBER;
    qint64 smallestDistanceIndex = -1;

    for (qint64 n = 0; n < betaSpheres.length(); ++n) {
      Matrix<qreal, 3, 1> a(endpoint.x(), endpoint.y(), endpoint.z());
      Matrix<qreal, 3, 1> b(betaSpheres.at(n).first.x(),
                            betaSpheres.at(n).first.y(),
                            betaSpheres.at(n).first.z());

      qreal distance = QTAIMMathUtilities::distance(a, b);

      if (distance < smallestDistance) {
        smallestDistance = distance;
        smallestDistanceIndex = n;
      }
    }
    qint64 nucleusIndex = smallestDistanceIndex;

    if (thisBasin == nucleusIndex) {
      fleft = leftElectronDensity;
    } else {
      fleft = -1.0;
    }
  }

  Matrix<qreal, 3, 1> rtpr;
  rtpr << right, t, p;
  Matrix<qreal, 3, 1> xyzr =
    QTAIMMathUtilities::sphericalToCartesian(rtpr, origin);

  qreal fright;
  x = xyzr(0);
  y = xyzr(1);
  z = xyzr(2);
  qreal rightElectronDensity = eval.electronDensity(Eigen::Vector3d(x, y, z));

  if (rightElectronDensity < 1.e-5) {
    fright = -1.0;
  } else {
    QVector3D endpoint = ode.integrate(QVector3D(x, y, z));

#define HUGE_REAL_NUMBER 1.e20
    qreal smallestDistance = HUGE_REAL_NUMBER;
    qint64 smallestDistanceIndex = -1;

    for (qint64 n = 0; n < betaSpheres.length(); ++n) {
      Matrix<qreal, 3, 1> a(endpoint.x(), endpoint.y(), endpoint.z());
      Matrix<qreal, 3, 1> b(betaSpheres.at(n).first.x(),
                            betaSpheres.at(n).first.y(),
                            betaSpheres.at(n).first.z());

      qreal distance = QTAIMMathUtilities::distance(a, b);

      if (distance < smallestDistance) {
        smallestDistance = distance;
        smallestDistanceIndex = n;
      }
    }
    qint64 nucleusIndex = smallestDistanceIndex;

    if (thisBasin == nucleusIndex) {
      fright = rightElectronDensity;
    } else {
      fright = -1.0;
    }
  }

  if (fleft > 0.0 && fright > 0.0) {
    qDebug() << "error in bisection: both values positive.";
  }

  qreal rf(0.0);
  while (fabs(right - left) > 2.0 * epsilon) {

    qreal midpoint = (right + left) / 2.0;
    rf = midpoint;

    //    qDebug() << left << midpoint << right ;

    Matrix<qreal, 3, 1> rtpm;
    rtpm << midpoint, t, p;
    Matrix<qreal, 3, 1> xyzm =
      QTAIMMathUtilities::sphericalToCartesian(rtpm, origin);

    qreal fmidpoint;
    x = xyzm(0);
    y = xyzm(1);
    z = xyzm(2);
    qreal midpointElectronDensity =
      eval.electronDensity(Eigen::Vector3d(x, y, z));

    if (midpointElectronDensity < 1.e-5) {
      fmidpoint = -1.0;
    } else {
      QVector3D endpoint = ode.integrate(QVector3D(x, y, z));

#define HUGE_REAL_NUMBER 1.e20
      qreal smallestDistance = HUGE_REAL_NUMBER;
      qint64 smallestDistanceIndex = -1;

      for (qint64 n = 0; n < betaSpheres.length(); ++n) {
        Matrix<qreal, 3, 1> a(endpoint.x(), endpoint.y(), endpoint.z());
        Matrix<qreal, 3, 1> b(betaSpheres.at(n).first.x(),
                              betaSpheres.at(n).first.y(),
                              betaSpheres.at(n).first.z());

        qreal distance = QTAIMMathUtilities::distance(a, b);

        if (distance < smallestDistance) {
          smallestDistance = distance;
          smallestDistanceIndex = n;
        }
      }
      qint64 nucleusIndex = smallestDistanceIndex;

      if (thisBasin == nucleusIndex) {
        fmidpoint = midpointElectronDensity;
      } else {
        fmidpoint = -1.0;
      }
    }

    if ((fleft * fmidpoint) < 0) {
      right = midpoint;
      fright = fmidpoint;
    } else if ((fright * fmidpoint) < 0) {
      left = midpoint;
      fleft = fmidpoint;
    } else {
      goto endOfBisection;
    }
  }
endOfBisection:

  // Integration over r
  unsigned int fdim = 1;
  double* val;
  double* err;
  val = (double*)malloc(sizeof(double) * fdim);
  err = (double*)malloc(sizeof(double) * fdim);

  double tol = 1.e-6;
  unsigned int maxEval = 0;

  unsigned int dim = 1;

  double* xmin;
  double* xmax;
  xmin = (double*)malloc(dim * sizeof(double));
  xmax = (double*)malloc(dim * sizeof(double));

  xmin[0] = 0.0;
  xmax[0] = rf;

  QVariantList paramVariantList;
  paramVariantList.append(wfnFileName);
  paramVariantList.append(t);
  paramVariantList.append(p);
  paramVariantList.append(
    ncpList.length()); // number of nuclear critical points
  for (qint64 j = 0; j < ncpList.length(); ++j) {
    paramVariantList.append(ncpList.at(j).x());
    paramVariantList.append(ncpList.at(j).y());
    paramVariantList.append(ncpList.at(j).z());
  }
  paramVariantList.append(0);               // mode
  paramVariantList.append(basinList.at(0)); // basin

  //  qDebug() << "Into R with rf=" << rf;
  adapt_integrate(fdim, property_r, &paramVariantList, dim, xmin, xmax, maxEval,
                  tol, 0, val, err);
  //  qDebug() << "Out of R with val=" << val[0] << "err=" << err[0];
  qreal Rval = val[0];

  free(xmin);
  free(xmax);
  free(val);
  free(err);

  //  QList<QVariant> variantList;

  variantList.append(sin(t) * Rval);

  //  qDebug() << rf << t << p << sin(t) * Rval;

  return variantList;
}

void property_v_tp(unsigned int /* ndim */, unsigned int npts,
                   const double* xyz, void* param, unsigned int /* fdim */,
                   double* fval)
{

  QVariantList* paramVariantListPtr = (QVariantList*)param;
  QVariantList paramVariantList = *paramVariantListPtr;

  qint64 counter = 0;
  QString wfnFileName = paramVariantList.at(counter).toString();
  counter++;

  qint64 nncp = paramVariantList.at(counter).toLongLong();
  counter++;
  QList<QVector3D> ncpList;
  for (qint64 i = 0; i < nncp; ++i) {
    qreal x = paramVariantList.at(counter).toDouble();
    counter++;
    qreal y = paramVariantList.at(counter).toDouble();
    counter++;
    qreal z = paramVariantList.at(counter).toDouble();
    counter++;

    ncpList.append(QVector3D(x, y, z));
  }
  qint64 nmode = 1;
  qint64 mode = paramVariantList.at(counter).toLongLong();
  counter++;
  QList<qint64> basinList;
  for (qint64 i = counter; i < paramVariantList.length(); ++i) {
    basinList.append(paramVariantList.at(i).toLongLong());
    counter++;
  }

  // prepare input

  QList<QList<QVariant>> inputList;

  for (unsigned int i = 0; i < npts; ++i) {

    double t = xyz[i * 2 + 0];
    double p = xyz[i * 2 + 1];

    QList<QVariant> variantList;

    variantList.append(wfnFileName);

    variantList.append(t);
    variantList.append(p);

    variantList.append(nncp);
    for (qint64 n = 0; n < nncp; ++n) {
      variantList.append(ncpList.at(n).x());
      variantList.append(ncpList.at(n).y());
      variantList.append(ncpList.at(n).z());
    }

    variantList.append(nmode); // for now, one mode
    for (qint64 m = 0; m < nmode; ++m) {
      variantList.append(mode);
    }

    qint64 nbasin = basinList.length();
    variantList.append(nbasin);
    for (qint64 b = 0; b < basinList.length(); ++b) {
      variantList.append(basinList.at(b));
    }

    inputList.append(variantList);
  }

  // calculate

  QProgressDialog dialog;
  dialog.setWindowTitle("QTAIM");
  dialog.setLabelText(QString("Atomic Basin Integration"));

  QFutureWatcher<void> futureWatcher;
  QObject::connect(&futureWatcher, SIGNAL(finished()), &dialog, SLOT(reset()));
  QObject::connect(&dialog, SIGNAL(canceled()), &futureWatcher, SLOT(cancel()));
  QObject::connect(&futureWatcher, SIGNAL(progressRangeChanged(int, int)),
                   &dialog, SLOT(setRange(int, int)));
  QObject::connect(&futureWatcher, SIGNAL(progressValueChanged(int)), &dialog,
                   SLOT(setValue(int)));

  QFuture<QList<QVariant>> future =
    QtConcurrent::mapped(inputList, QTAIMEvaluatePropertyTP);
  futureWatcher.setFuture(future);
  dialog.exec();
  futureWatcher.waitForFinished();

  QList<QList<QVariant>> results;
  if (futureWatcher.future().isCanceled()) {
    results.clear();
  } else {
    results = future.results();
  }

  // harvest results
  //  qDebug() << "results=" << results;
  for (qint64 i = 0; i < npts; ++i) {
    for (qint64 m = 0; m < nmode; ++m) {
      fval[m * nmode + i] = results.at(i).at(m).toDouble();
    }
  }
}

namespace Avogadro {
namespace QtPlugins {

QTAIMCubature::QTAIMCubature(QTAIMWavefunction& wfn)
{

  m_wfn = &wfn;

  m_temporaryFileName = QTAIMCubature::temporaryFileName();
  m_wfn->saveToBinaryFile(m_temporaryFileName);

  // Instantiate a Critical Point Locator
  QTAIMCriticalPointLocator cpl(wfn);

  // Locate the Nuclear Critical Points
  cpl.locateNuclearCriticalPoints();

  // QLists of results
  m_ncpList = cpl.nuclearCriticalPoints();
}

QList<QPair<qreal, qreal>> QTAIMCubature::integrate(qint64 mode,
                                                    QList<qint64> basins)
{

  QList<QPair<qreal, qreal>> value;

  m_mode = mode;
  m_basins = basins;

  double tol = 1.e-2;
  unsigned int maxEval = 0;

  bool threeDimensionalIntegration = false;
  bool cartesianIntegrationLimits = false;

  unsigned int fdim = 1;
  double* val;
  double* err;
  val = (double*)malloc(sizeof(double) * fdim);
  err = (double*)malloc(sizeof(double) * fdim);

  for (qint64 i = 0; i < m_basins.length(); ++i) {
    if (threeDimensionalIntegration) {

      unsigned int dim = 3;

      double* xmin;
      double* xmax;
      xmin = (double*)malloc(dim * sizeof(double));
      xmax = (double*)malloc(dim * sizeof(double));

      if (cartesianIntegrationLimits) {

        // shift origin of the integration to the nuclear coordinates of the ith
        // nucleus.

        xmin[0] = -8. + m_ncpList.at(i).x();
        xmax[0] = 8. + m_ncpList.at(i).x();
        xmin[1] = -8. + m_ncpList.at(i).y();
        xmax[1] = 8. + m_ncpList.at(i).y();
        xmin[2] = -8. + m_ncpList.at(i).z();
        xmax[2] = 8. + m_ncpList.at(i).z();

        QVariantList paramVariantList;
        paramVariantList.append(m_temporaryFileName);

        paramVariantList.append(
          m_ncpList.length()); // number of nuclear critical points
        for (qint64 j = 0; j < m_ncpList.length(); ++j) {
          paramVariantList.append(m_ncpList.at(j).x());
          paramVariantList.append(m_ncpList.at(j).y());
          paramVariantList.append(m_ncpList.at(j).z());
        }
        paramVariantList.append(0);            // mode
        paramVariantList.append(basins.at(i)); // basin

        adapt_integrate_v(fdim, property_v, &paramVariantList, dim, xmin, xmax,
                          maxEval, tol, 0, val, err);

      } else {
        const qreal pi = 4.0 * atan(1.0);

        xmin[0] = 0.;
        xmax[0] = 8.;
        xmin[1] = 0.;
        xmax[1] = pi;
        xmin[2] = 0.;
        xmax[2] = 2.0 * pi;

        QVariantList paramVariantList;
        paramVariantList.append(m_temporaryFileName);

        paramVariantList.append(
          m_ncpList.length()); // number of nuclear critical points
        for (qint64 j = 0; j < m_ncpList.length(); ++j) {
          paramVariantList.append(m_ncpList.at(j).x());
          paramVariantList.append(m_ncpList.at(j).y());
          paramVariantList.append(m_ncpList.at(j).z());
        }
        paramVariantList.append(0);            // mode
        paramVariantList.append(basins.at(i)); // basin

        adapt_integrate_v(fdim, property_v_rtp, &paramVariantList, dim, xmin,
                          xmax, maxEval, tol, 0, val, err);
      }

      free(xmin);
      free(xmax);

    } else {
      unsigned int dim = 2;

      double* xmin;
      double* xmax;
      xmin = (double*)malloc(dim * sizeof(double));
      xmax = (double*)malloc(dim * sizeof(double));

      const qreal pi = 4.0 * atan(1.0);

      xmin[0] = 0.;
      xmax[0] = pi;
      xmin[1] = 0.;
      xmax[1] = 2.0 * pi;

      QVariantList paramVariantList;
      paramVariantList.append(m_temporaryFileName);

      paramVariantList.append(
        m_ncpList.length()); // number of nuclear critical points
      for (qint64 j = 0; j < m_ncpList.length(); ++j) {
        paramVariantList.append(m_ncpList.at(j).x());
        paramVariantList.append(m_ncpList.at(j).y());
        paramVariantList.append(m_ncpList.at(j).z());
      }
      paramVariantList.append(0);            // mode
      paramVariantList.append(basins.at(i)); // basin

      adapt_integrate_v(fdim, property_v_tp, &paramVariantList, dim, xmin, xmax,
                        maxEval, tol, 0, val, err);

      free(xmin);
      free(xmax);
    }

    qDebug() << "basin=" << basins.at(i) + 1 << "value= " << val[0]
             << "err=" << err[0];

    QPair<qreal, qreal> thisPair;
    thisPair.first = val[0];
    thisPair.second = err[0];

    value.append(thisPair);
  }

  free(val);
  free(err);

  return value;
}

QTAIMCubature::~QTAIMCubature()
{
  if (QFile::exists(m_temporaryFileName)) {
    QFile::remove(m_temporaryFileName);
  }
}

void QTAIMCubature::setMode(qint64 mode)
{
  m_mode = mode;
}

QString QTAIMCubature::temporaryFileName()
{
  QTemporaryFile temporaryFile;
  temporaryFile.open();
  QString tempFileName = temporaryFile.fileName();
  temporaryFile.close();
  temporaryFile.remove();

  // wait for temporary file to be deleted
  QDir dir;
  do {
    // Nothing
  } while (dir.exists(tempFileName));

  return tempFileName;
}

} // end namespace QtPlugins
} // end namespace Avogadro
