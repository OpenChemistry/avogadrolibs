/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gaussiansettools.h"

#include "cube.h"
#include "gaussianset.h"
#include "molecule.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <vector>

using std::exp;
using std::sqrt;

namespace {

// Shell-major grid evaluators with factored exp() and fused MO coefficients.
// Each function handles the primitive loop and the triple (i,j,k) grid loop
// for one shell type. The MO coefficient is fused directly, so these
// accumulate the shell's contribution to the final MO value into output[].
//
// Parameters:
//   shell  - pre-packed shell metadata
//   mo     - MO index
//   moMat  - MO coefficient matrix
//   gtoA   - primitive exponents (local copy)
//   gtoCN  - normalized contraction coefficients (local copy)
//   dx,dy,dz - 1D displacement arrays from shell center (full grid size)
//   imin..kmax - range-clipped index bounds
//   ny, nz - grid dimensions for index computation
//   output - accumulation buffer (double precision, size nx*ny*nz)

void gridS(const Avogadro::Core::ShellInfo& shell, int mo,
           const Avogadro::MatrixX& moMat, const double* gtoA,
           const double* gtoCN, const double* dx, const double* dy,
           const double* dz, int imin, int imax, int jmin, int jmax, int kmin,
           int kmax, int ny, int nz, double* output)
{
  double moCoeff = moMat(shell.moIndex, mo);
  if (moCoeff == 0.0)
    return;

  std::vector<double> ex(imax - imin + 1);
  std::vector<double> ey(jmax - jmin + 1);
  std::vector<double> ez(kmax - kmin + 1);

  for (unsigned int p = shell.gtoStart; p < shell.gtoEnd; ++p) {
    double alpha = gtoA[p];
    double coeff = gtoCN[shell.cStart + (p - shell.gtoStart)] * moCoeff;

    for (int i = imin; i <= imax; ++i)
      ex[i - imin] = exp(-alpha * dx[i] * dx[i]);
    for (int j = jmin; j <= jmax; ++j)
      ey[j - jmin] = exp(-alpha * dy[j] * dy[j]);
    for (int k = kmin; k <= kmax; ++k)
      ez[k - kmin] = exp(-alpha * dz[k] * dz[k]);

    for (int i = imin; i <= imax; ++i) {
      double cex = coeff * ex[i - imin];
      for (int j = jmin; j <= jmax; ++j) {
        double cexy = cex * ey[j - jmin];
        int base = i * ny * nz + j * nz;
        for (int k = kmin; k <= kmax; ++k) {
          output[base + k] += cexy * ez[k - kmin];
        }
      }
    }
  }
}

void gridP(const Avogadro::Core::ShellInfo& shell, int mo,
           const Avogadro::MatrixX& moMat, const double* gtoA,
           const double* gtoCN, const double* dx, const double* dy,
           const double* dz, int imin, int imax, int jmin, int jmax, int kmin,
           int kmax, int ny, int nz, double* output)
{
  double mo_x = moMat(shell.moIndex + 0, mo);
  double mo_y = moMat(shell.moIndex + 1, mo);
  double mo_z = moMat(shell.moIndex + 2, mo);
  if (mo_x == 0.0 && mo_y == 0.0 && mo_z == 0.0)
    return;

  std::vector<double> ex(imax - imin + 1);
  std::vector<double> ey(jmax - jmin + 1);
  std::vector<double> ez(kmax - kmin + 1);

  for (unsigned int p = shell.gtoStart; p < shell.gtoEnd; ++p) {
    double alpha = gtoA[p];
    unsigned int cOff = shell.cStart + 3 * (p - shell.gtoStart);
    double c_x = gtoCN[cOff + 0] * mo_x;
    double c_y = gtoCN[cOff + 1] * mo_y;
    double c_z = gtoCN[cOff + 2] * mo_z;

    for (int i = imin; i <= imax; ++i)
      ex[i - imin] = exp(-alpha * dx[i] * dx[i]);
    for (int j = jmin; j <= jmax; ++j)
      ey[j - jmin] = exp(-alpha * dy[j] * dy[j]);
    for (int k = kmin; k <= kmax; ++k)
      ez[k - kmin] = exp(-alpha * dz[k] * dz[k]);

    for (int i = imin; i <= imax; ++i) {
      double exi = ex[i - imin];
      double dxi = dx[i];
      for (int j = jmin; j <= jmax; ++j) {
        double exy = exi * ey[j - jmin];
        double dyj = dy[j];
        int base = i * ny * nz + j * nz;
        for (int k = kmin; k <= kmax; ++k) {
          double g = exy * ez[k - kmin];
          output[base + k] += g * (c_x * dxi + c_y * dyj + c_z * dz[k]);
        }
      }
    }
  }
}

void gridD(const Avogadro::Core::ShellInfo& shell, int mo,
           const Avogadro::MatrixX& moMat, const double* gtoA,
           const double* gtoCN, const double* dx, const double* dy,
           const double* dz, int imin, int imax, int jmin, int jmax, int kmin,
           int kmax, int ny, int nz, double* output)
{
  // 6 cartesian D components: xx, yy, zz, xy, xz, yz
  double mo_c[6];
  bool allZero = true;
  for (int c = 0; c < 6; ++c) {
    mo_c[c] = moMat(shell.moIndex + c, mo);
    if (mo_c[c] != 0.0)
      allZero = false;
  }
  if (allZero)
    return;

  std::vector<double> ex(imax - imin + 1);
  std::vector<double> ey(jmax - jmin + 1);
  std::vector<double> ez(kmax - kmin + 1);

  for (unsigned int p = shell.gtoStart; p < shell.gtoEnd; ++p) {
    double alpha = gtoA[p];
    unsigned int cOff = shell.cStart + 6 * (p - shell.gtoStart);
    double c[6];
    for (int n = 0; n < 6; ++n)
      c[n] = gtoCN[cOff + n] * mo_c[n];

    for (int i = imin; i <= imax; ++i)
      ex[i - imin] = exp(-alpha * dx[i] * dx[i]);
    for (int j = jmin; j <= jmax; ++j)
      ey[j - jmin] = exp(-alpha * dy[j] * dy[j]);
    for (int k = kmin; k <= kmax; ++k)
      ez[k - kmin] = exp(-alpha * dz[k] * dz[k]);

    for (int i = imin; i <= imax; ++i) {
      double exi = ex[i - imin];
      double dxi = dx[i], dxi2 = dxi * dxi;
      for (int j = jmin; j <= jmax; ++j) {
        double exy = exi * ey[j - jmin];
        double dyj = dy[j], dyj2 = dyj * dyj;
        double dxidyj = dxi * dyj;
        // Hoist k-independent terms
        double ij_sum = c[0] * dxi2 + c[1] * dyj2 + c[3] * dxidyj;
        int base = i * ny * nz + j * nz;
        for (int k = kmin; k <= kmax; ++k) {
          double dzk = dz[k];
          double g = exy * ez[k - kmin];
          output[base + k] += g * (ij_sum + c[2] * dzk * dzk +
                                   c[4] * dxi * dzk + c[5] * dyj * dzk);
        }
      }
    }
  }
}

void gridD5(const Avogadro::Core::ShellInfo& shell, int mo,
            const Avogadro::MatrixX& moMat, const double* gtoA,
            const double* gtoCN, const double* dx, const double* dy,
            const double* dz, int imin, int imax, int jmin, int jmax, int kmin,
            int kmax, int ny, int nz, double* output)
{
  // 5 spherical D components: d0, d+1, d-1, d+2, d-2
  // Angular: -(xx+yy), xz, yz, xx-yy, xy
  double mo_c[5];
  bool allZero = true;
  for (int c = 0; c < 5; ++c) {
    mo_c[c] = moMat(shell.moIndex + c, mo);
    if (mo_c[c] != 0.0)
      allZero = false;
  }
  if (allZero)
    return;

  std::vector<double> ex(imax - imin + 1);
  std::vector<double> ey(jmax - jmin + 1);
  std::vector<double> ez(kmax - kmin + 1);

  for (unsigned int p = shell.gtoStart; p < shell.gtoEnd; ++p) {
    double alpha = gtoA[p];
    unsigned int cOff = shell.cStart + 5 * (p - shell.gtoStart);
    double c[5];
    for (int n = 0; n < 5; ++n)
      c[n] = gtoCN[cOff + n] * mo_c[n];

    for (int i = imin; i <= imax; ++i)
      ex[i - imin] = exp(-alpha * dx[i] * dx[i]);
    for (int j = jmin; j <= jmax; ++j)
      ey[j - jmin] = exp(-alpha * dy[j] * dy[j]);
    for (int k = kmin; k <= kmax; ++k)
      ez[k - kmin] = exp(-alpha * dz[k] * dz[k]);

    for (int i = imin; i <= imax; ++i) {
      double exi = ex[i - imin];
      double dxi = dx[i], dxi2 = dxi * dxi;
      for (int j = jmin; j <= jmax; ++j) {
        double exy = exi * ey[j - jmin];
        double dyj = dy[j], dyj2 = dyj * dyj;
        // k-independent angular parts
        // d0: zz - r2 = -(xx + yy), d+2: xx - yy, d-2: xy
        double ij_sum =
          c[0] * (-(dxi2 + dyj2)) + c[3] * (dxi2 - dyj2) + c[4] * (dxi * dyj);
        // d+1: xz, d-1: yz — these multiply dz[k]
        double dz_coeff = c[1] * dxi + c[2] * dyj;
        int base = i * ny * nz + j * nz;
        for (int k = kmin; k <= kmax; ++k) {
          double g = exy * ez[k - kmin];
          output[base + k] += g * (ij_sum + dz_coeff * dz[k]);
        }
      }
    }
  }
}

void gridF(const Avogadro::Core::ShellInfo& shell, int mo,
           const Avogadro::MatrixX& moMat, const double* gtoA,
           const double* gtoCN, const double* dx, const double* dy,
           const double* dz, int imin, int imax, int jmin, int jmax, int kmin,
           int kmax, int ny, int nz, double* output)
{
  // 10 cartesian F: xxx,yyy,zzz,xyy,xxy,xxz,xzz,yzz,yyz,xyz (Molden order)
  double mo_c[10];
  bool allZero = true;
  for (int c = 0; c < 10; ++c) {
    mo_c[c] = moMat(shell.moIndex + c, mo);
    if (mo_c[c] != 0.0)
      allZero = false;
  }
  if (allZero)
    return;

  std::vector<double> ex(imax - imin + 1);
  std::vector<double> ey(jmax - jmin + 1);
  std::vector<double> ez(kmax - kmin + 1);

  for (unsigned int p = shell.gtoStart; p < shell.gtoEnd; ++p) {
    double alpha = gtoA[p];
    unsigned int cOff = shell.cStart + 10 * (p - shell.gtoStart);
    double c[10];
    for (int n = 0; n < 10; ++n)
      c[n] = gtoCN[cOff + n] * mo_c[n];

    for (int i = imin; i <= imax; ++i)
      ex[i - imin] = exp(-alpha * dx[i] * dx[i]);
    for (int j = jmin; j <= jmax; ++j)
      ey[j - jmin] = exp(-alpha * dy[j] * dy[j]);
    for (int k = kmin; k <= kmax; ++k)
      ez[k - kmin] = exp(-alpha * dz[k] * dz[k]);

    for (int i = imin; i <= imax; ++i) {
      double exi = ex[i - imin];
      double dxi = dx[i], dxi2 = dxi * dxi, dxi3 = dxi2 * dxi;
      for (int j = jmin; j <= jmax; ++j) {
        double exy = exi * ey[j - jmin];
        double dyj = dy[j], dyj2 = dyj * dyj, dyj3 = dyj2 * dyj;
        // k-independent: xxx, xyy, xxy
        double ij_only =
          c[0] * dxi3 + c[1] * dyj3 + c[3] * dxi * dyj2 + c[4] * dxi2 * dyj;
        // multiply by dz[k]: xxz, xzz->dz^2, yzz->dz^2, yyz, xyz
        double dz1_coeff = c[5] * dxi2 + c[8] * dyj2 + c[9] * dxi * dyj;
        double dz2_coeff = c[6] * dxi + c[7] * dyj;
        int base = i * ny * nz + j * nz;
        for (int k = kmin; k <= kmax; ++k) {
          double dzk = dz[k], dzk2 = dzk * dzk;
          double g = exy * ez[k - kmin];
          output[base + k] += g * (ij_only + dz1_coeff * dzk +
                                   dz2_coeff * dzk2 + c[2] * dzk2 * dzk);
        }
      }
    }
  }
}

void gridF7(const Avogadro::Core::ShellInfo& shell, int mo,
            const Avogadro::MatrixX& moMat, const double* gtoA,
            const double* gtoCN, const double* dx, const double* dy,
            const double* dz, int imin, int imax, int jmin, int jmax, int kmin,
            int kmax, int ny, int nz, double* output)
{
  // 7 spherical F components
  double mo_c[7];
  bool allZero = true;
  for (int n = 0; n < 7; ++n) {
    mo_c[n] = moMat(shell.moIndex + n, mo);
    if (mo_c[n] != 0.0)
      allZero = false;
  }
  if (allZero)
    return;

  static const double root6 = 2.449489742783178;
  static const double root60 = 7.745966692414834;
  static const double root360 = 18.973665961010276;

  std::vector<double> ex(imax - imin + 1);
  std::vector<double> ey(jmax - jmin + 1);
  std::vector<double> ez(kmax - kmin + 1);

  for (unsigned int p = shell.gtoStart; p < shell.gtoEnd; ++p) {
    double alpha = gtoA[p];
    unsigned int cOff = shell.cStart + 7 * (p - shell.gtoStart);
    double c[7];
    for (int n = 0; n < 7; ++n)
      c[n] = gtoCN[cOff + n] * mo_c[n];

    for (int i = imin; i <= imax; ++i)
      ex[i - imin] = exp(-alpha * dx[i] * dx[i]);
    for (int j = jmin; j <= jmax; ++j)
      ey[j - jmin] = exp(-alpha * dy[j] * dy[j]);
    for (int k = kmin; k <= kmax; ++k)
      ez[k - kmin] = exp(-alpha * dz[k] * dz[k]);

    for (int i = imin; i <= imax; ++i) {
      double exi = ex[i - imin];
      double dxi = dx[i], dxi2 = dxi * dxi, dxi3 = dxi2 * dxi;
      for (int j = jmin; j <= jmax; ++j) {
        double exy = exi * ey[j - jmin];
        double dyj = dy[j], dyj2 = dyj * dyj, dyj3 = dyj2 * dyj;
        double xy2sum = dxi2 + dyj2;
        // k-independent: f5 and f6
        double f5 = (15.0 * dxi3 - 45.0 * dxi * dyj2) / root360;
        double f6 = (45.0 * dxi2 * dyj - 15.0 * dyj3) / root360;
        double ij_only = c[5] * f5 + c[6] * f6;
        // dz^1 coefficients
        double dz1_a = -1.5 * xy2sum; // for f0: dz*(dz2 + dz1_a)
        double dz1_f3 = 15.0 * (dxi2 - dyj2) / root60;
        double dz1_f4 = 30.0 * dxi * dyj / root60;
        double dz1_coeff = c[3] * dz1_f3 + c[4] * dz1_f4;
        // f1/f2 prefactors
        double f12_common_ij = -1.5 * (dxi2 + dyj2);
        double f1_dxi = dxi / root6;
        double f2_dyj = dyj / root6;
        int base = i * ny * nz + j * nz;
        for (int k = kmin; k <= kmax; ++k) {
          double dzk = dz[k], dzk2 = dzk * dzk, dzk3 = dzk2 * dzk;
          double g = exy * ez[k - kmin];
          double f0 = dzk3 - 1.5 * (dxi2 * dzk + dyj2 * dzk);
          double common12 = 6.0 * dzk2 + f12_common_ij;
          double f1 = f1_dxi * common12;
          double f2 = f2_dyj * common12;
          output[base + k] +=
            g * (c[0] * f0 + c[1] * f1 + c[2] * f2 + dz1_coeff * dzk + ij_only);
        }
      }
    }
  }
}

void gridG(const Avogadro::Core::ShellInfo& shell, int mo,
           const Avogadro::MatrixX& moMat, const double* gtoA,
           const double* gtoCN, const double* dx, const double* dy,
           const double* dz, int imin, int imax, int jmin, int jmax, int kmin,
           int kmax, int ny, int nz, double* output)
{
  // 15 cartesian G: Molden order
  // xxxx,yyyy,zzzz,xxxy,xxxz,yyyx,yyyz,zzzx,zzzy,xxyy,xxzz,yyzz,xxyz,yyxz,zzxy
  double mo_c[15];
  bool allZero = true;
  for (int n = 0; n < 15; ++n) {
    mo_c[n] = moMat(shell.moIndex + n, mo);
    if (mo_c[n] != 0.0)
      allZero = false;
  }
  if (allZero)
    return;

  std::vector<double> ex(imax - imin + 1);
  std::vector<double> ey(jmax - jmin + 1);
  std::vector<double> ez(kmax - kmin + 1);

  for (unsigned int p = shell.gtoStart; p < shell.gtoEnd; ++p) {
    double alpha = gtoA[p];
    unsigned int cOff = shell.cStart + 15 * (p - shell.gtoStart);
    double c[15];
    for (int n = 0; n < 15; ++n)
      c[n] = gtoCN[cOff + n] * mo_c[n];

    for (int i = imin; i <= imax; ++i)
      ex[i - imin] = exp(-alpha * dx[i] * dx[i]);
    for (int j = jmin; j <= jmax; ++j)
      ey[j - jmin] = exp(-alpha * dy[j] * dy[j]);
    for (int k = kmin; k <= kmax; ++k)
      ez[k - kmin] = exp(-alpha * dz[k] * dz[k]);

    for (int i = imin; i <= imax; ++i) {
      double exi = ex[i - imin];
      double dxi = dx[i], dxi2 = dxi * dxi;
      double dxi3 = dxi2 * dxi, dxi4 = dxi2 * dxi2;
      for (int j = jmin; j <= jmax; ++j) {
        double exy = exi * ey[j - jmin];
        double dyj = dy[j], dyj2 = dyj * dyj;
        double dyj3 = dyj2 * dyj, dyj4 = dyj2 * dyj2;
        // Group by powers of dz
        // dz^0: xxxx, yyyy, xxxy, yyyx, xxyy
        double c0 = c[0] * dxi4 + c[1] * dyj4 + c[3] * dxi3 * dyj +
                    c[5] * dyj3 * dxi + c[9] * dxi2 * dyj2;
        // dz^1: xxxz, yyyz, xxyz, yyxz, zzxy->needs dz^2*xy
        double c1 =
          c[4] * dxi3 + c[6] * dyj3 + c[12] * dxi2 * dyj + c[13] * dyj2 * dxi;
        // dz^2: xxzz, yyzz, zzxy
        double c2 = c[10] * dxi2 + c[11] * dyj2 + c[14] * dxi * dyj;
        // dz^3: zzzx, zzzy
        double c3 = c[7] * dxi + c[8] * dyj;
        // dz^4: zzzz
        double c4 = c[2];
        int base = i * ny * nz + j * nz;
        for (int k = kmin; k <= kmax; ++k) {
          double dzk = dz[k], dzk2 = dzk * dzk;
          double g = exy * ez[k - kmin];
          output[base + k] += g * (c0 + c1 * dzk + c2 * dzk2 + c3 * dzk2 * dzk +
                                   c4 * dzk2 * dzk2);
        }
      }
    }
  }
}

void gridG9(const Avogadro::Core::ShellInfo& shell, int mo,
            const Avogadro::MatrixX& moMat, const double* gtoA,
            const double* gtoCN, const double* dx, const double* dy,
            const double* dz, int imin, int imax, int jmin, int jmax, int kmin,
            int kmax, int ny, int nz, double* output)
{
  // 9 spherical G components
  double mo_c[9];
  bool allZero = true;
  for (int n = 0; n < 9; ++n) {
    mo_c[n] = moMat(shell.moIndex + n, mo);
    if (mo_c[n] != 0.0)
      allZero = false;
  }
  if (allZero)
    return;

  static const double s5 = sqrt(5.0);
  static const double s7 = sqrt(7.0);
  static const double s35 = sqrt(35.0);

  std::vector<double> ex(imax - imin + 1);
  std::vector<double> ey(jmax - jmin + 1);
  std::vector<double> ez(kmax - kmin + 1);

  for (unsigned int p = shell.gtoStart; p < shell.gtoEnd; ++p) {
    double alpha = gtoA[p];
    unsigned int cOff = shell.cStart + 9 * (p - shell.gtoStart);
    double c[9];
    for (int n = 0; n < 9; ++n)
      c[n] = gtoCN[cOff + n] * mo_c[n];

    for (int i = imin; i <= imax; ++i)
      ex[i - imin] = exp(-alpha * dx[i] * dx[i]);
    for (int j = jmin; j <= jmax; ++j)
      ey[j - jmin] = exp(-alpha * dy[j] * dy[j]);
    for (int k = kmin; k <= kmax; ++k)
      ez[k - kmin] = exp(-alpha * dz[k] * dz[k]);

    for (int i = imin; i <= imax; ++i) {
      double exi = ex[i - imin];
      double dxi = dx[i], x2 = dxi * dxi;
      for (int j = jmin; j <= jmax; ++j) {
        double exy = exi * ey[j - jmin];
        double dyj = dy[j], y2 = dyj * dyj;
        double xy2 = x2 + y2;
        // k-independent parts
        double g7 = (x2 * x2 - 6.0 * x2 * y2 + y2 * y2) * (s35 / 8.0);
        double g8 = dxi * dyj * (x2 - y2) * (s35 / 2.0);
        double ij_only = c[7] * g7 + c[8] * g8;
        // Precompute parts for terms depending on dz
        double x2_m_y2 = x2 - y2;
        int base = i * ny * nz + j * nz;
        for (int k = kmin; k <= kmax; ++k) {
          double dzk = dz[k], z2 = dzk * dzk;
          double g0 = exy * ez[k - kmin];
          double r2 = xy2 + z2;
          double g0v = 3.0 * r2 * r2 - 30.0 * r2 * z2 + 35.0 * z2 * z2;
          double g1 = dxi * dzk * (7.0 * z2 - 3.0 * r2) * (s5 / 8.0);
          double g2 = dyj * dzk * (7.0 * z2 - 3.0 * r2) * (s5 / 8.0);
          double g3 = x2_m_y2 * (7.0 * z2 - r2) * (s5 / 4.0);
          double g4 = dxi * dyj * (7.0 * z2 - r2) * (s5 / 2.0);
          double g5 = dxi * dzk * (x2 - 3.0 * y2) * (s7 / 4.0);
          double g6 = dyj * dzk * (3.0 * x2 - y2) * (s7 / 4.0);
          output[base + k] +=
            g0 * (c[0] * g0v * (1.0 / 8.0) + c[1] * g1 + c[2] * g2 + c[3] * g3 +
                  c[4] * g4 + c[5] * g5 + c[6] * g6 + ij_only);
        }
      }
    }
  }
}

} // anonymous namespace

namespace Avogadro::Core {

GaussianSetTools::GaussianSetTools(Molecule* mol) : m_molecule(mol)
{
  if (m_molecule) {
    m_basis = dynamic_cast<GaussianSet*>(m_molecule->basisSet());

    // Initialize the basis set calculation once (normalizes coefficients, etc.)
    // Then build pre-packed shell data for fast evaluation
    if (m_basis) {
      m_basis->initCalculation();
      buildShellData();
    }
  }
}

void GaussianSetTools::buildShellData()
{
  const std::vector<int>& sym = m_basis->symmetry();
  const std::vector<unsigned int>& atomIndices = m_basis->atomIndices();
  const std::vector<unsigned int>& moIndices = m_basis->moIndices();
  const std::vector<unsigned int>& gtoIndices = m_basis->gtoIndices();
  const std::vector<unsigned int>& cIndices = m_basis->cIndices();

  // Take local contiguous copies of exponents and normalized coefficients
  m_gtoA = m_basis->gtoA();
  m_gtoCN = m_basis->gtoCN();

  // Compute atom positions in Bohr (local — only needed during shell setup)
  Index atomsSize = m_molecule->atomCount();
  Eigen::Matrix<double, 3, Eigen::Dynamic> atomPosBohr(3, atomsSize);
  for (Index a = 0; a < atomsSize; ++a)
    atomPosBohr.col(a) = m_molecule->atom(a).position3d() * ANGSTROM_TO_BOHR;

  m_shells.resize(sym.size());
  for (size_t i = 0; i < sym.size(); ++i) {
    ShellInfo& s = m_shells[i];
    s.type = sym[i];
    s.L = symToL[sym[i]];
    s.atomIndex = atomIndices[i];
    s.moIndex = moIndices[i];
    s.gtoStart = gtoIndices[i];
    s.gtoEnd = gtoIndices[i + 1];
    s.cStart = cIndices[i];
    s.nComponents = symToNComp[sym[i]];

    // Cache center in Bohr
    s.centerBohr[0] = atomPosBohr(0, s.atomIndex);
    s.centerBohr[1] = atomPosBohr(1, s.atomIndex);
    s.centerBohr[2] = atomPosBohr(2, s.atomIndex);

    // Calculate per-shell cutoff
    s.cutoffSquared = calculateShellCutoff(s);
  }
}

double GaussianSetTools::calculateShellCutoff(const ShellInfo& shell) const
{
  const double threshold = 0.03 * 0.001; // 0.1% of a typical isovalue
  const double maxDistance = 100.0;

  double maxR2 = 0.0;
  const double coeff = std::abs(m_gtoCN[shell.cStart]);

  for (unsigned int j = shell.gtoStart; j < shell.gtoEnd; ++j) {
    double alpha = m_gtoA[j];
    // Start at the peak of r^L * exp(-alpha * r^2) for L > 0
    double r = std::min(maxDistance, std::sqrt(shell.L / (2.0 * alpha)));
    double value = coeff * std::pow(r, shell.L) * std::exp(-alpha * r * r);

    while (value > threshold && r < maxDistance) {
      r += 0.25;
      value = coeff * std::pow(r, shell.L) * std::exp(-alpha * r * r);
    }

    maxR2 = std::max(maxR2, r * r);
  }

  return maxR2;
}

bool GaussianSetTools::calculateMolecularOrbital(Cube& cube, int moNumber) const
{
  return calculateMolecularOrbitalGrid(cube, moNumber);
}

void GaussianSetTools::evaluateMOGrid(int moIndex, const MatrixX& moMat,
                                      const Vector3& minBohr,
                                      const Vector3& spBohr,
                                      const std::vector<double>& gridX,
                                      const std::vector<double>& gridY,
                                      const std::vector<double>& gridZ, int nx,
                                      int ny, int nz, double* output) const
{
  const double* gtoA = m_gtoA.data();
  const double* gtoCN = m_gtoCN.data();

  // Per-shell displacement arrays (allocated once, reused)
  std::vector<double> dx(nx), dy(ny), dz(nz);

  for (const auto& shell : m_shells) {
    double cutoff = std::sqrt(shell.cutoffSquared);

    // Compute 1D displacements from shell center
    for (int i = 0; i < nx; ++i)
      dx[i] = gridX[i] - shell.centerBohr[0];
    for (int j = 0; j < ny; ++j)
      dy[j] = gridY[j] - shell.centerBohr[1];
    for (int k = 0; k < nz; ++k)
      dz[k] = gridZ[k] - shell.centerBohr[2];

    // Range-clipped index bounds
    int imin = std::max(
      0, static_cast<int>(std::floor(
           (shell.centerBohr[0] - cutoff - minBohr.x()) / spBohr.x())));
    int imax = std::min(
      nx - 1, static_cast<int>(std::ceil(
                (shell.centerBohr[0] + cutoff - minBohr.x()) / spBohr.x())));
    int jmin = std::max(
      0, static_cast<int>(std::floor(
           (shell.centerBohr[1] - cutoff - minBohr.y()) / spBohr.y())));
    int jmax = std::min(
      ny - 1, static_cast<int>(std::ceil(
                (shell.centerBohr[1] + cutoff - minBohr.y()) / spBohr.y())));
    int kmin = std::max(
      0, static_cast<int>(std::floor(
           (shell.centerBohr[2] - cutoff - minBohr.z()) / spBohr.z())));
    int kmax = std::min(
      nz - 1, static_cast<int>(std::ceil(
                (shell.centerBohr[2] + cutoff - minBohr.z()) / spBohr.z())));

    if (imin > imax || jmin > jmax || kmin > kmax)
      continue;

    switch (shell.type) {
      case GaussianSet::S:
        gridS(shell, moIndex, moMat, gtoA, gtoCN, dx.data(), dy.data(),
              dz.data(), imin, imax, jmin, jmax, kmin, kmax, ny, nz, output);
        break;
      case GaussianSet::P:
        gridP(shell, moIndex, moMat, gtoA, gtoCN, dx.data(), dy.data(),
              dz.data(), imin, imax, jmin, jmax, kmin, kmax, ny, nz, output);
        break;
      case GaussianSet::D:
        gridD(shell, moIndex, moMat, gtoA, gtoCN, dx.data(), dy.data(),
              dz.data(), imin, imax, jmin, jmax, kmin, kmax, ny, nz, output);
        break;
      case GaussianSet::D5:
        gridD5(shell, moIndex, moMat, gtoA, gtoCN, dx.data(), dy.data(),
               dz.data(), imin, imax, jmin, jmax, kmin, kmax, ny, nz, output);
        break;
      case GaussianSet::F:
        gridF(shell, moIndex, moMat, gtoA, gtoCN, dx.data(), dy.data(),
              dz.data(), imin, imax, jmin, jmax, kmin, kmax, ny, nz, output);
        break;
      case GaussianSet::F7:
        gridF7(shell, moIndex, moMat, gtoA, gtoCN, dx.data(), dy.data(),
               dz.data(), imin, imax, jmin, jmax, kmin, kmax, ny, nz, output);
        break;
      case GaussianSet::G:
        gridG(shell, moIndex, moMat, gtoA, gtoCN, dx.data(), dy.data(),
              dz.data(), imin, imax, jmin, jmax, kmin, kmax, ny, nz, output);
        break;
      case GaussianSet::G9:
        gridG9(shell, moIndex, moMat, gtoA, gtoCN, dx.data(), dy.data(),
               dz.data(), imin, imax, jmin, jmax, kmin, kmax, ny, nz, output);
        break;
      default:
        break;
    }
  }
}

bool GaussianSetTools::calculateMolecularOrbitalGrid(Cube& cube,
                                                     int moNumber) const
{
  if (moNumber > static_cast<int>(m_basis->molecularOrbitalCount()))
    return false;

  const int nx = cube.nx(), ny = cube.ny(), nz = cube.nz();

  Vector3 minBohr = cube.min() * ANGSTROM_TO_BOHR;
  Vector3 spBohr = cube.spacing() * ANGSTROM_TO_BOHR;

  std::vector<double> gridX(nx), gridY(ny), gridZ(nz);
  for (int i = 0; i < nx; ++i)
    gridX[i] = minBohr.x() + i * spBohr.x();
  for (int j = 0; j < ny; ++j)
    gridY[j] = minBohr.y() + j * spBohr.y();
  for (int k = 0; k < nz; ++k)
    gridZ[k] = minBohr.z() + k * spBohr.z();

  std::vector<double> output(static_cast<size_t>(nx) * ny * nz, 0.0);

  const MatrixX& moMat = m_basis->moMatrix(m_type);
  evaluateMOGrid(moNumber, moMat, minBohr, spBohr, gridX, gridY, gridZ, nx, ny,
                 nz, output.data());

  // Copy results to cube
  for (size_t i = 0; i < output.size(); ++i)
    cube.setValue(static_cast<unsigned int>(i), static_cast<float>(output[i]));

  return true;
}

double GaussianSetTools::calculateMolecularOrbital(const Vector3& position,
                                                   int mo) const
{
  if (mo > static_cast<int>(m_basis->molecularOrbitalCount()))
    return 0.0;

  Eigen::VectorXd values;
  calculateValues(position, values);

  const MatrixX& matrix = m_basis->moMatrix(m_type);

  // Use Eigen's optimized dot product
  return matrix.col(mo).dot(values);
}

bool GaussianSetTools::calculateElectronDensity(Cube& cube) const
{
  return calculateElectronDensityGrid(cube);
}

bool GaussianSetTools::calculateElectronDensityGrid(Cube& cube) const
{
  // Determine occupied MOs and their weights
  // RHF: ρ = 2 · Σ |ψ_i|² for i = 0..n_occ-1
  // UHF/ROHF: ρ = Σ |ψ_i^α|² + Σ |ψ_i^β|²
  struct OccMO
  {
    int index;
    double weight;
    BasisSet::ElectronType type;
  };
  std::vector<OccMO> occupiedMOs;

  ScfType scf = m_basis->scfType();
  const auto& occAlpha = m_basis->moOccupancy(BasisSet::Alpha);
  const auto& occBeta = m_basis->moOccupancy(BasisSet::Beta);
  const auto& occPaired = m_basis->moOccupancy(BasisSet::Paired);

  if (scf == Rhf || scf == Unknown) {
    // Try occupancy data first, fall back to electron count
    if (!occPaired.empty()) {
      for (unsigned int i = 0; i < occPaired.size(); ++i) {
        if (occPaired[i] > 0)
          occupiedMOs.push_back({ static_cast<int>(i),
                                  static_cast<double>(occPaired[i]),
                                  BasisSet::Paired });
      }
    } else {
      unsigned int nOcc = m_basis->electronCount(BasisSet::Paired) / 2;
      for (unsigned int i = 0; i < nOcc; ++i)
        occupiedMOs.push_back({ static_cast<int>(i), 2.0, BasisSet::Paired });
    }
  } else {
    // UHF / ROHF: alpha + beta MOs
    if (!occAlpha.empty()) {
      for (unsigned int i = 0; i < occAlpha.size(); ++i) {
        if (occAlpha[i] > 0)
          occupiedMOs.push_back({ static_cast<int>(i),
                                  static_cast<double>(occAlpha[i]),
                                  BasisSet::Alpha });
      }
    } else {
      unsigned int nAlpha = m_basis->electronCount(BasisSet::Alpha);
      for (unsigned int i = 0; i < nAlpha; ++i)
        occupiedMOs.push_back({ static_cast<int>(i), 1.0, BasisSet::Alpha });
    }
    if (!occBeta.empty()) {
      for (unsigned int i = 0; i < occBeta.size(); ++i) {
        if (occBeta[i] > 0)
          occupiedMOs.push_back({ static_cast<int>(i),
                                  static_cast<double>(occBeta[i]),
                                  BasisSet::Beta });
      }
    } else {
      unsigned int nBeta = m_basis->electronCount(BasisSet::Beta);
      for (unsigned int i = 0; i < nBeta; ++i)
        occupiedMOs.push_back({ static_cast<int>(i), 1.0, BasisSet::Beta });
    }
  }

  if (occupiedMOs.empty()) {
    // Fall back to density matrix path
    const MatrixX& matrix = m_basis->densityMatrix();
    if (matrix.rows() == 0 || matrix.cols() == 0)
      m_basis->generateDensityMatrix();

    int matrixSize = static_cast<int>(m_basis->moMatrix().rows());
    if (matrix.rows() != matrixSize || matrix.cols() != matrixSize)
      return false;

    Eigen::VectorXd values;
    Eigen::VectorXd tmp;
    for (size_t i = 0; i < cube.data()->size(); ++i) {
      Vector3 pos = cube.position(i);
      calculateValues(pos, values);
      tmp.noalias() = matrix * values;
      cube.setValue(i, values.dot(tmp));
    }
    return true;
  }

  const int nx = cube.nx(), ny = cube.ny(), nz = cube.nz();
  const size_t gridSize = static_cast<size_t>(nx) * ny * nz;

  Vector3 minBohr = cube.min() * ANGSTROM_TO_BOHR;
  Vector3 spBohr = cube.spacing() * ANGSTROM_TO_BOHR;

  std::vector<double> gridX(nx), gridY(ny), gridZ(nz);
  for (int i = 0; i < nx; ++i)
    gridX[i] = minBohr.x() + i * spBohr.x();
  for (int j = 0; j < ny; ++j)
    gridY[j] = minBohr.y() + j * spBohr.y();
  for (int k = 0; k < nz; ++k)
    gridZ[k] = minBohr.z() + k * spBohr.z();

  std::vector<double> density(gridSize, 0.0);
  std::vector<double> moGrid(gridSize);

  for (const auto& occ : occupiedMOs) {
    std::fill(moGrid.begin(), moGrid.end(), 0.0);

    const MatrixX& moMat = m_basis->moMatrix(occ.type);
    if (moMat.rows() == 0)
      continue;

    evaluateMOGrid(occ.index, moMat, minBohr, spBohr, gridX, gridY, gridZ, nx,
                   ny, nz, moGrid.data());

    // Accumulate: density += weight * |ψ|²
    double w = occ.weight;
    for (size_t p = 0; p < gridSize; ++p)
      density[p] += w * moGrid[p] * moGrid[p];
  }

  // Copy to cube
  for (size_t i = 0; i < gridSize; ++i)
    cube.setValue(static_cast<unsigned int>(i), static_cast<float>(density[i]));

  return true;
}

double GaussianSetTools::calculateElectronDensity(const Vector3& position) const
{
  const MatrixX& matrix = m_basis->densityMatrix();
  int matrixSize(static_cast<int>(m_basis->moMatrix().rows()));

  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize) {
    return 0.0;
  }

  Eigen::VectorXd values;
  calculateValues(position, values);

  // Compute the quadratic form: v^T * D * v
  // The density matrix is symmetric, so we can use the full matrix multiply
  return values.dot(matrix * values);
}

bool GaussianSetTools::calculateSpinDensity(Cube& cube) const
{
  const MatrixX& matrix = m_basis->spinDensityMatrix();
  int matrixSize = static_cast<int>(m_basis->moMatrix().rows());
  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize)
    return false;

  Eigen::VectorXd values;
  Eigen::VectorXd tmp;

  for (size_t i = 0; i < cube.data()->size(); ++i) {
    Vector3 pos = cube.position(i);
    calculateValues(pos, values);
    tmp.noalias() = matrix * values;
    cube.setValue(i, values.dot(tmp));
  }
  return true;
}

double GaussianSetTools::calculateSpinDensity(const Vector3& position) const
{
  const MatrixX& matrix = m_basis->spinDensityMatrix();
  int matrixSize(static_cast<int>(m_basis->moMatrix().rows()));
  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize) {
    return 0.0;
  }

  Eigen::VectorXd values;
  calculateValues(position, values);

  // Compute the quadratic form: v^T * D * v
  // The spin density matrix is symmetric, so we can use the full matrix
  // multiply
  return values.dot(matrix * values);
}

bool GaussianSetTools::isValid() const
{
  return (m_molecule != nullptr) &&
         (dynamic_cast<GaussianSet*>(m_molecule->basisSet()) != nullptr);
}

inline void GaussianSetTools::calculateValues(const Vector3& position,
                                              Eigen::VectorXd& values) const
{
  // Calculate our position in Bohr
  Vector3 pos(position * ANGSTROM_TO_BOHR);

  // Resize and zero the output vector
  Index matrixSize = m_basis->moMatrix().rows();
  values.setZero(matrixSize);

  // Loop over pre-packed shells, computing delta per-shell from cached centers
  for (const auto& shell : m_shells) {
    Vector3 delta(pos.x() - shell.centerBohr[0], pos.y() - shell.centerBohr[1],
                  pos.z() - shell.centerBohr[2]);
    double dr2_i = delta.squaredNorm();

    // Bail early if the distance to this shell's center is beyond cutoff
    if (dr2_i > shell.cutoffSquared)
      continue;

    switch (shell.type) {
      case GaussianSet::S:
        pointS(shell, dr2_i, values);
        break;
      case GaussianSet::P:
        pointP(shell, delta, dr2_i, values);
        break;
      case GaussianSet::D:
        pointD(shell, delta, dr2_i, values);
        break;
      case GaussianSet::D5:
        pointD5(shell, delta, dr2_i, values);
        break;
      case GaussianSet::F:
        pointF(shell, delta, dr2_i, values);
        break;
      case GaussianSet::F7:
        pointF7(shell, delta, dr2_i, values);
        break;
      case GaussianSet::G:
        pointG(shell, delta, dr2_i, values);
        break;
      case GaussianSet::G9:
        pointG9(shell, delta, dr2_i, values);
        break;
      default:
        // Not handled - return a zero contribution
        ;
    }
  }
}

inline void GaussianSetTools::pointS(const ShellInfo& shell, double dr2,
                                     Eigen::VectorXd& values) const
{
  // S type orbitals - one component
  double tmp = 0.0;
  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    tmp += m_gtoCN[cIndex++] * exp(-m_gtoA[i] * dr2);
  }
  values[shell.moIndex] = tmp;
}

inline void GaussianSetTools::pointP(const ShellInfo& shell,
                                     const Vector3& delta, double dr2,
                                     Eigen::VectorXd& values) const
{
  // P type orbitals have three components
  Vector3 components(Vector3::Zero());

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (unsigned int j = 0; j < 3; ++j) {
      components[j] += m_gtoCN[cIndex++] * tmpGTO;
    }
  }
  for (unsigned int i = 0; i < 3; ++i)
    values[shell.moIndex + i] = components[i] * delta[i];
}

inline void GaussianSetTools::pointD(const ShellInfo& shell,
                                     const Vector3& delta, double dr2,
                                     Eigen::VectorXd& values) const
{
  // D type orbitals have six cartesian components
  double components[6] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double componentsD[6] = { delta.x() * delta.x(),   // xx
                            delta.y() * delta.y(),   // yy
                            delta.z() * delta.z(),   // zz
                            delta.x() * delta.y(),   // xy
                            delta.x() * delta.z(),   // xz
                            delta.y() * delta.z() }; // yz

  for (int i = 0; i < 6; ++i)
    values[shell.moIndex + i] += components[i] * componentsD[i];
}

inline void GaussianSetTools::pointD5(const ShellInfo& shell,
                                      const Vector3& delta, double dr2,
                                      Eigen::VectorXd& values) const
{
  // D type orbitals have five spherical components
  double components[5] = { 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double xx = delta.x() * delta.x();
  double yy = delta.y() * delta.y();
  double zz = delta.z() * delta.z();
  double xy = delta.x() * delta.y();
  double xz = delta.x() * delta.z();
  double yz = delta.y() * delta.z();

  double componentsD[5] = { zz - dr2, // 0
                            xz,       // 1p
                            yz,       // 1n
                            xx - yy,  // 2p
                            xy };     // 2n

  for (int i = 0; i < 5; ++i)
    values[shell.moIndex + i] += componentsD[i] * components[i];
}

inline void GaussianSetTools::pointF(const ShellInfo& shell,
                                     const Vector3& delta, double dr2,
                                     Eigen::VectorXd& values) const
{
  // F type orbitals have 10 cartesian components
  double components[10] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double xxx = delta.x() * delta.x() * delta.x();
  double xxy = delta.x() * delta.x() * delta.y();
  double xxz = delta.x() * delta.x() * delta.z();
  double xyy = delta.x() * delta.y() * delta.y();
  double xyz = delta.x() * delta.y() * delta.z();
  double xzz = delta.x() * delta.z() * delta.z();
  double yyy = delta.y() * delta.y() * delta.y();
  double yyz = delta.y() * delta.y() * delta.z();
  double yzz = delta.y() * delta.z() * delta.z();
  double zzz = delta.z() * delta.z() * delta.z();

  // Molden order
  double componentsF[10] = { xxx, yyy, zzz, xyy, xxy, xxz, xzz, yzz, yyz, xyz };

  for (int i = 0; i < 10; ++i)
    values[shell.moIndex + i] += components[i] * componentsF[i];
}

inline void GaussianSetTools::pointF7(const ShellInfo& shell,
                                      const Vector3& delta, double dr2,
                                      Eigen::VectorXd& values) const
{
  // F type orbitals have 7 spherical components
  double components[7] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double xxx = delta.x() * delta.x() * delta.x();
  double xxy = delta.x() * delta.x() * delta.y();
  double xxz = delta.x() * delta.x() * delta.z();
  double xyy = delta.x() * delta.y() * delta.y();
  double xyz = delta.x() * delta.y() * delta.z();
  double xzz = delta.x() * delta.z() * delta.z();
  double yyy = delta.y() * delta.y() * delta.y();
  double yyz = delta.y() * delta.y() * delta.z();
  double yzz = delta.y() * delta.z() * delta.z();
  double zzz = delta.z() * delta.z() * delta.z();

  /*
  Spherical combinations borrowed from CASINO/Crystal documentation

   linear combination
3,0     z^3 - 3/2 * (x^2z + y^2z)      2z^3 - 3 * (x^2z + y^2z)      * 2
3,1     6 * xz^2 - 3/2 * (x^3 + xy^2)  4xz^2 - x^3 - xy^2            * 2/3
3,-1    6 * yz^2 - 3/2 * (x^2y + y^3)  4yz^2 - x^2y - y^3            * 2/3
3,2     15 * (x^2z - y^2z)             x^2z - y^2z                   * 1/15
3,-2    30 * xyz                       xyz                           * 1/30
3,3     15 * x^3 - 45 * xy^2           x^3 - 3xy^2                   * 1/15
3,-3    45 * x^2y - 15 * y^3           3x^2y - y^3                   * 1/15

final normalization
          (2 - delta_m,0) * (l - |m|)!
*  root  ------------------------------                     (m-dependent)
                (l + m)!
*/
  double root6 = 2.449489742783178;
  double root60 = 7.745966692414834;
  double root360 = 18.973665961010276;
  double componentsF[7] = { zzz - 3.0 / 2.0 * (xxz + yyz),
                            (6.0 * xzz - 3.0 / 2.0 * (xxx + xyy)) / root6,
                            (6.0 * yzz - 3.0 / 2.0 * (xxy + yyy)) / root6,
                            (15.0 * (xxz - yyz)) / root60,
                            (30.0 * xyz) / root60,
                            (15.0 * xxx - 45.0 * xyy) / root360,
                            (45.0 * xxy - 15.0 * yyy) / root360 };

  for (int i = 0; i < 7; ++i)
    values[shell.moIndex + i] += components[i] * componentsF[i];
}

inline void GaussianSetTools::pointG(const ShellInfo& shell,
                                     const Vector3& delta, double dr2,
                                     Eigen::VectorXd& values) const
{
  // G type orbitals have 15 cartesian components
  double components[15] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  const double xxxx = delta.x() * delta.x() * delta.x() * delta.x();
  const double yyyy = delta.y() * delta.y() * delta.y() * delta.y();
  const double zzzz = delta.z() * delta.z() * delta.z() * delta.z();
  const double xxxy = delta.x() * delta.x() * delta.x() * delta.y();
  const double xxxz = delta.x() * delta.x() * delta.x() * delta.z();
  const double yyyx = delta.y() * delta.y() * delta.y() * delta.x();
  const double yyyz = delta.y() * delta.y() * delta.y() * delta.z();
  const double zzzx = delta.z() * delta.z() * delta.z() * delta.x();
  const double zzzy = delta.z() * delta.z() * delta.z() * delta.y();
  const double xxyy = delta.x() * delta.x() * delta.y() * delta.y();
  const double xxzz = delta.x() * delta.x() * delta.z() * delta.z();
  const double yyzz = delta.y() * delta.y() * delta.z() * delta.z();
  const double xxyz = delta.x() * delta.x() * delta.y() * delta.z();
  const double yyxz = delta.y() * delta.y() * delta.x() * delta.z();
  const double zzxy = delta.z() * delta.z() * delta.x() * delta.y();

  // Molden order
  double componentsG[15] = { xxxx, yyyy, zzzz, xxxy, xxxz, yyyx, yyyz, zzzx,
                             zzzy, xxyy, xxzz, yyzz, xxyz, yyxz, zzxy };

  for (int i = 0; i < 15; ++i)
    values[shell.moIndex + i] += components[i] * componentsG[i];
}

inline void GaussianSetTools::pointG9(const ShellInfo& shell,
                                      const Vector3& delta, double dr2,
                                      Eigen::VectorXd& values) const
{
  // G type orbitals have 9 spherical components
  double components[9] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double x2(delta.x() * delta.x()), y2(delta.y() * delta.y()),
    z2(delta.z() * delta.z());

  double componentsG[9] = {
    (3.0 * dr2 * dr2 - 30.0 * dr2 * z2 + 35.0 * z2 * z2) * (1.0 / 8.0),
    delta.x() * delta.z() * (7.0 * z2 - 3.0 * dr2) * (sqrt(5.0) / 8.0),
    delta.y() * delta.z() * (7.0 * z2 - 3.0 * dr2) * (sqrt(5.0) / 8.0),
    (x2 - y2) * (7.0 * z2 - dr2) * (sqrt(5.0) / 4.0),
    delta.x() * delta.y() * (7.0 * z2 - dr2) * (sqrt(5.0) / 2.0),
    delta.x() * delta.z() * (x2 - 3.0 * y2) * (sqrt(7.0) / 4.0),
    delta.y() * delta.z() * (3.0 * x2 - y2) * (sqrt(7.0) / 4.0),
    (x2 * x2 - 6.0 * x2 * y2 + y2 * y2) * (sqrt(35.0) / 8.0),
    delta.x() * delta.y() * (x2 - y2) * (sqrt(35.0) / 2.0)
  };

  for (int i = 0; i < 9; ++i)
    values[shell.moIndex + i] += components[i] * componentsG[i];
}

} // namespace Avogadro::Core
