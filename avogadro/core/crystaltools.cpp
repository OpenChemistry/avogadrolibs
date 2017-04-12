/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "crystaltools.h"

#include "molecule.h"
#include "unitcell.h"

#include <algorithm>
#include <iostream>

namespace Avogadro {
namespace Core {

namespace {
struct WrapAtomsToCellFunctor
{
  const UnitCell& unitCell;

  WrapAtomsToCellFunctor(Molecule& molecule) : unitCell(*molecule.unitCell()) {}

  void operator()(Vector3& pos) { unitCell.wrapCartesian(pos, pos); }
};
}

bool CrystalTools::wrapAtomsToUnitCell(Molecule& molecule)
{
  if (!molecule.unitCell())
    return false;

  std::for_each(molecule.atomPositions3d().begin(),
                molecule.atomPositions3d().end(),
                WrapAtomsToCellFunctor(molecule));
  return true;
}

bool CrystalTools::rotateToStandardOrientation(Molecule& molecule, Options opts)
{
  if (!molecule.unitCell())
    return false;

  const UnitCell& cell = *molecule.unitCell();

  const Matrix3& before = cell.cellMatrix();

  // Extract vector components:
  const Real& x1 = before(0, 0);
  const Real& y1 = before(1, 0);
  const Real& z1 = before(2, 0);

  const Real& x2 = before(0, 1);
  const Real& y2 = before(1, 1);
  const Real& z2 = before(2, 1);

  const Real& x3 = before(0, 2);
  const Real& y3 = before(1, 2);
  const Real& z3 = before(2, 2);

  // Cache some frequently used values:
  // Length of v1
  const Real L1 = std::sqrt(x1 * x1 + y1 * y1 + z1 * z1);
  // Squared norm of v1's yz projection
  const Real sqrdnorm1yz = y1 * y1 + z1 * z1;
  // Squared norm of v2's yz projection
  const Real sqrdnorm2yz = y2 * y2 + z2 * z2;
  // Determinant of v1 and v2's projections in yz plane
  const Real detv1v2yz = y2 * z1 - y1 * z2;
  // Scalar product of v1 and v2's projections in yz plane
  const Real dotv1v2yz = y1 * y2 + z1 * z2;

  // Used for denominators, since we want to check that they are
  // sufficiently far from 0 to keep things reasonable:
  Real denom;
  const Real DENOM_TOL = 1e-5;

  // Create target matrix, fill with zeros
  Matrix3 newMat(Matrix3::Zero());

  // Set components of new v1:
  newMat(0, 0) = L1;

  // Set components of new v2:
  denom = L1;
  if (fabs(denom) < DENOM_TOL)
    return false;

  newMat(0, 1) = (x1 * x2 + y1 * y2 + z1 * z2) / denom;

  newMat(1, 1) = sqrt(x2 * x2 * sqrdnorm1yz + detv1v2yz * detv1v2yz -
                      2 * x1 * x2 * dotv1v2yz + x1 * x1 * sqrdnorm2yz) /
                 denom;

  // Set components of new v3
  newMat(0, 2) = (x1 * x3 + y1 * y3 + z1 * z3) / denom;

  denom = L1 * L1 * newMat(1, 1);
  if (fabs(denom) < DENOM_TOL)
    return false;

  newMat(1, 2) = (x1 * x1 * (y2 * y3 + z2 * z3) +
                  x2 * (x3 * sqrdnorm1yz - x1 * (y1 * y3 + z1 * z3)) +
                  detv1v2yz * (y3 * z1 - y1 * z3) - x1 * x3 * dotv1v2yz) /
                 denom;

  denom = L1 * newMat(1, 1);
  if (fabs(denom) < DENOM_TOL)
    return false;

  // Numerator is determinant of original cell:
  newMat(2, 2) = before.determinant() / denom;

  return setCellMatrix(molecule, newMat, opts & TransformAtoms);
}

bool CrystalTools::setVolume(Molecule& molecule, Real newVolume, Options opts)
{
  if (!molecule.unitCell())
    return false;

  const UnitCell& cell = *molecule.unitCell();

  const Real scaleFactor =
    std::pow(newVolume / cell.volume(), static_cast<Real>(1.0 / 3.0));

  const Matrix3 newMatrix(cell.cellMatrix() * scaleFactor);

  return setCellMatrix(molecule, newMatrix, opts & TransformAtoms);
}

// A collection of fuzzy comparison operators used in the niggli reduction
// algorithm:
namespace {
const double FUZZY_TOL(1e-5);
template <typename T>
bool fuzzyLessThan(T v1, T v2, T prec = static_cast<T>(FUZZY_TOL))
{
  return (v1 < (v2 - prec));
}

template <typename T>
bool fuzzyGreaterThan(T v1, T v2, T prec = static_cast<T>(FUZZY_TOL))
{
  return (v2 < (v1 - prec));
}

template <typename T>
bool fuzzyEqual(T v1, T v2, T prec = static_cast<T>(FUZZY_TOL))
{
  return (!(fuzzyLessThan(v1, v2, prec) || fuzzyGreaterThan(v1, v2, prec)));
}

template <typename T>
bool fuzzyNotEqual(T v1, T v2, T prec = static_cast<T>(FUZZY_TOL))
{
  return (!(fuzzyEqual(v1, v2, prec)));
}

template <typename T>
bool fuzzyLessThanEq(T v1, T v2, T prec = static_cast<T>(FUZZY_TOL))
{
  return (!fuzzyGreaterThan(v1, v2, prec));
}

template <typename T>
bool fuzzyGreaterThanEq(T v1, T v2, T prec = static_cast<T>(FUZZY_TOL))
{
  return (!lt(v1, v2, prec));
}

template <typename T>
T niggliSign(T v)
{
  // consider 0 to be positive
  return (v >= static_cast<T>(0.)) ? static_cast<T>(1.0) : static_cast<T>(-1.0);
}

template <typename T>
T niggliRound(T v, T dec)
{
  const T shift = std::pow(10.0, dec);
  const T shifted = v * shift;
  return std::floor(shifted + 0.5) / shift;
}
}

bool CrystalTools::niggliReduce(Molecule& molecule, Options opts)
{
  if (!molecule.unitCell())
    return false;

  UnitCell& cell = *molecule.unitCell();

  // Maximum number of iterations
  const unsigned int maxIterations = 1000;

  // Get cell parameters in storage units, convert deg->rad
  Real a = cell.a();
  Real b = cell.b();
  Real c = cell.c();
  Real alpha = cell.alpha();
  Real beta = cell.beta();
  Real gamma = cell.gamma();

  // Compute characteristic (step 0)
  Real A = a * a;
  Real B = b * b;
  Real C = c * c;
  Real xi = 2 * b * c * std::cos(alpha);
  Real eta = 2 * a * c * std::cos(beta);
  Real zeta = 2 * a * b * std::cos(gamma);

  // Return value.
  bool ret = false;

  // Comparison tolerance.
  Real tol = FUZZY_TOL * std::pow(a * b * c, static_cast<Real>(1.0 / 3.0));

  // Initialize change of basis matrices:
  //
  // Although the reduction algorithm produces quantities directly
  // relatable to a,b,c,alpha,beta,gamma, we will calculate a change
  // of basis matrix to use instead, and discard A, B, C, xi, eta,
  // zeta. By multiplying the change of basis matrix against the
  // current cell matrix, we avoid the problem of handling the
  // orientation matrix already present in the cell. The inverse of
  // this matrix can also be used later to convert the atomic
  // positions.

  // tmpMat is used to build other matrices
  Matrix3 tmpMat;

  // Cache static matrices:

  // Swap x, y (Used in Step 1). Negatives ensure proper sign of final
  // determinant.
  tmpMat << 0, -1, 0, -1, 0, 0, 0, 0, -1;
  const Matrix3 C1(tmpMat);
  // Swap y, z (Used in Step 2). Negatives ensure proper sign of final
  // determinant
  tmpMat << -1, 0, 0, 0, 0, -1, 0, -1, 0;
  const Matrix3 C2(tmpMat);
  // For step 8:
  tmpMat << 1, 0, 1, 0, 1, 1, 0, 0, 1;
  const Matrix3 C8(tmpMat);

  // initial change of basis matrix
  tmpMat << 1, 0, 0, 0, 1, 0, 0, 0, 1;
  Matrix3 cob(tmpMat);

// Enable debugging output here:
/*
#define NIGGLI_DEBUG(step) \
 std::cout << iter << " " << step << " " << A << " " << B << " " << C \
           << " " << xi << " " << eta << " " << zeta << std::endl;
*/
#define NIGGLI_DEBUG(step)

  // Perform iterative reduction:
  unsigned int iter;
  for (iter = 0; iter < maxIterations; ++iter) {
    // Step 1:
    if (fuzzyGreaterThan(A, B, tol) ||
        (fuzzyEqual(A, B, tol) &&
         fuzzyGreaterThan(std::fabs(xi), std::fabs(eta), tol))) {
      cob *= C1;
      std::swap(A, B);
      std::swap(xi, eta);
      NIGGLI_DEBUG(1);
    }

    // Step 2:
    if (fuzzyGreaterThan(B, C, tol) ||
        (fuzzyEqual(B, C, tol) &&
         fuzzyGreaterThan(std::fabs(eta), std::fabs(zeta), tol))) {
      cob *= C2;
      std::swap(B, C);
      std::swap(eta, zeta);
      NIGGLI_DEBUG(2);
      continue;
    }

    // Step 3:
    // Use exact comparisons in steps 3 and 4.
    if (xi * eta * zeta > 0) {
      // Update change of basis matrix:
      tmpMat << niggliSign(xi), 0, 0, 0, niggliSign(eta), 0, 0, 0,
        niggliSign(zeta);
      cob *= tmpMat;

      // Update characteristic
      xi = std::fabs(xi);
      eta = std::fabs(eta);
      zeta = std::fabs(zeta);
      NIGGLI_DEBUG(3);
      ++iter;
    }

    // Step 4:
    // Use exact comparisons for steps 3 and 4
    else { // either step 3 or 4 should run
      // Update change of basis matrix:
      Real* p = nullptr;
      Real i = 1;
      Real j = 1;
      Real k = 1;
      if (xi > 0) {
        i = -1;
      } else if (!(xi < 0)) {
        p = &i;
      }
      if (eta > 0) {
        j = -1;
      } else if (!(eta < 0)) {
        p = &j;
      }
      if (zeta > 0) {
        k = -1;
      } else if (!(zeta < 0)) {
        p = &k;
      }
      if (i * j * k < 0) {
        if (!p) {
          // This was originally an error message displayed in a dialog:
          // Niggli-reduction failed. The input structure's lattice is confusing
          // the Niggli-reduction algorithm. Try making a small perturbation
          // (approx. 2 orders of magnitude smaller than the tolerance) to the
          // input lattices and try again.
          return false;
        }
        *p = -1;
      }
      tmpMat << i, 0, 0, 0, j, 0, 0, 0, k;
      cob *= tmpMat;

      // Update characteristic
      xi = -std::fabs(xi);
      eta = -std::fabs(eta);
      zeta = -std::fabs(zeta);
      NIGGLI_DEBUG(4);
      ++iter;
    }

    // Step 5:
    if (fuzzyGreaterThan(std::fabs(xi), B, tol) ||
        (fuzzyEqual(xi, B, tol) && fuzzyLessThan(2 * eta, zeta, tol)) ||
        (fuzzyEqual(xi, -B, tol) && fuzzyLessThan(zeta, Real(0), tol))) {
      Real signXi = niggliSign(xi);
      // Update change of basis matrix:
      tmpMat << 1, 0, 0, 0, 1, -signXi, 0, 0, 1;
      cob *= tmpMat;

      // Update characteristic
      C = B + C - xi * signXi;
      eta = eta - zeta * signXi;
      xi = xi - 2 * B * signXi;
      NIGGLI_DEBUG(5);
      continue;
    }

    // Step 6:
    if (fuzzyGreaterThan(std::fabs(eta), A, tol) ||
        (fuzzyEqual(eta, A, tol) && fuzzyLessThan(2 * xi, zeta, tol)) ||
        (fuzzyEqual(eta, -A, tol) && fuzzyLessThan(zeta, Real(0), tol))) {
      Real signEta = niggliSign(eta);
      // Update change of basis matrix:
      tmpMat << 1, 0, -signEta, 0, 1, 0, 0, 0, 1;
      cob *= tmpMat;

      // Update characteristic
      C = A + C - eta * signEta;
      xi = xi - zeta * signEta;
      eta = eta - 2 * A * signEta;
      NIGGLI_DEBUG(6);
      continue;
    }

    // Step 7:
    if (fuzzyGreaterThan(std::fabs(zeta), A, tol) ||
        (fuzzyEqual(zeta, A, tol) && fuzzyLessThan(2 * xi, eta, tol)) ||
        (fuzzyEqual(zeta, -A, tol) && fuzzyLessThan(eta, Real(0), tol))) {
      Real signZeta = niggliSign(zeta);
      // Update change of basis matrix:
      tmpMat << 1, -signZeta, 0, 0, 1, 0, 0, 0, 1;
      cob *= tmpMat;

      // Update characteristic
      B = A + B - zeta * signZeta;
      xi = xi - eta * signZeta;
      zeta = zeta - 2 * A * signZeta;
      NIGGLI_DEBUG(7);
      continue;
    }

    // Step 8:
    Real sumAllButC = A + B + xi + eta + zeta;
    if (fuzzyLessThan(sumAllButC, Real(0), tol) ||
        (fuzzyEqual(sumAllButC, Real(0), tol) &&
         fuzzyGreaterThan(2 * (A + eta) + zeta, Real(0), tol))) {
      // Update change of basis matrix:
      cob *= C8;

      // Update characteristic
      C = sumAllButC + C;
      xi = 2 * B + xi + zeta;
      eta = 2 * A + eta + zeta;
      NIGGLI_DEBUG(8);
      continue;
    }

    // Done!
    ret = true;
    break;
  }

  // No change
  if (iter == 0)
    return true;

  // Iteration limit exceeded:
  if (!ret)
    return false;

  // Update atoms if needed
  if (opts & TransformAtoms) {
    // Get fractional coordinates
    Array<Vector3> fcoords;
    if (!fractionalCoordinates(molecule, fcoords))
      return false;

    // fix coordinates with COB matrix:
    const Matrix3 invCob(cob.inverse());
    for (Array<Vector3>::iterator it = fcoords.begin(), itEnd = fcoords.end();
         it != itEnd; ++it) {
      *it = invCob * (*it);
    }

    // Update cell
    cell.setCellMatrix(cell.cellMatrix() * cob);

    // Reapply the fractional coordinates
    setFractionalCoordinates(molecule, fcoords);
  } else {
    // just update the matrix:
    cell.setCellMatrix(cell.cellMatrix() * cob);
  }
  return true;
}

bool CrystalTools::isNiggliReduced(const Molecule& molecule)
{
  if (!molecule.unitCell())
    return false;

  const UnitCell& cell = *molecule.unitCell();

  const Real a = cell.a();
  const Real b = cell.b();
  const Real c = cell.c();
  const Real alpha = cell.alpha();
  const Real beta = cell.beta();
  const Real gamma = cell.gamma();

  const Real A = a * a;
  const Real B = b * b;
  const Real C = c * c;
  const Real xi = static_cast<Real>(2) * b * c * std::cos(alpha);
  const Real eta = static_cast<Real>(2) * a * c * std::cos(beta);
  const Real zeta = static_cast<Real>(2) * a * b * std::cos(gamma);

  const Real tol = FUZZY_TOL * ((a + b + c) * static_cast<Real>(1. / 3.));

  // First check the Buerger conditions. Taken from: Gruber B.. Acta
  // Cryst. A. 1973;29(4):433-440. Available at:
  // http://scripts.iucr.org/cgi-bin/paper?S0567739473001063
  // [Accessed December 15, 2010].
  if (fuzzyGreaterThan(A, B, tol) || fuzzyGreaterThan(B, C, tol))
    return false;

  if (fuzzyEqual(A, B, tol) &&
      fuzzyGreaterThan(std::fabs(xi), std::fabs(eta), tol)) {
    return false;
  }

  if (fuzzyEqual(B, C, tol) &&
      fuzzyGreaterThan(std::fabs(eta), std::fabs(zeta), tol)) {
    return false;
  }

  if (!(fuzzyGreaterThan(xi, static_cast<Real>(0.0), tol) &&
        fuzzyGreaterThan(eta, static_cast<Real>(0.0), tol) &&
        fuzzyGreaterThan(zeta, static_cast<Real>(0.0), tol)) &&
      !(fuzzyLessThanEq(zeta, static_cast<Real>(0.0), tol) &&
        fuzzyLessThanEq(zeta, static_cast<Real>(0.0), tol) &&
        fuzzyLessThanEq(zeta, static_cast<Real>(0.0), tol))) {
    return false;
  }

  // Check against Niggli conditions (taken from Gruber 1973). The
  // logic of the second comparison is reversed from the paper to
  // simplify the algorithm.
  if (fuzzyEqual(xi, B, tol) &&
      fuzzyGreaterThan(zeta, static_cast<Real>(2) * eta, tol)) {
    return false;
  }
  if (fuzzyEqual(eta, A, tol) &&
      fuzzyGreaterThan(zeta, static_cast<Real>(2) * xi, tol)) {
    return false;
  }
  if (fuzzyEqual(zeta, A, tol) &&
      fuzzyGreaterThan(eta, static_cast<Real>(2) * xi, tol)) {
    return false;
  }
  if (fuzzyEqual(xi, -B, tol) &&
      fuzzyNotEqual(zeta, static_cast<Real>(0), tol)) {
    return false;
  }
  if (fuzzyEqual(eta, -A, tol) &&
      fuzzyNotEqual(zeta, static_cast<Real>(0), tol)) {
    return false;
  }
  if (fuzzyEqual(zeta, -A, tol) &&
      fuzzyNotEqual(eta, static_cast<Real>(0), tol)) {
    return false;
  }
  if (fuzzyEqual(xi + eta + zeta + A + B, static_cast<Real>(0), tol) &&
      fuzzyGreaterThan(static_cast<Real>(2) * (A + eta) + zeta,
                       static_cast<Real>(0), tol)) {
    return false;
  }

  // all good!
  return true;
}

bool CrystalTools::buildSupercell(Molecule& molecule, unsigned int a,
                                  unsigned int b, unsigned int c)
{
  if (!molecule.unitCell())
    return false;

  // Just a check. Hopefully this won't happen
  if (a == 0 || b == 0 || c == 0) {
    std::cerr << "Warning: in buildSupercell(), a, b, or c were set to zero."
              << "This function will not proceed. Returning false.";
    return false;
  }

  // Get the old vectors
  Vector3 oldA = molecule.unitCell()->aVector();
  Vector3 oldB = molecule.unitCell()->bVector();
  Vector3 oldC = molecule.unitCell()->cVector();

  // Calculate new vectors
  Vector3 newA = oldA * a;
  Vector3 newB = oldB * b;
  Vector3 newC = oldC * c;

  // Add in the atoms to the new subcells of the supercell
  Index numAtoms = molecule.atomCount();
  Array<Vector3> atoms = molecule.atomPositions3d();
  Array<unsigned char> atomicNums = molecule.atomicNumbers();
  for (Index ind_a = 0; ind_a < a; ++ind_a) {
    for (Index ind_b = 0; ind_b < b; ++ind_b) {
      for (Index ind_c = 0; ind_c < c; ++ind_c) {
        // Skip over the subcell that already exists
        if (ind_a == 0 && ind_b == 0 && ind_c == 0)
          continue;
        // The positions of the new atoms are displacements of the old atoms
        Vector3 displacement = ind_a * oldA + ind_b * oldB + ind_c * oldC;
        for (Index i = 0; i < numAtoms; ++i) {
          Atom newAtom = molecule.addAtom(atomicNums.at(i));
          newAtom.setPosition3d(atoms.at(i) + displacement);
        }
      }
    }
  }

  // Now set the unit cell
  molecule.unitCell()->setAVector(newA);
  molecule.unitCell()->setBVector(newB);
  molecule.unitCell()->setCVector(newC);

  // We're done!
  return true;
}

namespace {
struct TransformAtomsFunctor
{
  TransformAtomsFunctor(const Matrix3& t) : transform(t) {}
  const Matrix3& transform;

  void operator()(Vector3& pos) { pos = transform * pos; }
};
}

bool CrystalTools::setCellMatrix(Molecule& molecule,
                                 const Matrix3& newCellColMatrix, Options opt)
{
  if (opt & TransformAtoms && molecule.unitCell()) {
    const Matrix3 xform(newCellColMatrix *
                        molecule.unitCell()->cellMatrix().inverse());
    std::for_each(molecule.atomPositions3d().begin(),
                  molecule.atomPositions3d().end(),
                  TransformAtomsFunctor(xform));
  }

  if (!molecule.unitCell())
    molecule.setUnitCell(new UnitCell);

  molecule.unitCell()->setCellMatrix(newCellColMatrix);

  return true;
}

namespace {
struct FractionalCoordinatesFunctor
{
  const UnitCell& unitCell;

  FractionalCoordinatesFunctor(const UnitCell& uc) : unitCell(uc) {}

  void operator()(Vector3& pos) { unitCell.toFractional(pos, pos); }
};
}

bool CrystalTools::fractionalCoordinates(const UnitCell& unitCell,
                                         const Array<Vector3>& cart,
                                         Array<Vector3>& frac)
{
  if (&frac != &cart) // avoid self-copy...
    frac = cart;

  std::for_each(frac.begin(), frac.end(),
                FractionalCoordinatesFunctor(unitCell));

  return true;
}

bool CrystalTools::fractionalCoordinates(const Molecule& molecule,
                                         Array<Vector3>& coords)
{
  if (!molecule.unitCell())
    return false;

  coords = molecule.atomPositions3d();
  coords.resize(molecule.atomCount());

  return fractionalCoordinates(*molecule.unitCell(), coords, coords);
}

namespace {
struct SetFractionalCoordinatesFunctor
{
  const UnitCell& unitCell;

  SetFractionalCoordinatesFunctor(const Molecule& molecule)
    : unitCell(*molecule.unitCell())
  {
  }

  Vector3 operator()(const Vector3& pos) { return unitCell.toCartesian(pos); }
};
}

bool CrystalTools::setFractionalCoordinates(Molecule& molecule,
                                            const Array<Vector3>& coords)
{
  if (!molecule.unitCell())
    return false;

  if (coords.size() != molecule.atomCount())
    return false;

  Array<Vector3>& output = molecule.atomPositions3d();
  output.resize(coords.size());

  std::transform(coords.begin(), coords.end(), output.begin(),
                 SetFractionalCoordinatesFunctor(molecule));

  return true;
}

} // namespace Core
} // namespace Avogadro
