/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "crystaltools.h"

#include "elements.h"
#include "molecule.h"
#include "neighborperceiver.h"
#include "unitcell.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iostream>
#include <set>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Avogadro::Core {

namespace {
struct WrapAtomsToCellFunctor
{
  const UnitCell& unitCell;

  WrapAtomsToCellFunctor(Molecule& molecule) : unitCell(*molecule.unitCell()) {}

  void operator()(Vector3& pos) { unitCell.wrapCartesian(pos, pos); }
};
} // namespace

bool CrystalTools::wrapAtomsToUnitCell(Molecule& molecule)
{
  if (!molecule.unitCell())
    return false;

  // remove any bonds first - otherwise they may wrap
  // across the unit cell strangely
  molecule.clearBonds();

  std::for_each(molecule.atomPositions3d().begin(),
                molecule.atomPositions3d().end(),
                WrapAtomsToCellFunctor(molecule));

  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();
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
  const Real L1 = std::hypot(x1, y1, z1);
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

  if (opts & RightHanded && newMat(2, 2) < 0.0)
    newMat(2, 2) *= -1.0;

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
} // namespace

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

  // Allow Argument Dependent Lookup for swap
  using std::swap;

  // Perform iterative reduction:
  unsigned int iter;
  for (iter = 0; iter < maxIterations; ++iter) {
    // Step 1:
    if (fuzzyGreaterThan(A, B, tol) ||
        (fuzzyEqual(A, B, tol) &&
         fuzzyGreaterThan(std::fabs(xi), std::fabs(eta), tol))) {
      cob *= C1;
      swap(A, B);
      swap(xi, eta);
      NIGGLI_DEBUG(1);
    }

    // Step 2:
    if (fuzzyGreaterThan(B, C, tol) ||
        (fuzzyEqual(B, C, tol) &&
         fuzzyGreaterThan(std::fabs(eta), std::fabs(zeta), tol))) {
      cob *= C2;
      swap(B, C);
      swap(eta, zeta);
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
    for (auto& fcoord : fcoords) {
      fcoord = invCob * fcoord;
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

namespace {

// Mirrors the elements that Molecule::perceiveBondsSimple() refuses to bond.
bool isNobleGas(unsigned char atomicNumber)
{
  switch (atomicNumber) {
    case 2:  // He
    case 10: // Ne
    case 18: // Ar
    case 36: // Kr
      return true;
    default:
      return false;
  }
}

using PeriodicBondKey = std::tuple<Index, Index, int, int, int>;

// Orders the two ends of a periodic bond so that it gets the same key whichever
// atom it was discovered from: (i, j, offset) and (j, i, -offset) are one bond.
PeriodicBondKey periodicBondKey(Index atom1, Index atom2,
                                const Vector3i& offset)
{
  const PeriodicBondKey forward(atom1, atom2, offset.x(), offset.y(),
                                offset.z());
  const PeriodicBondKey reverse(atom2, atom1, -offset.x(), -offset.y(),
                                -offset.z());
  return forward < reverse ? forward : reverse;
}

} // namespace

Array<CrystalTools::PeriodicBond> CrystalTools::perceivePeriodicBonds(
  const Molecule& molecule, double tolerance)
{
  Array<PeriodicBond> bonds;

  const Array<std::pair<Index, Index>>& bondPairs = molecule.bondPairs();
  const Array<unsigned char>& bondOrders = molecule.bondOrders();
  const Index numAtoms = molecule.atomCount();

  bonds.reserve(bondPairs.size());
  for (Index i = 0; i < bondPairs.size(); ++i) {
    bonds.push_back(PeriodicBond{ bondPairs[i].first, bondPairs[i].second,
                                  Vector3i(0, 0, 0), bondOrders[i], false });
  }

  // Nothing is periodic without a cell, and nothing can be perceived without
  // coordinates. Either way the molecule's own bonds are the whole answer.
  const UnitCell* cell = molecule.unitCell();
  if (!cell || numAtoms < 2 || molecule.atomPositions3d().size() != numAtoms)
    return bonds;

  const Array<Vector3>& positions = molecule.atomPositions3d();
  std::vector<Vector3> frac(numAtoms);
  for (Index i = 0; i < numAtoms; ++i)
    frac[i] = cell->toFractional(positions[i]);

  // Cache the covalent radii, matching Molecule::perceiveBondsSimple().
  std::vector<double> radii(numAtoms);
  double maxRadius = 0.0;
  for (Index i = 0; i < numAtoms; ++i) {
    radii[i] = Elements::radiusCovalent(molecule.atomicNumber(i));
    if (radii[i] <= 0.0)
      radii[i] = 2.0;
    maxRadius = std::max(maxRadius, radii[i]);
  }
  const double maxDistance = 2.0 * maxRadius + tolerance;

  // Re-point the existing bonds that were stored stretched right across the
  // cell, so they become the short bonds they really are.
  //
  // Only bonds that are already too long to be a bond at all are touched. The
  // nearest image is not a safe test on its own: in a cell whose shortest axis
  // is under twice a bond length - rutile's c axis is 2.96 A, shorter than two
  // Ti-O bonds - an ordinary bond can reach past the half-cell mark and be
  // "corrected" onto an image it was never bonded to.
  std::set<PeriodicBondKey> seen;
  for (auto& bond : bonds) {
    const double cutoff = radii[bond.atom1] + radii[bond.atom2] + tolerance;
    const Vector3 delta = frac[bond.atom2] - frac[bond.atom1];
    if (cell->toCartesian(delta).norm() > cutoff) {
      bond.offset = Vector3i(-static_cast<int>(std::lround(delta.x())),
                             -static_cast<int>(std::lround(delta.y())),
                             -static_cast<int>(std::lround(delta.z())));
    }
    seen.insert(periodicBondKey(bond.atom1, bond.atom2, bond.offset));
  }
  // Bonds shorter than this are treated as coincident atoms rather than a bond,
  // again matching perceiveBondsSimple().
  const double minDistance = 0.45;

  const Vector3 aVec = cell->aVector();
  const Vector3 bVec = cell->bVector();
  const Vector3 cVec = cell->cVector();
  const double volume = std::abs(aVec.dot(bVec.cross(cVec)));
  if (volume <= 0.0)
    return bonds; // A degenerate cell has no meaningful periodic neighbours.

  // Perpendicular width of the cell along each axis - the distance between the
  // two faces, which is what actually limits how far a bond can reach, not the
  // lattice vector lengths.
  const Vector3 widths(volume / bVec.cross(cVec).norm(),
                       volume / cVec.cross(aVec).norm(),
                       volume / aVec.cross(bVec).norm());

  // A cell thinner than the bonding cutoff needs images beyond its immediate
  // neighbours. The cap keeps a near-degenerate cell from generating an
  // unbounded number of images.
  constexpr int maxDepth = 5;
  std::array<int, 3> depth;
  for (int i = 0; i < 3; ++i) {
    depth[i] = static_cast<int>(std::ceil(maxDistance / widths[i]));
    depth[i] = std::max(1, std::min(depth[i], maxDepth));
  }

  // Build the shell of periodic images surrounding the cell, keeping only those
  // close enough to bond with something inside it.
  Array<Vector3> searchPositions(positions);
  std::vector<std::pair<Index, Vector3i>> images;
  for (int oa = -depth[0]; oa <= depth[0]; ++oa) {
    for (int ob = -depth[1]; ob <= depth[1]; ++ob) {
      for (int oc = -depth[2]; oc <= depth[2]; ++oc) {
        if (oa == 0 && ob == 0 && oc == 0)
          continue;
        const Vector3 shift = oa * aVec + ob * bVec + oc * cVec;
        const Vector3 offsetFrac(oa, ob, oc);
        for (Index j = 0; j < numAtoms; ++j) {
          const Vector3 imageFrac = frac[j] + offsetFrac;
          bool reachable = true;
          for (int k = 0; k < 3; ++k) {
            // How far the image sticks out past the cell along this axis.
            const double overshoot =
              std::max(0.0, std::max(-imageFrac[k], imageFrac[k] - 1.0));
            if (overshoot * widths[k] > maxDistance) {
              reachable = false;
              break;
            }
          }
          if (!reachable)
            continue;
          searchPositions.push_back(positions[j] + shift);
          images.emplace_back(j, Vector3i(oa, ob, oc));
        }
      }
    }
  }

  if (images.empty())
    return bonds;

  const NeighborPerceiver perceiver(searchPositions,
                                    static_cast<float>(maxDistance));
  Array<Index> neighbors;
  for (Index i = 0; i < numAtoms; ++i) {
    if (isNobleGas(molecule.atomicNumber(i)))
      continue;
    perceiver.getNeighborsInclusiveInPlace(neighbors, positions[i]);
    for (Index n : neighbors) {
      // Anything below numAtoms is a pair inside the cell, which is the
      // molecule's own business.
      if (n < numAtoms)
        continue;
      const Index j = images[n - numAtoms].first;
      const Vector3i& offset = images[n - numAtoms].second;
      if (isNobleGas(molecule.atomicNumber(j)))
        continue;
      if (molecule.atomicNumber(i) == 1 && molecule.atomicNumber(j) == 1)
        continue;

      const double cutoff = radii[i] + radii[j] + tolerance;
      const double distanceSq =
        (searchPositions[n] - positions[i]).squaredNorm();
      if (distanceSq >= cutoff * cutoff ||
          distanceSq <= minDistance * minDistance)
        continue;

      // Each crossing bond is found twice, once from either end.
      if (!seen.insert(periodicBondKey(i, j, offset)).second)
        continue;

      bonds.push_back(PeriodicBond{ i, j, offset, 1, true });
    }
  }

  return bonds;
}

bool CrystalTools::buildSupercell(Molecule& molecule, unsigned int a,
                                  unsigned int b, unsigned int c, Options opts)
{
  // Just a check. Hopefully this won't happen
  if (a == 0 || b == 0 || c == 0) {
    std::cerr << "Warning: in buildSupercell(), a, b, or c were set to zero."
              << "This function will not proceed. Returning false.";
    return false;
  }

  return buildSupercell(
    molecule, Vector3(0.0, 0.0, 0.0),
    Vector3(static_cast<Real>(a), static_cast<Real>(b), static_cast<Real>(c)),
    opts);
}

namespace {

// Bins atom positions so that duplicate-position lookups stay linear in the
// number of atoms rather than quadratic. The bin size is twice the tolerance,
// so any duplicate is guaranteed to lie in one of the 27 neighboring bins.
class PositionGrid
{
public:
  PositionGrid(double tolerance) : m_tol(tolerance), m_invBin(0.5 / tolerance)
  {
  }

  void insert(const Vector3& pos, Index index)
  {
    m_bins[key(pos)].push_back(std::make_pair(pos, index));
  }

  // Returns true and sets @a index if an atom already sits at @a pos.
  bool find(const Vector3& pos, Index& index) const
  {
    const std::array<long, 3> k = key(pos);
    for (long i = -1; i <= 1; ++i) {
      for (long j = -1; j <= 1; ++j) {
        for (long l = -1; l <= 1; ++l) {
          auto bin =
            m_bins.find(std::array<long, 3>{ k[0] + i, k[1] + j, k[2] + l });
          if (bin == m_bins.end())
            continue;
          for (const auto& entry : bin->second) {
            if ((entry.first - pos).norm() < m_tol) {
              index = entry.second;
              return true;
            }
          }
        }
      }
    }
    return false;
  }

private:
  struct KeyHash
  {
    std::size_t operator()(const std::array<long, 3>& k) const
    {
      // Mix the three bin coordinates; the constants are the usual odd
      // multipliers used to spread integer triples over the hash space.
      return static_cast<std::size_t>(k[0] * 73856093L ^ k[1] * 19349663L ^
                                      k[2] * 83492791L);
    }
  };

  std::array<long, 3> key(const Vector3& pos) const
  {
    return std::array<long, 3>{
      static_cast<long>(std::floor(pos.x() * m_invBin)),
      static_cast<long>(std::floor(pos.y() * m_invBin)),
      static_cast<long>(std::floor(pos.z() * m_invBin))
    };
  }

  double m_tol;
  double m_invBin;
  std::unordered_map<std::array<long, 3>,
                     std::vector<std::pair<Vector3, Index>>, KeyHash>
    m_bins;
};

} // namespace

bool CrystalTools::buildSupercell(Molecule& molecule, const Vector3& rangeMin,
                                  const Vector3& rangeMax, Options opts)
{
  if (!molecule.unitCell())
    return false;

  // An empty (or inverted) range along any axis would produce no atoms at all.
  for (int i = 0; i < 3; ++i) {
    if (rangeMax[i] <= rangeMin[i]) {
      std::cerr << "Warning: in buildSupercell(), the range along axis " << i
                << " is empty. This function will not proceed. "
                << "Returning false.";
      return false;
    }
  }

  // Tolerance used when deciding whether a fractional limit is an integer and
  // whether an atom sits on a range boundary.
  const Real fracTol = 1e-5;

  // A range with non-integer limits cannot describe a lattice, so in that case
  // the unit cell is left alone and the copies simply extend beyond it - the
  // usual crystal packing view. Integer limits give a true supercell.
  bool isSupercell = true;
  for (int i = 0; i < 3; ++i) {
    if (std::abs(rangeMin[i] - std::round(rangeMin[i])) > fracTol ||
        std::abs(rangeMax[i] - std::round(rangeMax[i])) > fracTol) {
      isSupercell = false;
      break;
    }
  }

  // Get the old vectors
  const Vector3 oldA = molecule.unitCell()->aVector();
  const Vector3 oldB = molecule.unitCell()->bVector();
  const Vector3 oldC = molecule.unitCell()->cVector();

  // archive the old bond pairs and orders
  const Array<std::pair<Index, Index>> bondPairs = molecule.bondPairs();
  const Array<unsigned char> bondOrders = molecule.bondOrders();

  // Work out the periodic connectivity now, while the molecule is still just
  // the one cell. Bonds crossing a boundary are missing from the molecule, so
  // without this the copies show every molecule cut at each subcell face.
  const bool usePeriodicBonds = (opts & PerceivePeriodicBonds) != 0;
  const Array<PeriodicBond> periodicBonds =
    usePeriodicBonds ? perceivePeriodicBonds(molecule) : Array<PeriodicBond>();

  const Index numAtoms = molecule.atomCount();
  const Array<Vector3> atoms = molecule.atomPositions3d();
  const Array<unsigned char> atomicNums = molecule.atomicNumbers();

  // Fractional coordinates of the original atoms, used to decide which
  // translations of each atom land inside the requested range.
  std::vector<Vector3> fracCoords(numAtoms);
  for (Index i = 0; i < numAtoms; ++i)
    fracCoords[i] = molecule.unitCell()->toFractional(atoms.at(i));

  // The translations that could contribute anything at all. A supercell uses
  // the half-open range [min, max) so that 0 -> 2 gives exactly two cells,
  // matching the integer form of this function. A packing view uses the closed
  // range [min, max] so that the atoms on both bounding faces are shown.
  std::array<long, 3> tMin, tMax;
  for (int i = 0; i < 3; ++i) {
    if (isSupercell) {
      tMin[i] = static_cast<long>(std::lround(rangeMin[i]));
      tMax[i] = static_cast<long>(std::lround(rangeMax[i])) - 1;
    } else {
      // An atom's fractional coordinate is f + n, and f may itself lie outside
      // [0, 1), so widen the translation window by the span of f.
      Real fMin = 0.0;
      Real fMax = 0.0;
      for (Index j = 0; j < numAtoms; ++j) {
        fMin = std::min(fMin, fracCoords[j][i]);
        fMax = std::max(fMax, fracCoords[j][i]);
      }
      tMin[i] = static_cast<long>(std::floor(rangeMin[i] - fMax - fracTol));
      tMax[i] = static_cast<long>(std::ceil(rangeMax[i] - fMin + fracTol));
    }
  }

  // Duplicate positions are possible: translational copies at fractional ~1.0
  // overlap with the next subcell's ~0.0.
  const double dupTol = 0.01;
  PositionGrid grid(dupTol);
  for (Index i = 0; i < numAtoms; ++i)
    grid.insert(atoms.at(i), i);

  // For every translation, map each original atom onto the atom it became, so
  // the bonds can be copied even where duplicates were skipped. Absent atoms
  // (outside the range) are marked with the sentinel MaxIndex.
  std::vector<std::vector<Index>> indexMap;
  indexMap.reserve(
    static_cast<std::size_t>((tMax[0] - tMin[0] + 1) * (tMax[1] - tMin[1] + 1) *
                             (tMax[2] - tMin[2] + 1)));

  for (long ind_a = tMin[0]; ind_a <= tMax[0]; ++ind_a) {
    for (long ind_b = tMin[1]; ind_b <= tMax[1]; ++ind_b) {
      for (long ind_c = tMin[2]; ind_c <= tMax[2]; ++ind_c) {
        const Vector3 translation(static_cast<Real>(ind_a),
                                  static_cast<Real>(ind_b),
                                  static_cast<Real>(ind_c));
        const Vector3 displacement = ind_a * oldA + ind_b * oldB + ind_c * oldC;

        indexMap.emplace_back(numAtoms, MaxIndex);
        std::vector<Index>& copyMap = indexMap.back();

        for (Index i = 0; i < numAtoms; ++i) {
          if (!isSupercell) {
            // Keep only the atoms whose translated fractional coordinates fall
            // inside the requested range.
            const Vector3 frac = fracCoords[i] + translation;
            bool inRange = true;
            for (int k = 0; k < 3; ++k) {
              if (frac[k] < rangeMin[k] - fracTol ||
                  frac[k] > rangeMax[k] + fracTol) {
                inRange = false;
                break;
              }
            }
            if (!inRange)
              continue;
          }

          const Vector3 newPos = atoms.at(i) + displacement;
          Index existingIdx = MaxIndex;
          if (grid.find(newPos, existingIdx)) {
            copyMap[i] = existingIdx;
          } else {
            Atom newAtom = molecule.addAtom(atomicNums.at(i));
            newAtom.setPosition3d(newPos);
            copyMap[i] = newAtom.index();
            grid.insert(newPos, newAtom.index());
          }
        }
      }
    }
  }

  // Now add the bonds using the index map
  if (usePeriodicBonds) {
    // The molecule's own bonds come first in the periodic list, in molecule
    // bond order. Any of them that turned out to cross a boundary is about to
    // be re-added pointing at the right image, so drop the stale stretched one
    // first. Descending order keeps the remaining bond indices valid.
    for (Index i = bondPairs.size(); i > 0; --i) {
      const Vector3i& offset = periodicBonds[i - 1].offset;
      if (offset.x() != 0 || offset.y() != 0 || offset.z() != 0)
        molecule.removeBond(i - 1);
    }

    const long spanB = tMax[1] - tMin[1] + 1;
    const long spanC = tMax[2] - tMin[2] + 1;
    // The copy that a given translation produced, or null if that translation
    // lies outside the requested range.
    auto copyAt = [&](long ta, long tb, long tc) -> const std::vector<Index>* {
      if (ta < tMin[0] || ta > tMax[0] || tb < tMin[1] || tb > tMax[1] ||
          tc < tMin[2] || tc > tMax[2]) {
        return nullptr;
      }
      return &indexMap[static_cast<std::size_t>(
        ((ta - tMin[0]) * spanB + (tb - tMin[1])) * spanC + (tc - tMin[2]))];
    };

    for (long ta = tMin[0]; ta <= tMax[0]; ++ta) {
      for (long tb = tMin[1]; tb <= tMax[1]; ++tb) {
        for (long tc = tMin[2]; tc <= tMax[2]; ++tc) {
          const std::vector<Index>* from = copyAt(ta, tb, tc);
          for (const PeriodicBond& periodicBond : periodicBonds) {
            const Vector3i& offset = periodicBond.offset;
            const std::vector<Index>* to =
              copyAt(ta + offset.x(), tb + offset.y(), tc + offset.z());
            if (to == nullptr) {
              // The bond reaches past the edge of the range, so there is
              // nothing on the far side to join. A perceived bond is simply
              // left out - a packing view is meant to be cut at its boundary -
              // but a bond the molecule already had falls back to its own copy
              // rather than being lost.
              if (periodicBond.perceived)
                continue;
              to = from;
            }
            const Index a1 = (*from)[periodicBond.atom1];
            const Index a2 = (*to)[periodicBond.atom2];
            // Skip bonds where either atom fell outside the range, and bonds
            // whose ends were merged into a single atom
            if (a1 == MaxIndex || a2 == MaxIndex || a1 == a2)
              continue;
            // Avoid adding duplicate bonds (duplicated atoms may share bonds)
            if (!molecule.bond(a1, a2).isValid())
              molecule.addBond(a1, a2, periodicBond.order);
          }
        }
      }
    }
  } else {
    for (Index i = 0; i < bondPairs.size(); ++i) {
      const std::pair<Index, Index> bond = bondPairs.at(i);
      for (const auto& copyMap : indexMap) {
        const Index a1 = copyMap[bond.first];
        const Index a2 = copyMap[bond.second];
        // Skip bonds where either atom fell outside the range, and bonds whose
        // ends were merged into a single atom
        if (a1 == MaxIndex || a2 == MaxIndex || a1 == a2)
          continue;
        // Avoid adding duplicate bonds (duplicated atoms may share bonds)
        if (!molecule.bond(a1, a2).isValid())
          molecule.addBond(a1, a2, bondOrders.at(i));
      }
    }
  }

  if (isSupercell) {
    // Shift the atoms so that rangeMin sits at the new origin, then grow the
    // cell to span the range.
    const Vector3 origin =
      rangeMin[0] * oldA + rangeMin[1] * oldB + rangeMin[2] * oldC;
    if (!origin.isZero()) {
      Array<Vector3>& positions = molecule.atomPositions3d();
      for (auto& pos : positions)
        pos -= origin;
    }

    molecule.unitCell()->setAVector(oldA * (rangeMax[0] - rangeMin[0]));
    molecule.unitCell()->setBVector(oldB * (rangeMax[1] - rangeMin[1]));
    molecule.unitCell()->setCVector(oldC * (rangeMax[2] - rangeMin[2]));
  }

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
} // namespace

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

  if (!UnitCell::isRegular(newCellColMatrix)) {
    std::cerr << __FUNCTION__ << " cell matrix is singular\n";
    return false;
  }

  // only create a new unit cell if it doesn't exist
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
} // namespace

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
} // namespace

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

} // namespace Avogadro::Core
