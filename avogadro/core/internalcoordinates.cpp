/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "internalcoordinates.h"

#include "angletools.h"
#include "graph.h"
#include "matrix.h"

#include <Eigen/Geometry>

#include <cmath>
#include <set>
#include <vector>

namespace Avogadro::Core {

namespace {

// Two points closer than this are treated as coincident: the direction
// between them carries no information.
const Real coincidentTolerance = 1e-8;

// |sin| of the angle below which three points are treated as collinear. The
// normal to their plane is numerically meaningless below this, so a dihedral
// measured against them cannot be reconstructed.
const Real collinearTolerance = 1e-4;

// |sin| above which a reference is good enough to stop looking for a better
// one, about 5.7 degrees away from collinear.
const Real goodReferenceTolerance = 0.1;

// |sin| below which a reference is too nearly collinear to be worth choosing,
// about one degree. This is deliberately far looser than the numerical
// tolerance above: a dihedral measured against a reference a tenth of a
// degree off the axis swings by tens of degrees when the geometry moves by a
// thousandth of an angstrom, so such a value is noise wearing a coordinate's
// clothes rather than something anyone can read or edit.
const Real referenceTolerance = 0.0175;

// A reference is usable only if it names a real atom that has already been
// given a position.
bool isPlaced(Index index, const std::vector<bool>& placed)
{
  return index != MaxIndex && index < placed.size() && placed[index];
}

// Any unit vector perpendicular to @p v. The axis is chosen away from v to
// avoid cancellation in the cross product.
Vector3 anyPerpendicular(const Vector3& v)
{
  const Vector3 axis =
    (std::abs(v.x()) < 0.9) ? Vector3(1.0, 0.0, 0.0) : Vector3(0.0, 1.0, 0.0);
  const Vector3 perpendicular = axis.cross(v);
  const Real norm = perpendicular.norm();
  if (norm < coincidentTolerance)
    return Vector3(0.0, 0.0, 1.0);
  return perpendicular / norm;
}

// |sin| of the angle at @p vertex between the directions to @p p and @p q.
// Zero when the three points are collinear or two of them coincide.
Real sineAt(const Vector3& p, const Vector3& vertex, const Vector3& q)
{
  const Vector3 u = p - vertex;
  const Vector3 v = q - vertex;
  const Real uNorm = u.norm();
  const Real vNorm = v.norm();
  if (uNorm < coincidentTolerance || vNorm < coincidentTolerance)
    return 0.0;
  return (u / uNorm).cross(v / vNorm).norm();
}

/**
 * The best reference seen so far, and separately the best that would do if
 * nothing better turns up.
 *
 * A reference that leaves the three points collinear still states a true
 * angle of 180 degrees, so for the angle reference it beats having none at
 * all; it simply cannot carry a dihedral. For the dihedral reference there
 * is no such consolation -- a collinear 'c' measures a meaningless number --
 * so that caller takes the good candidate only.
 */
struct Candidate
{
  Index good = MaxIndex;
  Real goodScore = referenceTolerance;
  Index fallback = MaxIndex;

  void offer(Index index, Real score)
  {
    if (score > goodScore) {
      goodScore = score;
      good = index;
    } else if (fallback == MaxIndex) {
      fallback = index;
    }
  }

  /** True once a candidate is far enough from collinear to stop looking. */
  bool settled() const { return goodScore > goodReferenceTolerance; }

  Index result() const { return good != MaxIndex ? good : fallback; }
};

// One row of a z-matrix: the atom it places, and the already-placed atoms it
// is measured against.
struct Reference
{
  Index atom = MaxIndex;
  Index a = MaxIndex;
  Index b = MaxIndex;
  Index c = MaxIndex;
};

/**
 * Choose the atoms that row @p atom is measured against.
 *
 * References are drawn only from atoms that have already been placed, which
 * is what makes the result a valid z-matrix: every reference is guaranteed
 * to appear in an earlier row.
 *
 * Bonded references are preferred, so that a row's length, angle and
 * dihedral are the chemically meaningful ones. Where no bonded candidate
 * exists -- the opening rows of the matrix, and the first atom of each
 * additional fragment -- the most recently placed atoms are used instead.
 * Those still describe the geometry exactly; they are simply not bond
 * lengths and bond angles.
 */
Reference chooseReferences(const Molecule& molecule, const Graph& graph,
                           Index atom, const std::vector<Index>& placedOrder,
                           const std::vector<bool>& placed)
{
  Reference reference;
  reference.atom = atom;
  if (placedOrder.empty())
    return reference; // the first row has nothing to measure against

  const Vector3 pos = molecule.atomPosition3d(atom);

  // 'a' is a bonded, already-placed neighbour where one exists. The
  // adjacency list is in bond order rather than index order, so take the
  // lowest index explicitly to keep the result deterministic.
  for (size_t neighbor : graph.neighbors(atom)) {
    if (isPlaced(neighbor, placed) &&
        (reference.a == MaxIndex || neighbor < reference.a))
      reference.a = neighbor;
  }
  if (reference.a == MaxIndex)
    reference.a = placedOrder.back(); // a new fragment: anchor to the last atom
  if (placedOrder.size() < 2)
    return reference; // the second row can only carry a distance

  const Vector3 posA = molecule.atomPosition3d(reference.a);

  // 'b' completes the angle at 'a'. Prefer an atom bonded to 'a', and among
  // those one that does not leave atom-a-b collinear.
  Candidate candidateB;
  for (size_t neighbor : graph.neighbors(reference.a)) {
    if (neighbor == atom || !isPlaced(neighbor, placed))
      continue;
    if ((molecule.atomPosition3d(neighbor) - posA).norm() < coincidentTolerance)
      continue; // coincident with 'a': no angle can be measured
    candidateB.offer(neighbor,
                     sineAt(pos, posA, molecule.atomPosition3d(neighbor)));
  }
  // A bonded neighbour that leaves atom-a-b in a line is no better than no
  // neighbour at all: the angle it states is 180 degrees, which pins nothing
  // down and leaves every dihedral from this row unreconstructible. So the
  // walk back through the placement order runs whenever no bonded candidate
  // was out of line, not merely when there was no bonded candidate.
  if (candidateB.good == MaxIndex) {
    for (auto it = placedOrder.rbegin(); it != placedOrder.rend(); ++it) {
      if (*it == atom || *it == reference.a)
        continue;
      if ((molecule.atomPosition3d(*it) - posA).norm() < coincidentTolerance)
        continue; // coincident with 'a': no angle can be measured
      candidateB.offer(*it, sineAt(pos, posA, molecule.atomPosition3d(*it)));
      if (candidateB.settled())
        break;
    }
  }
  // Nothing out of line anywhere, so fall back on a collinear reference: the
  // molecule really is straight here, and a 180 degree angle describes it.
  reference.b = candidateB.result();

  if (reference.b == MaxIndex || placedOrder.size() < 3)
    return reference; // the third row can only carry a distance and an angle

  const Vector3 posB = molecule.atomPosition3d(reference.b);

  // 'c' completes the dihedral about the a-b axis. It is only reconstructible
  // when a, b and c are not collinear, so candidates below the tolerance are
  // rejected outright rather than merely scored down.
  Candidate candidateC;
  for (size_t neighbor : graph.neighbors(reference.b)) {
    if (neighbor == atom || neighbor == reference.a ||
        !isPlaced(neighbor, placed))
      continue;
    candidateC.offer(neighbor,
                     sineAt(posA, posB, molecule.atomPosition3d(neighbor)));
  }
  if (candidateC.good == MaxIndex) {
    for (auto it = placedOrder.rbegin(); it != placedOrder.rend(); ++it) {
      if (*it == atom || *it == reference.a || *it == reference.b)
        continue;
      candidateC.offer(*it, sineAt(posA, posB, molecule.atomPosition3d(*it)));
      if (candidateC.settled())
        break;
    }
  }
  // Unlike 'b', a collinear candidate is refused outright rather than kept
  // as a fallback: the dihedral it would measure is a meaningless number.
  reference.c = candidateC.good;

  // 'c' may still be unset, meaning every candidate is collinear with a and
  // b. Then atom-a-b is collinear too, the dihedral has no bearing on where
  // the atom sits, and a distance and an angle describe the row exactly.
  return reference;
}

/**
 * Order the atoms into a valid z-matrix and choose each row's references.
 *
 * Atoms are taken in bond order from the lowest-indexed atom outwards,
 * always preferring the lowest-indexed atom reachable from those already
 * placed. A molecule whose atom order is already a valid z-matrix order
 * therefore keeps that order, and the caller's row-to-atom map is the
 * identity. When the bonded frontier runs out, the lowest unplaced atom
 * starts the next fragment.
 */
std::vector<Reference> buildZMatrix(const Molecule& molecule)
{
  const Index atomCount = molecule.atomCount();
  std::vector<Reference> rows;
  if (atomCount == 0)
    return rows;
  rows.reserve(atomCount);

  const Graph& graph = molecule.graph();
  std::vector<bool> placed(atomCount, false);
  std::vector<Index> placedOrder;
  placedOrder.reserve(atomCount);

  // Unplaced atoms bonded to something already placed, kept in index order.
  std::set<Index> frontier;
  Index nextUnplaced = 0;

  while (rows.size() < atomCount) {
    Index atom = MaxIndex;
    if (!frontier.empty()) {
      atom = *frontier.begin();
      // A dummy atom exists only to be something else's reference, so it goes
      // in as soon as its anchor is placed. One placed after the atoms that
      // need it would be no use to them, which is the whole point of adding
      // it to a linear fragment.
      for (Index candidate : frontier) {
        if (molecule.atomicNumber(candidate) == 0) {
          atom = candidate;
          break;
        }
      }
      frontier.erase(atom);
    } else {
      // Start the matrix, or a new fragment, at the lowest unplaced atom.
      while (nextUnplaced < atomCount && placed[nextUnplaced])
        ++nextUnplaced;
      if (nextUnplaced >= atomCount)
        break;
      atom = nextUnplaced;
    }

    rows.push_back(
      chooseReferences(molecule, graph, atom, placedOrder, placed));
    placed[atom] = true;
    placedOrder.push_back(atom);

    for (size_t neighbor : graph.neighbors(atom)) {
      if (neighbor < atomCount && !placed[neighbor])
        frontier.insert(neighbor);
    }
  }

  return rows;
}

/**
 * Build the z-matrix rows in the molecule's own atom order, so that row @a i
 * places atom @a i.
 *
 * Unlike buildZMatrix() this cannot fail: chooseReferences() always finds
 * references among the atoms before it, falling back on non-bonded ones. The
 * question is whether those references are worth having, which
 * atomOrderIsUsable() answers.
 */
std::vector<Reference> buildZMatrixInAtomOrder(const Molecule& molecule)
{
  const Index atomCount = molecule.atomCount();
  std::vector<Reference> rows;
  rows.reserve(atomCount);

  const Graph& graph = molecule.graph();
  std::vector<bool> placed(atomCount, false);
  std::vector<Index> placedOrder;
  placedOrder.reserve(atomCount);

  for (Index atom = 0; atom < atomCount; ++atom) {
    rows.push_back(
      chooseReferences(molecule, graph, atom, placedOrder, placed));
    placed[atom] = true;
    placedOrder.push_back(atom);
  }

  return rows;
}

/**
 * Whether the molecule's atom order gives every atom a bonded reference.
 *
 * True when each atom is bonded to an atom of lower index, or is the lowest
 * indexed atom of its fragment and so opens it. That is exactly the
 * guarantee buildZMatrix() provides, so where it holds the atom order costs
 * nothing in reference quality and keeps the file's numbering the one the
 * user sees.
 */
bool atomOrderHasBondedReferences(const Molecule& molecule)
{
  const Index atomCount = molecule.atomCount();
  const Graph& graph = molecule.graph();

  // The lowest-indexed atom seen so far in each fragment. An atom that is
  // not bonded to anything earlier is acceptable only if it is opening its
  // own fragment rather than rejoining one already under way.
  std::vector<bool> fragmentOpened(graph.subgraphsCount(), false);

  for (Index atom = 0; atom < atomCount; ++atom) {
    bool bondedToEarlier = false;
    for (size_t neighbor : graph.neighbors(atom)) {
      if (neighbor < atom) {
        bondedToEarlier = true;
        break;
      }
    }

    const size_t fragment = graph.subgraph(atom);
    if (fragment >= fragmentOpened.size())
      return false; // a fragment id we cannot reason about: take the safe path
    const bool opensFragment = !fragmentOpened[fragment];
    fragmentOpened[fragment] = true;

    if (!bondedToEarlier && !opensFragment)
      return false;
  }

  return true;
}

/**
 * The in-plane direction perpendicular to @p ab that a distance-and-angle
 * row is placed along. The row is free to rotate about the a-b axis, so
 * either the molecule's existing plane or the xy-plane is used.
 */
Vector3 referencePerpendicular(const Molecule& molecule, Index atom, Index a,
                               Index b, const Vector3& ab, ZMatrixOrigin origin)
{
  if (origin == ZMatrixOrigin::Preserve) {
    Vector3 oldAb = molecule.atomPosition3d(b) - molecule.atomPosition3d(a);
    const Vector3 oldV =
      molecule.atomPosition3d(atom) - molecule.atomPosition3d(a);
    if (oldAb.norm() > coincidentTolerance) {
      oldAb.normalize();
      Vector3 oldPerpendicular = oldV - oldV.dot(oldAb) * oldAb;
      if (oldPerpendicular.norm() > coincidentTolerance) {
        oldPerpendicular.normalize();
        // Carry the molecule's own plane onto the rebuilt a-b direction.
        const Eigen::Quaternion<Real> rotation =
          Eigen::Quaternion<Real>::FromTwoVectors(oldAb, ab);
        return (rotation * oldPerpendicular).normalized();
      }
    }
    // The molecule has no plane to preserve here, so fall through.
  }

  // Canonical: keep the third atom in the xy-plane where a-b allows it.
  Vector3 perpendicular(-ab.y(), ab.x(), 0.0);
  if (perpendicular.norm() > coincidentTolerance)
    return perpendicular.normalized();
  return anyPerpendicular(ab);
}

Array<Vector3> buildCartesian(const Molecule& molecule,
                              const Array<InternalCoordinate>& internalCoords,
                              const Array<Index>& rowToAtom,
                              ZMatrixOrigin origin)
{
  const Index atomCount = molecule.atomCount();
  Array<Vector3> coords(atomCount, Vector3(0.0, 0.0, 0.0));

  // An atom that no row places keeps the position it already has rather than
  // being dragged to the origin, so a short or malformed matrix disturbs
  // only the atoms it actually names.
  if (origin == ZMatrixOrigin::Preserve) {
    for (Index i = 0; i < atomCount; ++i)
      coords[i] = molecule.atomPosition3d(i);
  }

  if (internalCoords.size() != rowToAtom.size())
    return coords;

  std::vector<bool> placed(atomCount, false);

  for (size_t row = 0; row < internalCoords.size(); ++row) {
    const Index atom = rowToAtom[row];
    if (atom >= atomCount)
      continue; // the map does not name a real atom

    const InternalCoordinate& internal = internalCoords[row];
    const Index a = internal.a;
    const Index b = internal.b;
    const Index c = internal.c;

    // Each branch uses as much of the row as is actually usable. A row whose
    // references have not been placed is not an error: it is how the opening
    // rows of every z-matrix are defined.
    if (!isPlaced(a, placed)) {
      // Nothing to measure from: this row anchors the matrix.
      coords[atom] = (origin == ZMatrixOrigin::Preserve)
                       ? molecule.atomPosition3d(atom)
                       : Vector3(0.0, 0.0, 0.0);
    } else if (!isPlaced(b, placed)) {
      // A distance only, so any direction satisfies the row.
      Vector3 direction(1.0, 0.0, 0.0);
      if (origin == ZMatrixOrigin::Preserve) {
        const Vector3 existing =
          molecule.atomPosition3d(atom) - molecule.atomPosition3d(a);
        if (existing.norm() > coincidentTolerance)
          direction = existing.normalized();
      }
      coords[atom] = coords[a] + internal.length * direction;
    } else {
      Vector3 ab = coords[b] - coords[a];
      const Real abNorm = ab.norm();
      if (abNorm < coincidentTolerance) {
        // 'a' and 'b' coincide, so there is no axis to measure the angle
        // from. Keep the distance and place the atom along +x.
        coords[atom] = coords[a] + internal.length * Vector3(1.0, 0.0, 0.0);
        placed[atom] = true;
        continue;
      }
      ab /= abNorm;

      const Real theta = internal.angle * DEG_TO_RAD;
      const Real sinTheta = std::sin(theta);
      const Real cosTheta = std::cos(theta);

      if (!isPlaced(c, placed)) {
        // A distance and an angle: free to rotate about the a-b axis.
        const Vector3 perpendicular =
          referencePerpendicular(molecule, atom, a, b, ab, origin);
        coords[atom] = coords[a] + internal.length *
                                     (cosTheta * ab + sinTheta * perpendicular);
      } else {
        // Natural extension reference frame, see
        // J. Comp. Chem. Vol. 26, No. 10, p. 1063-1068 (2005)
        // https://doi.org/10.1002/jcc.20237
        Vector3 bc = coords[c] - coords[b];
        const Real bcNorm = bc.norm();
        if (bcNorm > coincidentTolerance)
          bc /= bcNorm;

        Vector3 normal = ab.cross(bc);
        const Real normalNorm = normal.norm();
        if (normalNorm > collinearTolerance)
          normal /= normalNorm;
        else
          normal = anyPerpendicular(ab); // a, b and c are collinear

        const Vector3 inPlane = normal.cross(ab);
        // A z-matrix dihedral is the IUPAC signed torsion atom-a-b-c, whose
        // sense about the a-b axis is opposite to that of this frame, so the
        // rotation is applied negated. Getting this wrong does not disturb
        // any distance or angle -- it silently builds the mirror image.
        const Real phi = -internal.dihedral * DEG_TO_RAD;

        // Local frame at 'a': +ab is the angle reference, inPlane carries a
        // zero dihedral, and normal rotates the atom out of the a-b-c plane.
        const Vector3 local(internal.length * cosTheta,
                            internal.length * sinTheta * std::cos(phi),
                            internal.length * sinTheta * std::sin(phi));

        Matrix3 frame;
        frame << ab, inPlane, normal;
        coords[atom] = frame * local + coords[a];
      }
    }

    placed[atom] = true;
  }

  return coords;
}

} // namespace

Array<Vector3> internalToCartesian(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords)
{
  // In this form the row index is the atom index.
  Array<Index> rowToAtom(internalCoords.size());
  for (size_t i = 0; i < rowToAtom.size(); ++i)
    rowToAtom[i] = i;

  return buildCartesian(molecule, internalCoords, rowToAtom,
                        ZMatrixOrigin::Canonical);
}

Array<Vector3> internalToCartesian(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords,
  const Array<Index>& rowToAtom, ZMatrixOrigin origin)
{
  return buildCartesian(molecule, internalCoords, rowToAtom, origin);
}

Array<DummyAtomSite> linearDummySites(const Molecule& molecule, Real distance)
{
  Array<DummyAtomSite> sites;
  if (distance < coincidentTolerance)
    return sites;

  const std::vector<Reference> rows = buildZMatrix(molecule);

  // One dummy per anchor, however many rows are stranded on it, and a shared
  // direction between them so that the dihedrals they produce come out at
  // clean multiples of 180 degrees rather than at arbitrary angles.
  std::set<Index> anchored;
  Vector3 shared = Vector3::Zero();

  for (size_t row = 0; row < rows.size(); ++row) {
    const Reference& reference = rows[row];
    // The opening rows are short of references by definition rather than by
    // fault, and no dummy would change that.
    if (reference.a == MaxIndex || reference.b == MaxIndex)
      continue;

    const Vector3 pos = molecule.atomPosition3d(reference.atom);
    const Vector3 posA = molecule.atomPosition3d(reference.a);
    const Vector3 posB = molecule.atomPosition3d(reference.b);

    // Two ways a row is stranded: its own angle is straight, so it carries no
    // plane of its own; or three atoms were there to measure a dihedral
    // against and not one of them was off the a-b axis.
    const bool straight = sineAt(pos, posA, posB) <= referenceTolerance;
    const bool noDihedral = row >= 3 && reference.c == MaxIndex;
    if (!straight && !noDihedral)
      continue;

    if (!anchored.insert(reference.a).second)
      continue; // this anchor already has one

    Vector3 axis = pos - posA;
    if (axis.norm() < coincidentTolerance)
      continue;
    axis.normalize();

    // Carry the first dummy's direction to the rest, squared up against each
    // anchor's own axis. Parallel axes -- the usual case, these atoms all
    // being in one line -- keep it exactly.
    Vector3 perpendicular = shared - shared.dot(axis) * axis;
    if (perpendicular.norm() < collinearTolerance)
      perpendicular = anyPerpendicular(axis);
    perpendicular.normalize();
    if (shared.isZero())
      shared = perpendicular;

    DummyAtomSite site;
    site.anchor = reference.a;
    site.position = posA + distance * perpendicular;
    sites.push_back(site);
  }

  return sites;
}

namespace {

/** Measure the rows @p rows describe, and record the atom each one places. */
Array<InternalCoordinate> measureRows(const Molecule& molecule,
                                      const std::vector<Reference>& rows,
                                      Array<Index>& rowToAtom)
{
  Array<InternalCoordinate> internalCoords(rows.size());
  rowToAtom.resize(rows.size());

  for (size_t row = 0; row < rows.size(); ++row) {
    const Reference& reference = rows[row];
    rowToAtom[row] = reference.atom;

    InternalCoordinate coord;
    coord.a = reference.a;
    coord.b = reference.b;
    coord.c = reference.c;

    if (reference.a != MaxIndex) {
      const Vector3 pos = molecule.atomPosition3d(reference.atom);
      const Vector3 posA = molecule.atomPosition3d(reference.a);
      coord.length = (pos - posA).norm();

      if (reference.b != MaxIndex) {
        const Vector3 posB = molecule.atomPosition3d(reference.b);
        if (coord.length > coincidentTolerance &&
            (posB - posA).norm() > coincidentTolerance)
          coord.angle = calculateAngle(pos, posA, posB);

        if (reference.c != MaxIndex) {
          const Vector3 posC = molecule.atomPosition3d(reference.c);
          if ((posC - posB).norm() > coincidentTolerance)
            coord.dihedral = calculateDihedral(pos, posA, posB, posC);
        }
      }
    }

    internalCoords[row] = coord;
  }

  return internalCoords;
}

} // namespace

Array<Index> linearReferenceRows(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords,
  Real toleranceDegrees)
{
  Array<Index> rows;

  for (size_t row = 0; row < internalCoords.size(); ++row) {
    const InternalCoordinate& coord = internalCoords[row];
    // A row with no angle reference states no angle, and one with no
    // dihedral reference states no dihedral: the opening rows of every
    // z-matrix are like this and there is nothing ill-conditioned about
    // them.
    if (coord.b == MaxIndex)
      continue;

    if (coord.angle >= toleranceDegrees) {
      rows.push_back(row);
      continue;
    }

    if (coord.c == MaxIndex)
      continue;

    // The dihedral turns about the a-b axis, so it is just as badly
    // conditioned when a, b and c are the atoms in a line.
    const Real referenceAngle = calculateAngle(
      molecule.atomPosition3d(coord.a), molecule.atomPosition3d(coord.b),
      molecule.atomPosition3d(coord.c));
    if (referenceAngle >= toleranceDegrees)
      rows.push_back(row);
  }

  return rows;
}

Array<InternalCoordinate> cartesianToInternal(const Molecule& molecule,
                                              Array<Index>& rowToAtom)
{
  return measureRows(molecule, buildZMatrix(molecule), rowToAtom);
}

Array<InternalCoordinate> cartesianToInternal(const Molecule& molecule,
                                              Array<Index>& rowToAtom,
                                              ZMatrixOrder order)
{
  Array<InternalCoordinate> optimal =
    measureRows(molecule, buildZMatrix(molecule), rowToAtom);
  if (order == ZMatrixOrder::Optimal)
    return optimal;

  // The molecule's own order is only worth keeping if it costs nothing: it
  // has to give every atom a bonded reference, and it must not leave more
  // rows hanging off a straight line than the bond-order walk would.
  if (!atomOrderHasBondedReferences(molecule))
    return optimal;

  Array<Index> atomOrderRowToAtom;
  Array<InternalCoordinate> atomOrder = measureRows(
    molecule, buildZMatrixInAtomOrder(molecule), atomOrderRowToAtom);

  if (linearReferenceRows(molecule, atomOrder).size() >
      linearReferenceRows(molecule, optimal).size())
    return optimal;

  rowToAtom = atomOrderRowToAtom;
  return atomOrder;
}

} // end namespace Avogadro::Core
