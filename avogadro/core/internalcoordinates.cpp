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
  Real bestScore = -1.0;
  for (size_t neighbor : graph.neighbors(reference.a)) {
    if (neighbor == atom || !isPlaced(neighbor, placed))
      continue;
    const Real score = sineAt(pos, posA, molecule.atomPosition3d(neighbor));
    if (score > bestScore) {
      bestScore = score;
      reference.b = neighbor;
    }
  }
  if (reference.b == MaxIndex) {
    // No bonded candidate, so walk back through the placement order.
    for (auto it = placedOrder.rbegin(); it != placedOrder.rend(); ++it) {
      if (*it == atom || *it == reference.a)
        continue;
      if ((molecule.atomPosition3d(*it) - posA).norm() < coincidentTolerance)
        continue; // coincident with 'a': no angle can be measured
      const Real score = sineAt(pos, posA, molecule.atomPosition3d(*it));
      if (score > bestScore) {
        bestScore = score;
        reference.b = *it;
      }
      if (bestScore > goodReferenceTolerance)
        break;
    }
  }
  if (reference.b == MaxIndex || placedOrder.size() < 3)
    return reference; // the third row can only carry a distance and an angle

  const Vector3 posB = molecule.atomPosition3d(reference.b);

  // 'c' completes the dihedral about the a-b axis. It is only reconstructible
  // when a, b and c are not collinear, so candidates below the tolerance are
  // rejected outright rather than merely scored down.
  bestScore = collinearTolerance;
  for (size_t neighbor : graph.neighbors(reference.b)) {
    if (neighbor == atom || neighbor == reference.a ||
        !isPlaced(neighbor, placed))
      continue;
    const Real score = sineAt(posA, posB, molecule.atomPosition3d(neighbor));
    if (score > bestScore) {
      bestScore = score;
      reference.c = neighbor;
    }
  }
  if (reference.c == MaxIndex) {
    for (auto it = placedOrder.rbegin(); it != placedOrder.rend(); ++it) {
      if (*it == atom || *it == reference.a || *it == reference.b)
        continue;
      const Real score = sineAt(posA, posB, molecule.atomPosition3d(*it));
      if (score > bestScore) {
        bestScore = score;
        reference.c = *it;
      }
      if (bestScore > goodReferenceTolerance)
        break;
    }
  }

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
      frontier.erase(frontier.begin());
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

Array<InternalCoordinate> cartesianToInternal(const Molecule& molecule,
                                              Array<Index>& rowToAtom)
{
  const std::vector<Reference> rows = buildZMatrix(molecule);

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

} // end namespace Avogadro::Core
