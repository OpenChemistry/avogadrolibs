/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fragmenttools.h"

#include "rwmolecule.h"

#include <avogadro/core/angletools.h>

#include <QtCore/QObject>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <initializer_list>
#include <vector>

namespace Avogadro::QtGui {

namespace {

/**
 * Mark every atom reachable from @p from without crossing @p bond and
 * without passing through @p blocked.
 *
 * Iterative rather than recursive: a fragment can be most of the molecule,
 * and a recursive walk would put one stack frame on it per atom.
 */
void reachableFrom(RWMolecule& molecule, const RWBond& bond, const RWAtom& from,
                   Index blocked, std::vector<bool>& reached)
{
  if (from.index() >= reached.size())
    return;

  std::vector<Index> pending;
  reached[from.index()] = true;
  pending.push_back(from.index());

  while (!pending.empty()) {
    const RWAtom current = molecule.atom(pending.back());
    pending.pop_back();

    for (const auto& it : molecule.bonds(current)) {
      if (it == bond)
        continue; // never cross the bond being split

      const Index next = it.getOtherAtom(current).index();
      if (next == blocked || next >= reached.size() || reached[next])
        continue;

      reached[next] = true;
      pending.push_back(next);
    }
  }
}

// Every atom reachable from @p from over any bond at all -- not stepping
// around one particular bond, the way reachableFrom() above does for a
// fragment. Passing a default-constructed, invalid RWBond as the one to
// avoid means "cross every bond", since an invalid bond never compares equal
// to a real one.
//
// This is a fresh walk rather than a lookup into Graph::subgraph(), whose
// cached component ids are computed once and can go stale while an edit is
// in progress -- exactly the situation these functions run in.
void componentOf(RWMolecule& molecule, Index from, std::vector<bool>& reached)
{
  reachableFrom(molecule, RWBond(), molecule.atom(from), MaxIndex, reached);
}

// Whether @p atomA and @p atomB can reach each other over bonds at all.
bool inSameComponent(RWMolecule& molecule, Index atomA, Index atomB)
{
  std::vector<bool> reached(molecule.atomCount(), false);
  componentOf(molecule, atomA, reached);
  return atomB < reached.size() && reached[atomB];
}

// Every atom in @p startAtom's connected component, as unique ids.
Core::Array<Index> componentUniqueIds(RWMolecule& molecule, Index startAtom)
{
  Core::Array<Index> component;
  std::vector<bool> reached(molecule.atomCount(), false);
  componentOf(molecule, startAtom, reached);
  for (Index i = 0; i < reached.size(); ++i) {
    if (reached[i])
      component.push_back(molecule.atomUniqueId(molecule.atom(i)));
  }
  return component;
}

} // namespace

Core::Array<Index> FragmentTools::fragmentUniqueIds(RWMolecule& molecule,
                                                    const RWBond& bond,
                                                    const RWAtom& startAtom)
{
  Core::Array<Index> fragment;
  const Index atomCount = molecule.atomCount();
  const Index start = startAtom.index();
  if (start >= atomCount)
    return fragment;

  // What the far end holds on to: everything it can still reach once the
  // bond is taken away and the moving atom is stepped around. For an
  // ordinary bond that is simply the other side. For a bond in a ring it is
  // the rest of the ring, which cannot move without deforming it.
  std::vector<bool> held(atomCount, false);
  reachableFrom(molecule, bond, bond.getOtherAtom(startAtom), start, held);

  // What moves: everything the starting atom reaches without crossing the
  // bond, less whatever the far end holds. Substituents hanging off the
  // starting atom are reached here and are held by nothing else, so they
  // come along even when the bond itself is in a ring -- which is the whole
  // point of asking the question this way round.
  std::vector<bool> moving(atomCount, false);
  reachableFrom(molecule, bond, startAtom, MaxIndex, moving);

  for (Index i = 0; i < atomCount; ++i) {
    if (moving[i] && !held[i])
      fragment.push_back(molecule.atomUniqueId(molecule.atom(i)));
  }

  return fragment;
}

Core::Array<Index> FragmentTools::fragmentUniqueIds(RWMolecule& molecule,
                                                    Index anchorAtom,
                                                    Index movingAtom)
{
  Core::Array<Index> fragment;

  const RWAtom anchor = molecule.atom(anchorAtom);
  const RWAtom moving = molecule.atom(movingAtom);
  if (!anchor.isValid() || !moving.isValid())
    return fragment;

  const RWBond bond = molecule.bond(anchor, moving);
  if (bond.isValid())
    return fragmentUniqueIds(molecule, bond, moving);

  // The two are not bonded, which an internal coordinate is free to be. If
  // they do not even share a molecule there is nothing on the anchor's side
  // holding the moving atom in place, so the whole of its molecule comes
  // along -- editing a water dimer's O' row this way moves all of the
  // second water. If they do share a molecule this is an explicit edit
  // against a user-chosen reference elsewhere in it, so only the named atom
  // moves.
  if (!inSameComponent(molecule, anchorAtom, movingAtom))
    return componentUniqueIds(molecule, movingAtom);

  fragment.push_back(molecule.atomUniqueId(moving));
  return fragment;
}

void FragmentTools::transformAtoms(RWMolecule& molecule,
                                   const Core::Array<Index>& uniqueIds,
                                   const Eigen::Affine3d& transform)
{
  for (const Index uniqueId : uniqueIds) {
    RWAtom atom = molecule.atomByUniqueId(uniqueId);
    if (atom.isValid())
      atom.setPosition3d(transform * atom.position3d());
  }
}

void FragmentTools::transformAtoms(RWMolecule& molecule,
                                   const Core::Array<Index>& uniqueIds,
                                   const Eigen::Affine3d& transform,
                                   const QString& undoText)
{
  molecule.beginMergeMode(undoText);
  transformAtoms(molecule, uniqueIds, transform);
  molecule.endMergeMode();
}

namespace {

// Below this the two points are treated as coincident and the direction
// between them carries no information.
const Real coincidentTolerance = 1e-8;

// |sin| below which three points are treated as collinear, leaving no
// well-defined plane to rotate in or about.
const Real collinearTolerance = 1e-6;

// A NaN or an infinity reaching a transform would spread from there into
// every atom it moves, so a value that cannot be meant is refused at the
// door rather than stored.
bool isUsableValue(Real value)
{
  return std::isfinite(value);
}

// Whether @p fragment contains @p atom, by unique id. Used two ways below:
// the fragment must contain the atom the caller asked to move (else that
// atom is held by a ring and the coordinate cannot be set), and it must NOT
// contain a fixed reference atom the transform would move regardless of the
// fragment (else the edit would drag its own reference point along and
// become a silent no-op).
bool fragmentContains(RWMolecule& molecule, const Core::Array<Index>& fragment,
                      Index atom)
{
  const Index uniqueId = molecule.atomUniqueId(molecule.atom(atom));
  return std::find(fragment.begin(), fragment.end(), uniqueId) !=
         fragment.end();
}

// The named atoms must all exist and all be different, or the coordinate
// does not describe anything.
bool distinctAndValid(RWMolecule& molecule, std::initializer_list<Index> atoms)
{
  for (const Index* i = atoms.begin(); i != atoms.end(); ++i) {
    if (!molecule.atom(*i).isValid())
      return false;
    for (const Index* j = i + 1; j != atoms.end(); ++j) {
      if (*i == *j)
        return false;
    }
  }
  return true;
}

// The chain overloads take unique ids rather than indices, so they need
// their own version of the check above.
template <std::size_t N>
bool allDistinctAndValid(RWMolecule& molecule,
                         const std::array<Index, N>& uniqueIds)
{
  for (std::size_t i = 0; i < N; ++i) {
    if (!molecule.atomByUniqueId(uniqueIds[i]).isValid())
      return false;
    for (std::size_t j = i + 1; j < N; ++j) {
      if (uniqueIds[i] == uniqueIds[j])
        return false;
    }
  }
  return true;
}

// The upfront degeneracy checks below mirror the tolerance comparisons
// inside setDistance()/setAngle()/setTorsion() -- not the transform maths
// itself -- so the chain overloads can tell Degenerate apart from a fragment
// that simply could not be found (Ring/NotRigid) before choosing a fragment
// at all.
bool isDistanceDegenerate(const Vector3& atomPosition, const Vector3& aPosition)
{
  return (atomPosition - aPosition).norm() < coincidentTolerance;
}

bool isAngleDegenerate(const Vector3& atomPosition, const Vector3& aPosition,
                       const Vector3& bPosition)
{
  const Vector3 toAtom = atomPosition - aPosition;
  const Vector3 toB = bPosition - aPosition;
  if (toAtom.norm() < coincidentTolerance || toB.norm() < coincidentTolerance)
    return true;
  return toAtom.normalized().cross(toB.normalized()).norm() <
         collinearTolerance;
}

bool isTorsionDegenerate(const Vector3& atomPosition, const Vector3& aPosition,
                         const Vector3& bPosition, const Vector3& cPosition)
{
  Vector3 axis = bPosition - aPosition;
  if (axis.norm() < coincidentTolerance)
    return true;
  axis.normalize();

  const Vector3 toAtom = atomPosition - aPosition;
  if (toAtom.normalized().cross(axis).norm() < collinearTolerance)
    return true;

  const Vector3 toC = cPosition - bPosition;
  return toC.norm() < coincidentTolerance ||
         toC.normalized().cross(axis).norm() < collinearTolerance;
}

} // namespace

bool FragmentTools::setDistance(RWMolecule& molecule, Index atom, Index a,
                                Real length, const Core::Array<Index>& fragment)
{
  if (!distinctAndValid(molecule, { atom, a }))
    return false;
  if (!isUsableValue(length) || length < 0.0)
    return false; // a distance is never negative
  if (!fragmentContains(molecule, fragment, atom))
    return false;
  // A translation moves everything given to it, so the fixed end must not
  // be part of what moves.
  if (fragmentContains(molecule, fragment, a))
    return false;

  const Vector3 positionA = molecule.atomPosition3d(a);
  Vector3 direction = molecule.atomPosition3d(atom) - positionA;
  const Real current = direction.norm();
  if (current < coincidentTolerance)
    return false; // no direction to move along

  direction /= current;

  Eigen::Affine3d transform;
  transform.setIdentity();
  transform.translate(Vector3(direction * (length - current)));

  transformAtoms(molecule, fragment, transform, QObject::tr("Adjust Distance"));
  return true;
}

bool FragmentTools::setDistance(RWMolecule& molecule, Index atom, Index a,
                                Real length)
{
  return setDistance(molecule, atom, a, length,
                     fragmentUniqueIds(molecule, a, atom));
}

bool FragmentTools::setAngle(RWMolecule& molecule, Index atom, Index a, Index b,
                             Real degrees, const Core::Array<Index>& fragment)
{
  if (!distinctAndValid(molecule, { atom, a, b }))
    return false;
  if (!isUsableValue(degrees))
    return false;
  if (!fragmentContains(molecule, fragment, atom))
    return false;
  // The rotation only leaves the pivot a fixed, so the other reference atom
  // b must not be part of what moves. The pivot itself is allowed in the
  // fragment -- the property table's angle fragment always contains it.
  if (fragmentContains(molecule, fragment, b))
    return false;

  const Vector3 position = molecule.atomPosition3d(atom);
  const Vector3 positionA = molecule.atomPosition3d(a);
  const Vector3 positionB = molecule.atomPosition3d(b);

  // The angle opens in the plane of the three atoms, about their vertex.
  const Vector3 toAtom = position - positionA;
  const Vector3 toB = positionB - positionA;
  if (toAtom.norm() < coincidentTolerance || toB.norm() < coincidentTolerance)
    return false;

  Vector3 axis = toAtom.normalized().cross(toB.normalized());
  if (axis.norm() < collinearTolerance)
    return false; // already straight, so there is no plane to open it in
  axis.normalize();

  // Turning about toAtom x toB by a positive angle carries the atom towards
  // b, which closes the angle, so the rotation runs the other way.
  const Real change =
    (degrees - calculateAngle(position, positionA, positionB)) * DEG_TO_RAD;

  Eigen::Affine3d transform;
  transform.setIdentity();
  transform.translate(positionA);
  transform.rotate(Eigen::AngleAxis<Real>(-change, axis));
  transform.translate(-positionA);

  transformAtoms(molecule, fragment, transform, QObject::tr("Adjust Angle"));
  return true;
}

bool FragmentTools::setAngle(RWMolecule& molecule, Index atom, Index a, Index b,
                             Real degrees)
{
  return setAngle(molecule, atom, a, b, degrees,
                  fragmentUniqueIds(molecule, a, atom));
}

bool FragmentTools::setTorsion(RWMolecule& molecule, Index atom, Index a,
                               Index b, Index c, Real degrees,
                               const Core::Array<Index>& fragment)
{
  if (!distinctAndValid(molecule, { atom, a, b, c }))
    return false;
  if (!isUsableValue(degrees))
    return false;
  if (!fragmentContains(molecule, fragment, atom))
    return false;
  // The rotation only leaves the a-b axis fixed, so the other reference atom
  // c must not be part of what moves. The axis atoms themselves are allowed
  // in the fragment.
  if (fragmentContains(molecule, fragment, c))
    return false;

  const Vector3 position = molecule.atomPosition3d(atom);
  const Vector3 positionA = molecule.atomPosition3d(a);
  const Vector3 positionB = molecule.atomPosition3d(b);
  const Vector3 positionC = molecule.atomPosition3d(c);

  // The torsion turns about the a-b axis.
  Vector3 axis = positionB - positionA;
  if (axis.norm() < coincidentTolerance)
    return false;
  axis.normalize();

  // With atom, a and b in a line the torsion does not move the atom at all,
  // so there is nothing an edit could achieve.
  const Vector3 toAtom = position - positionA;
  if (toAtom.normalized().cross(axis).norm() < collinearTolerance)
    return false;

  // A torsion is measured between two planes, and a-b-c only defines the
  // second one while c is off the a-b axis. With c on that axis, or sitting
  // on top of b, the measured value is meaningless, so an edit against it
  // could not reach what was asked for.
  const Vector3 toC = positionC - positionB;
  if (toC.norm() < coincidentTolerance ||
      toC.normalized().cross(axis).norm() < collinearTolerance)
    return false;

  const Real change =
    (degrees - calculateDihedral(position, positionA, positionB, positionC)) *
    DEG_TO_RAD;

  Eigen::Affine3d transform;
  transform.setIdentity();
  transform.translate(positionA);
  transform.rotate(Eigen::AngleAxis<Real>(-change, axis));
  transform.translate(-positionA);

  transformAtoms(molecule, fragment, transform, QObject::tr("Adjust Torsion"));
  return true;
}

bool FragmentTools::setTorsion(RWMolecule& molecule, Index atom, Index a,
                               Index b, Index c, Real degrees)
{
  return setTorsion(molecule, atom, a, b, c, degrees,
                    fragmentUniqueIds(molecule, a, atom));
}

FragmentTools::CoordinateEditResult FragmentTools::setChainDistance(
  RWMolecule& molecule, const std::array<Index, 2>& uniqueIds, Real length)
{
  if (!allDistinctAndValid(molecule, uniqueIds))
    return CoordinateEditResult::InvalidAtoms;
  if (!isUsableValue(length) || length < 0.0)
    return CoordinateEditResult::InvalidValue;

  const RWAtom atomI = molecule.atomByUniqueId(uniqueIds[0]);
  const RWAtom atomJ = molecule.atomByUniqueId(uniqueIds[1]);
  const Index i = atomI.index();
  const Index j = atomJ.index();

  if (isDistanceDegenerate(molecule.atomPosition3d(j),
                           molecule.atomPosition3d(i)))
    return CoordinateEditResult::Degenerate;

  // j's side of the i-j bond if it exists; otherwise, with nothing to hold
  // j in place relative to i, its whole molecule if that is a different one
  // from i's; otherwise there is nothing rigid to move.
  Core::Array<Index> fragment;
  const RWBond bond = molecule.bond(atomI, atomJ);
  if (bond.isValid())
    fragment = fragmentUniqueIds(molecule, bond, atomJ);
  else if (!inSameComponent(molecule, i, j))
    fragment = componentUniqueIds(molecule, j);
  else
    return CoordinateEditResult::NotRigid;

  // The geometry was already confirmed usable above, and the fragment above
  // is built to contain j and exclude i by construction, so this should
  // always succeed; the fallback is defensive only.
  return setDistance(molecule, j, i, length, fragment)
           ? CoordinateEditResult::Ok
           : CoordinateEditResult::NotRigid;
}

FragmentTools::CoordinateEditResult FragmentTools::setChainAngle(
  RWMolecule& molecule, const std::array<Index, 3>& uniqueIds, Real degrees)
{
  if (!allDistinctAndValid(molecule, uniqueIds))
    return CoordinateEditResult::InvalidAtoms;
  if (!isUsableValue(degrees))
    return CoordinateEditResult::InvalidValue;

  const RWAtom atomI = molecule.atomByUniqueId(uniqueIds[0]);
  const RWAtom atomJ = molecule.atomByUniqueId(uniqueIds[1]);
  const RWAtom atomK = molecule.atomByUniqueId(uniqueIds[2]);
  const Index i = atomI.index();
  const Index j = atomJ.index();
  const Index k = atomK.index();

  // Vertex j, measured towards i: the same order setAngle() below will use
  // once k is renamed "atom" and i is renamed "b".
  if (isAngleDegenerate(molecule.atomPosition3d(k), molecule.atomPosition3d(j),
                        molecule.atomPosition3d(i)))
    return CoordinateEditResult::Degenerate;

  // The end atoms decide first: with i and k in different molecules there is
  // no bond-side fragment to reason about, so all of k's molecule comes
  // along, regardless of what j is bonded to.
  if (!inSameComponent(molecule, i, k)) {
    const Core::Array<Index> fragment = componentUniqueIds(molecule, k);
    return setAngle(molecule, k, j, i, degrees, fragment)
             ? CoordinateEditResult::Ok
             : CoordinateEditResult::Degenerate; // checked above; defensive
  }

  // Same molecule: prefer the table convention -- the vertex's side of the
  // first bond -- whenever that bond exists, since that is what a bonded
  // valence angle always has and what the property table has always used.
  // Only look to the second bond when the first is absent.
  Core::Array<Index> fragment;
  CoordinateEditResult failureResult;
  const RWBond bondIJ = molecule.bond(atomI, atomJ);
  const RWBond bondJK = molecule.bond(atomJ, atomK);
  if (bondIJ.isValid()) {
    fragment = fragmentUniqueIds(molecule, bondIJ, atomJ);
    // This side may not reach k at all: k is only reachable from the vertex
    // by going the other way around a ring, so there is no side of this
    // bond that can move on its own.
    failureResult = CoordinateEditResult::Ring;
  } else if (bondJK.isValid()) {
    fragment = fragmentUniqueIds(molecule, bondJK, atomK);
    // This fragment always contains k -- fragmentUniqueIds() always
    // includes the start atom it was asked for -- so the only way setAngle()
    // below can refuse it is the fixed-reference guard: i sits inside k's
    // side too, so no rigid fragment can move without dragging the fixed
    // atom along. That is a rigidity problem, not a ring.
    failureResult = CoordinateEditResult::NotRigid;
  } else {
    return CoordinateEditResult::NotRigid;
  }

  return setAngle(molecule, k, j, i, degrees, fragment)
           ? CoordinateEditResult::Ok
           : failureResult;
}

FragmentTools::CoordinateEditResult FragmentTools::setChainTorsion(
  RWMolecule& molecule, const std::array<Index, 4>& uniqueIds, Real degrees)
{
  if (!allDistinctAndValid(molecule, uniqueIds))
    return CoordinateEditResult::InvalidAtoms;
  if (!isUsableValue(degrees))
    return CoordinateEditResult::InvalidValue;

  const RWAtom atomI = molecule.atomByUniqueId(uniqueIds[0]);
  const RWAtom atomJ = molecule.atomByUniqueId(uniqueIds[1]);
  const RWAtom atomK = molecule.atomByUniqueId(uniqueIds[2]);
  const RWAtom atomL = molecule.atomByUniqueId(uniqueIds[3]);
  const Index i = atomI.index();
  const Index j = atomJ.index();
  const Index k = atomK.index();
  const Index l = atomL.index();

  // A dihedral is symmetric under reversal (i-j-k-l reads the same as
  // l-k-j-i), so measuring l-k-j-i here reaches the same requested value as
  // the chain's own i-j-k-l order while moving l, the chain's last atom, the
  // way setTorsion() below expects: atom=l, a=k, b=j, c=i.
  if (isTorsionDegenerate(
        molecule.atomPosition3d(l), molecule.atomPosition3d(k),
        molecule.atomPosition3d(j), molecule.atomPosition3d(i)))
    return CoordinateEditResult::Degenerate;

  // Different molecules at the ends: all of l's molecule comes along, and
  // the axis atoms j and k need not even be part of it.
  if (!inSameComponent(molecule, i, l)) {
    const Core::Array<Index> fragment = componentUniqueIds(molecule, l);
    return setTorsion(molecule, l, k, j, i, degrees, fragment)
             ? CoordinateEditResult::Ok
             : CoordinateEditResult::Degenerate; // checked above; defensive
  }

  // Same molecule: the table convention is k's side of the central j-k
  // bond, which a torsion's middle link always has. With no such bond there
  // is nothing to rotate independently.
  const RWBond bondJK = molecule.bond(atomJ, atomK);
  if (!bondJK.isValid())
    return CoordinateEditResult::NotRigid;

  const Core::Array<Index> fragment =
    fragmentUniqueIds(molecule, bondJK, atomK);

  // The bond exists but its side does not reach l: l reconnects to the j
  // side by some other path, as it would going the other way around a
  // macrocycle, so there is no side of this bond that can move on its own.
  return setTorsion(molecule, l, k, j, i, degrees, fragment)
           ? CoordinateEditResult::Ok
           : CoordinateEditResult::Ring;
}

} // namespace Avogadro::QtGui
