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
  if (!bond.isValid()) {
    // The two are not bonded, which an internal coordinate is free to be, so
    // there is nothing hanging off the moving atom to carry with it.
    fragment.push_back(molecule.atomUniqueId(moving));
    return fragment;
  }

  return fragmentUniqueIds(molecule, bond, moving);
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

// The caller names the atom it wants moved, so a fragment that does not
// contain that atom cannot carry the edit out. That happens when the atom is
// held by a ring: the coordinate simply cannot be set without deforming the
// ring, and saying so beats reporting a success that moved nothing.
bool fragmentMoves(RWMolecule& molecule, const Core::Array<Index>& fragment,
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

} // namespace

bool FragmentTools::setDistance(RWMolecule& molecule, Index atom, Index a,
                                Real length, const Core::Array<Index>& fragment)
{
  if (!distinctAndValid(molecule, { atom, a }))
    return false;
  if (!isUsableValue(length) || length < 0.0)
    return false; // a distance is never negative
  if (!fragmentMoves(molecule, fragment, atom))
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
  if (!fragmentMoves(molecule, fragment, atom))
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
  if (!fragmentMoves(molecule, fragment, atom))
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

} // namespace Avogadro::QtGui
