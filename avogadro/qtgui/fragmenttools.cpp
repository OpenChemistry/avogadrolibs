/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fragmenttools.h"

#include "rwmolecule.h"

#include <avogadro/core/angletools.h>

#include <QtCore/QObject>

#include <algorithm>
#include <initializer_list>
#include <vector>

namespace Avogadro::QtGui {

namespace {

bool fragmentHasAtom(const Core::Array<Index>& fragment, Index uniqueId)
{
  return std::find(fragment.begin(), fragment.end(), uniqueId) !=
         fragment.end();
}

/**
 * Walk outwards from @p currentAtom, adding everything reachable without
 * crossing @p bond.
 *
 * @p bond stays the bond being split all the way down, so that the far end
 * looked for is always the right atom. Handing the recursion the bond just
 * traversed instead would ask getOtherAtom() for an atom that is not in it,
 * which quietly answers with one of its own -- and then a ring is only
 * noticed when it closes within a single step.
 *
 * @return False as soon as the far end of @p bond is reached by another
 * route, which means the bond is in a ring.
 */
bool fragmentRecurse(RWMolecule& molecule, const RWBond& bond,
                     const RWAtom& startAtom, const RWAtom& currentAtom,
                     Core::Array<Index>& fragment)
{
  const RWAtom bondedAtom(bond.getOtherAtom(startAtom));
  const Core::Array<RWBond> bonds = molecule.bonds(currentAtom);

  for (const auto& it : bonds) {
    if (it == bond)
      continue; // never cross the bond being split

    const RWAtom nextAtom = it.getOtherAtom(currentAtom);
    if (nextAtom == bondedAtom)
      return false; // reached the far end another way, so this is a ring

    if (nextAtom != startAtom) {
      // Atoms already collected are skipped, which is what stops the
      // recursion running away around a ring elsewhere in the fragment.
      const Index uniqueId = molecule.atomUniqueId(nextAtom);
      if (!fragmentHasAtom(fragment, uniqueId)) {
        fragment.push_back(uniqueId);
        if (!fragmentRecurse(molecule, bond, startAtom, nextAtom, fragment))
          return false;
      }
    }
  }

  return true;
}

} // namespace

Core::Array<Index> FragmentTools::fragmentUniqueIds(RWMolecule& molecule,
                                                    const RWBond& bond,
                                                    const RWAtom& startAtom)
{
  Core::Array<Index> fragment;
  if (!fragmentRecurse(molecule, bond, startAtom, startAtom, fragment)) {
    // The bond is in a ring, so there is no side of it that can move on its
    // own. Move the single atom and leave the ring intact.
    fragment.clear();
  }
  fragment.push_back(molecule.atomUniqueId(startAtom));

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
                                   const Eigen::Affine3d& transform,
                                   const QString& undoText)
{
  molecule.beginMergeMode(undoText);
  for (const Index uniqueId : uniqueIds) {
    RWAtom atom = molecule.atomByUniqueId(uniqueId);
    if (atom.isValid())
      atom.setPosition3d(transform * atom.position3d());
  }
  molecule.endMergeMode();
}

namespace {

// Below this the two points are treated as coincident and the direction
// between them carries no information.
const Real coincidentTolerance = 1e-8;

// |sin| below which three points are treated as collinear, leaving no
// well-defined plane to rotate in or about.
const Real collinearTolerance = 1e-6;

// The named atoms must all exist and all be different, or the coordinate
// does not describe anything.
bool distinctAndValid(RWMolecule& molecule, std::initializer_list<Index> atoms)
{
  const std::vector<Index> named(atoms);
  for (size_t i = 0; i < named.size(); ++i) {
    if (!molecule.atom(named[i]).isValid())
      return false;
    for (size_t j = i + 1; j < named.size(); ++j) {
      if (named[i] == named[j])
        return false;
    }
  }
  return true;
}

} // namespace

bool FragmentTools::setDistance(RWMolecule& molecule, Index atom, Index a,
                                Real length)
{
  if (!distinctAndValid(molecule, { atom, a }))
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

  transformAtoms(molecule, fragmentUniqueIds(molecule, a, atom), transform,
                 QObject::tr("Adjust Distance"));
  return true;
}

bool FragmentTools::setAngle(RWMolecule& molecule, Index atom, Index a, Index b,
                             Real degrees)
{
  if (!distinctAndValid(molecule, { atom, a, b }))
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

  transformAtoms(molecule, fragmentUniqueIds(molecule, a, atom), transform,
                 QObject::tr("Adjust Angle"));
  return true;
}

bool FragmentTools::setTorsion(RWMolecule& molecule, Index atom, Index a,
                               Index b, Index c, Real degrees)
{
  if (!distinctAndValid(molecule, { atom, a, b, c }))
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

  const Real change =
    (degrees - calculateDihedral(position, positionA, positionB, positionC)) *
    DEG_TO_RAD;

  Eigen::Affine3d transform;
  transform.setIdentity();
  transform.translate(positionA);
  transform.rotate(Eigen::AngleAxis<Real>(-change, axis));
  transform.translate(-positionA);

  transformAtoms(molecule, fragmentUniqueIds(molecule, a, atom), transform,
                 QObject::tr("Adjust Torsion"));
  return true;
}

} // namespace Avogadro::QtGui
