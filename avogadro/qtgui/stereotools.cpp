/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "stereotools.h"

#include "molecule.h"
#include "rwmolecule.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/graph.h>
#include <avogadro/core/vector.h>

#include <Eigen/Geometry>

#include <algorithm>
#include <array>
#include <cmath>
#include <vector>

namespace {

using Avogadro::Core::Carbon;
using Avogadro::Core::Graph;
using Avogadro::Index;
using Avogadro::Vector3;

constexpr double minNormSquared = 1.0e-8;
constexpr double minSignedDistance = 1.0e-5;
constexpr double antiParallelDotTolerance = -0.999999;
constexpr double pi = 3.14159265358979323846;

std::vector<Index> collectSubstituentAtoms(const Graph& graph, Index centerAtom,
                                           Index startAtom)
{
  std::vector<Index> component;
  std::vector<bool> visited(graph.size(), false);
  std::vector<Index> stack{ startAtom };
  visited[startAtom] = true;

  while (!stack.empty()) {
    Index current = stack.back();
    stack.pop_back();
    component.push_back(current);

    for (size_t neighbor : graph.neighbors(current)) {
      if (neighbor == centerAtom || visited[neighbor])
        continue;

      visited[neighbor] = true;
      stack.push_back(static_cast<Index>(neighbor));
    }
  }

  return component;
}

bool containsAnyOtherNeighbor(const std::vector<Index>& component,
                              const std::vector<Index>& neighbors,
                              Index currentNeighbor)
{
  return std::any_of(neighbors.begin(), neighbors.end(), [&](Index neighbor) {
    return neighbor != currentNeighbor &&
           std::find(component.begin(), component.end(), neighbor) !=
             component.end();
  });
}

double signedDistanceToPlane(const Vector3& planeOrigin, const Vector3& normal,
                             const Vector3& point)
{
  return normal.dot(point - planeOrigin);
}

bool isUsableDirection(const Vector3& direction)
{
  return std::isfinite(direction.x()) && std::isfinite(direction.y()) &&
         std::isfinite(direction.z()) &&
         direction.squaredNorm() > minNormSquared;
}

Vector3 candidateDirectionFromPlaneReflection(const Vector3& centerPosition,
                                              const Vector3& candidateVector,
                                              const Vector3& planeOrigin,
                                              const Vector3& planeNormal)
{
  const Vector3 candidatePosition = centerPosition + candidateVector;
  const double signedDistance =
    signedDistanceToPlane(planeOrigin, planeNormal, candidatePosition);
  const Vector3 reflectedPosition =
    candidatePosition - 2.0 * signedDistance * planeNormal;
  return reflectedPosition - centerPosition;
}

Vector3 candidateDirectionFromSphereIntersection(
  const Vector3& centerPosition, const Vector3& candidateDirection,
  const Vector3& planeOrigin, const Vector3& planeNormal,
  double originalSignedDistance)
{
  const double bondLength = candidateDirection.norm();
  if (bondLength * bondLength <= minNormSquared)
    return Vector3::Zero();

  const double centerSignedDistance =
    signedDistanceToPlane(planeOrigin, planeNormal, centerPosition);
  const double targetNormalComponent =
    (-originalSignedDistance - centerSignedDistance) / bondLength;
  if (std::abs(targetNormalComponent) > 1.0)
    return Vector3::Zero();

  Vector3 tangent =
    candidateDirection.normalized() -
    candidateDirection.normalized().dot(planeNormal) * planeNormal;
  if (tangent.squaredNorm() <= minNormSquared)
    tangent = planeNormal.unitOrthogonal();
  else
    tangent.normalize();

  const double tangentScale =
    std::sqrt(std::max(0.0, 1.0 - targetNormalComponent * targetNormalComponent));
  return tangentScale * tangent + targetNormalComponent * planeNormal;
}

bool flipsConfiguration(const Vector3& centerPosition,
                        const Vector3& candidateDirection,
                        const Vector3& planeOrigin, const Vector3& planeNormal,
                        double originalSignedDistance)
{
  const Vector3 rotatedPosition = centerPosition + candidateDirection;
  const double rotatedSignedDistance =
    signedDistanceToPlane(planeOrigin, planeNormal, rotatedPosition);

  return std::abs(rotatedSignedDistance) > minSignedDistance &&
         originalSignedDistance * rotatedSignedDistance < 0.0;
}

Eigen::Quaterniond stereochemistryRotation(const Vector3& from,
                                          const Vector3& to,
                                          const std::array<Vector3, 3>& fixed)
{
  const Vector3 fromDirection = from.normalized();
  const Vector3 toDirection = to.normalized();
  const double directionDot = fromDirection.dot(toDirection);

  if (directionDot > antiParallelDotTolerance)
    return Eigen::Quaterniond::FromTwoVectors(fromDirection, toDirection);

  std::array<Vector3, 3> candidateAxes = {
    fixed[0] - fixed[1],
    fixed[1] - fixed[2],
    fixed[2] - fixed[0],
  };

  for (Vector3 axis : candidateAxes) {
    axis -= axis.dot(fromDirection) * fromDirection;
    if (axis.squaredNorm() <= minNormSquared)
      continue;

    axis.normalize();
    return Eigen::Quaterniond(Eigen::AngleAxisd(pi, axis));
  }

  return Eigen::Quaterniond(
    Eigen::AngleAxisd(pi, fromDirection.unitOrthogonal()));
}

} // namespace

namespace Avogadro::QtGui {

StereoInversionResult StereoTools::invertTetrahedralCenter(RWMolecule& molecule,
                                                           Index atomId)
{
  if (atomId >= molecule.atomCount())
    return StereoInversionResult::InvalidAtom;

  const auto centerAtom = molecule.atom(atomId);
  if (!centerAtom.isValid())
    return StereoInversionResult::InvalidAtom;
  if (centerAtom.atomicNumber() != Carbon)
    return StereoInversionResult::NonCarbonCenter;

  const Graph& graph = molecule.molecule().graph();
  std::vector<Index> neighbors;
  for (size_t neighbor : graph.neighbors(atomId))
    neighbors.push_back(static_cast<Index>(neighbor));

  if (neighbors.size() != 4)
    return StereoInversionResult::NonTetrahedralCenter;

  for (Index neighbor : neighbors) {
    auto bond = molecule.bond(atomId, neighbor);
    if (!bond.isValid() || bond.order() != 1)
      return StereoInversionResult::UnsupportedBondOrders;
  }

  struct Candidate
  {
    Index neighbor = MaxIndex;
    std::vector<Index> atoms;
    bool hydrogen = false;
  };

  Candidate bestCandidate;
  for (Index neighbor : neighbors) {
    std::vector<Index> component =
      collectSubstituentAtoms(graph, atomId, neighbor);
    if (containsAnyOtherNeighbor(component, neighbors, neighbor))
      continue;

    Candidate candidate{ neighbor, std::move(component),
                         molecule.atomicNumber(neighbor) == 1 };
    if (bestCandidate.neighbor == MaxIndex ||
        (candidate.hydrogen && !bestCandidate.hydrogen) ||
        (candidate.hydrogen == bestCandidate.hydrogen &&
         candidate.atoms.size() < bestCandidate.atoms.size())) {
      bestCandidate = std::move(candidate);
    }
  }

  if (bestCandidate.neighbor == MaxIndex)
    return StereoInversionResult::NoMovableSubstituent;

  const Vector3 centerPosition = molecule.atomPosition3d(atomId);
  const Vector3 candidateVector =
    molecule.atomPosition3d(bestCandidate.neighbor) - centerPosition;
  if (!isUsableDirection(candidateVector))
    return StereoInversionResult::DegenerateGeometry;

  std::array<Index, 3> fixedNeighbors{};
  size_t fixedIndex = 0;
  for (Index neighbor : neighbors) {
    if (neighbor != bestCandidate.neighbor)
      fixedNeighbors[fixedIndex++] = neighbor;
  }

  const Vector3 planeOrigin = molecule.atomPosition3d(fixedNeighbors[0]);
  const std::array<Vector3, 3> fixedVectors = {
    molecule.atomPosition3d(fixedNeighbors[0]) - centerPosition,
    molecule.atomPosition3d(fixedNeighbors[1]) - centerPosition,
    molecule.atomPosition3d(fixedNeighbors[2]) - centerPosition,
  };
  const Vector3 planeVector1 = fixedVectors[1] - fixedVectors[0];
  const Vector3 planeVector2 = fixedVectors[2] - fixedVectors[0];
  Vector3 planeNormal = planeVector1.cross(planeVector2);
  if (!isUsableDirection(planeNormal))
    return StereoInversionResult::DegenerateGeometry;
  planeNormal.normalize();

  const Vector3 candidatePosition = centerPosition + candidateVector;
  const double originalSignedDistance =
    signedDistanceToPlane(planeOrigin, planeNormal, candidatePosition);
  if (std::abs(originalSignedDistance) <= minSignedDistance)
    return StereoInversionResult::DegenerateGeometry;

  std::vector<Vector3> candidateDirections;
  Vector3 reflectedDirection = candidateDirectionFromPlaneReflection(
    centerPosition, candidateVector, planeOrigin, planeNormal);
  if (isUsableDirection(reflectedDirection))
    candidateDirections.push_back(reflectedDirection);

  Vector3 intersectedDirection = candidateDirectionFromSphereIntersection(
    centerPosition, candidateVector, planeOrigin, planeNormal,
    originalSignedDistance);
  if (isUsableDirection(intersectedDirection))
    candidateDirections.push_back(candidateVector.norm() *
                                  intersectedDirection.normalized());

  Vector3 centroidDirection = Vector3::Zero();
  for (Index neighbor : fixedNeighbors) {
    Vector3 direction = molecule.atomPosition3d(neighbor) - centerPosition;
    if (!isUsableDirection(direction))
      return StereoInversionResult::DegenerateGeometry;
    centroidDirection += direction.normalized();
  }
  if (isUsableDirection(centroidDirection))
    candidateDirections.push_back(candidateVector.norm() *
                                  centroidDirection.normalized());

  Vector3 selectedDirection = Vector3::Zero();
  for (const Vector3& direction : candidateDirections) {
    if (!isUsableDirection(direction))
      continue;
    if (flipsConfiguration(centerPosition, direction, planeOrigin, planeNormal,
                           originalSignedDistance)) {
      selectedDirection = direction;
      break;
    }
  }

  if (!isUsableDirection(selectedDirection))
    return StereoInversionResult::DegenerateGeometry;

  const Eigen::Quaterniond rotation =
    stereochemistryRotation(candidateVector, selectedDirection, fixedVectors);
  if (!std::isfinite(rotation.x()) || !std::isfinite(rotation.y()) ||
      !std::isfinite(rotation.z()) || !std::isfinite(rotation.w()))
    return StereoInversionResult::DegenerateGeometry;

  molecule.undoStack().beginMacro(QStringLiteral("Invert Tetrahedral Center"));
  for (Index movingAtom : bestCandidate.atoms) {
    const Vector3 currentPosition = molecule.atomPosition3d(movingAtom);
    const Vector3 rotatedPosition =
      centerPosition + rotation * (currentPosition - centerPosition);
    molecule.setAtomPosition3d(movingAtom, rotatedPosition,
                               QStringLiteral("Invert Tetrahedral Center"));
  }
  molecule.undoStack().endMacro();
  molecule.emitChanged(Molecule::Atoms | Molecule::Modified);

  return StereoInversionResult::Success;
}

} // namespace Avogadro::QtGui
