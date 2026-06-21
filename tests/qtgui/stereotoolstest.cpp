/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/stereotools.h>

#include <Eigen/Geometry>

using Avogadro::Vector3;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWAtom;
using Avogadro::QtGui::RWMolecule;
using Avogadro::QtGui::StereoInversionResult;
using Avogadro::QtGui::StereoTools;

namespace {

double signedDistanceToPlane(const Vector3& origin, const Vector3& a,
                             const Vector3& b, const Vector3& point)
{
  const Vector3 normal = (a - origin).cross(b - origin).normalized();
  return normal.dot(point - origin);
}

} // namespace

TEST(StereoToolsTest, invertSimpleTetrahedralCarbon)
{
  Molecule molecule;
  RWMolecule mol(molecule);

  RWAtom center = mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  RWAtom hydrogen = mol.addAtom(1, Vector3(0.75, 0.70, 0.65));
  RWAtom fluorine = mol.addAtom(9, Vector3(-1.00, -0.55, 0.80));
  RWAtom chlorine = mol.addAtom(17, Vector3(-0.70, 1.05, -0.45));
  RWAtom bromine = mol.addAtom(35, Vector3(0.95, -0.75, -0.95));

  mol.addBond(center, hydrogen);
  mol.addBond(center, fluorine);
  mol.addBond(center, chlorine);
  mol.addBond(center, bromine);

  const Vector3 centerPosition = center.position3d();
  const double originalDistance =
    (hydrogen.position3d() - centerPosition).norm();
  const double originalSign = signedDistanceToPlane(
    fluorine.position3d(), chlorine.position3d(), bromine.position3d(),
    hydrogen.position3d());

  EXPECT_EQ(StereoTools::invertTetrahedralCenter(mol, center.index()),
            StereoInversionResult::Success);

  const double invertedDistance =
    (hydrogen.position3d() - centerPosition).norm();
  const double invertedSign = signedDistanceToPlane(
    fluorine.position3d(), chlorine.position3d(), bromine.position3d(),
    hydrogen.position3d());

  EXPECT_LT(originalSign * invertedSign, 0.0);
  EXPECT_NEAR(originalDistance, invertedDistance, 1.0e-6);
}

TEST(StereoToolsTest, invertRingLikeTetrahedralCarbon)
{
  Molecule molecule;
  RWMolecule mol(molecule);

  RWAtom center = mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  RWAtom hydrogen = mol.addAtom(1, Vector3(0.85, 0.15, 0.70));
  RWAtom methyl = mol.addAtom(6, Vector3(-1.00, 0.20, 0.65));
  RWAtom ringA = mol.addAtom(6, Vector3(-0.55, 1.05, -0.75));
  RWAtom ringB = mol.addAtom(6, Vector3(0.75, -1.05, -0.70));
  RWAtom ringBridge1 = mol.addAtom(6, Vector3(0.10, 1.60, -1.10));
  RWAtom ringBridge2 = mol.addAtom(6, Vector3(1.00, 0.20, -1.25));
  RWAtom methylH1 = mol.addAtom(1, Vector3(-1.70, 0.85, 1.05));
  RWAtom methylH2 = mol.addAtom(1, Vector3(-1.35, -0.75, 0.95));
  RWAtom methylH3 = mol.addAtom(1, Vector3(-1.40, 0.40, -0.35));

  mol.addBond(center, hydrogen);
  mol.addBond(center, methyl);
  mol.addBond(center, ringA);
  mol.addBond(center, ringB);
  mol.addBond(ringA, ringBridge1);
  mol.addBond(ringBridge1, ringBridge2);
  mol.addBond(ringBridge2, ringB);
  mol.addBond(methyl, methylH1);
  mol.addBond(methyl, methylH2);
  mol.addBond(methyl, methylH3);

  const double originalSign = signedDistanceToPlane(
    methyl.position3d(), ringA.position3d(), ringB.position3d(),
    hydrogen.position3d());

  EXPECT_EQ(StereoTools::invertTetrahedralCenter(mol, center.index()),
            StereoInversionResult::Success);

  const double invertedSign = signedDistanceToPlane(
    methyl.position3d(), ringA.position3d(), ringB.position3d(),
    hydrogen.position3d());

  EXPECT_LT(originalSign * invertedSign, 0.0);
}

TEST(StereoToolsTest, rejectCentersWithoutIsolatedSubstituent)
{
  Molecule molecule;
  RWMolecule mol(molecule);

  RWAtom center = mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  RWAtom a = mol.addAtom(6, Vector3(0.85, 0.20, 0.75));
  RWAtom b = mol.addAtom(6, Vector3(-0.95, -0.30, 0.75));
  RWAtom c = mol.addAtom(6, Vector3(-0.75, 1.00, -0.55));
  RWAtom d = mol.addAtom(6, Vector3(0.90, -0.95, -0.55));

  mol.addBond(center, a);
  mol.addBond(center, b);
  mol.addBond(center, c);
  mol.addBond(center, d);
  mol.addBond(a, b);
  mol.addBond(b, c);
  mol.addBond(c, d);

  EXPECT_EQ(StereoTools::invertTetrahedralCenter(mol, center.index()),
            StereoInversionResult::NoMovableSubstituent);
}

TEST(StereoToolsTest, invertMultiAtomSubstituentOnRegularTetrahedron)
{
  Molecule molecule;
  RWMolecule mol(molecule);

  RWAtom center = mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  RWAtom methyl = mol.addAtom(6, Vector3(1.0, 1.0, 1.0));
  RWAtom fixedA = mol.addAtom(6, Vector3(-1.0, -1.0, 1.0));
  RWAtom fixedB = mol.addAtom(6, Vector3(-1.0, 1.0, -1.0));
  RWAtom fixedC = mol.addAtom(6, Vector3(1.0, -1.0, -1.0));
  RWAtom methylH1 = mol.addAtom(1, Vector3(1.75, 1.10, 1.35));
  RWAtom methylH2 = mol.addAtom(1, Vector3(1.10, 1.80, 1.20));
  RWAtom methylH3 = mol.addAtom(1, Vector3(1.25, 1.05, 1.95));

  mol.addBond(center, methyl);
  mol.addBond(center, fixedA);
  mol.addBond(center, fixedB);
  mol.addBond(center, fixedC);
  mol.addBond(fixedA, fixedB);
  mol.addBond(fixedB, fixedC);
  mol.addBond(methyl, methylH1);
  mol.addBond(methyl, methylH2);
  mol.addBond(methyl, methylH3);

  const double originalSign = signedDistanceToPlane(
    fixedA.position3d(), fixedB.position3d(), fixedC.position3d(),
    methyl.position3d());

  Vector3 axis = fixedA.position3d() - fixedB.position3d();
  axis -= axis.dot(methyl.position3d().normalized()) *
          methyl.position3d().normalized();
  axis.normalize();

  const Eigen::Quaterniond expectedRotation(
    Eigen::AngleAxisd(3.14159265358979323846, axis));
  const Vector3 expectedMethylH1 = expectedRotation * methylH1.position3d();

  EXPECT_EQ(StereoTools::invertTetrahedralCenter(mol, center.index()),
            StereoInversionResult::Success);

  const double invertedSign = signedDistanceToPlane(
    fixedA.position3d(), fixedB.position3d(), fixedC.position3d(),
    methyl.position3d());

  EXPECT_LT(originalSign * invertedSign, 0.0);
  EXPECT_NEAR((methylH1.position3d() - expectedMethylH1).norm(), 0.0, 1.0e-6);
}
