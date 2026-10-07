/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/avospglib.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <map>
#include <string>
#include <vector>

using Avogadro::Matrix3;
using Avogadro::Vector3;
using Avogadro::Core::AvoSpglib;
using Avogadro::Core::Molecule;
using Avogadro::Core::SpaceGroups;
using Avogadro::Core::UnitCell;
using namespace std::string_literals;

TEST(SpaceGroupTest, getSpaceGroup)
{
  Molecule mol;

  // First, let's build rutile
  mol.setData("name", "TiO2 rutile");

  Matrix3 mat;
  mat.col(0) = Vector3(2.95812, 0.00000, 0.00000); // A
  mat.col(1) = Vector3(0.00000, 4.59373, 0.00000); // B
  mat.col(2) = Vector3(0.00000, 0.00000, 4.59373); // C

  UnitCell* uc = new UnitCell(mat);

  mol.setUnitCell(uc);

  mol.addAtom(8).setPosition3d(uc->toCartesian(Vector3(0.0, 0.3053, 0.3053)));
  mol.addAtom(8).setPosition3d(uc->toCartesian(Vector3(0.0, 0.6947, 0.6947)));
  mol.addAtom(8).setPosition3d(uc->toCartesian(Vector3(0.5, 0.1947, 0.8053)));
  mol.addAtom(8).setPosition3d(uc->toCartesian(Vector3(0.5, 0.8053, 0.1947)));
  mol.addAtom(22).setPosition3d(uc->toCartesian(Vector3(0.0, 0.0, 0.0)));
  mol.addAtom(22).setPosition3d(uc->toCartesian(Vector3(0.5, 0.5, 0.5)));

  // Now let's find the space group of this crystal!
  double cartTol = 0.05;
  unsigned short hallNumber = AvoSpglib::getHallNumber(mol, cartTol);

  EXPECT_EQ(hallNumber, 419);

  unsigned short intNumber = SpaceGroups::internationalNumber(hallNumber);
  std::string schoenflies = SpaceGroups::schoenflies(hallNumber);
  std::string hallSymbol = SpaceGroups::hallSymbol(hallNumber);
  std::string intSymbol = SpaceGroups::internationalFull(hallNumber);

  EXPECT_EQ(intNumber, 136);
  EXPECT_EQ(schoenflies, "D4h^14"s);
  EXPECT_EQ(hallSymbol, "-P 4n 2n"s);
  EXPECT_EQ(intSymbol, "P 4_2/m 2_1/n 2/m"s);
}

// We're going to take a conventional cell, reduce it to the primitive form,
// and check our results
TEST(SpaceGroupTest, reduceToPrimitive)
{
  // Let's build a primitive cell of corundum!
  Molecule primMol;
  Matrix3 primMat;
  primMat.col(0) = Vector3(5.12980369, 0.00000000, 0.00000000); // A
  primMat.col(1) = Vector3(2.92081932, 4.21707249, 0.00000000); // B
  primMat.col(2) = Vector3(2.92081932, 1.52998182, 3.92973995); // C

  UnitCell* primUC = new UnitCell(primMat);
  primMol.setUnitCell(primUC);

  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.94365, 0.55635, 0.25)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.25000, 0.94365, 0.55635)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.55635, 0.25000, 0.94365)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.05635, 0.44365, 0.75000)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.75000, 0.05635, 0.44365)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.44365, 0.75000, 0.05635)));
  primMol.addAtom(13).setPosition3d(
    primUC->toCartesian(Vector3(0.35217, 0.35217, 0.35217)));
  primMol.addAtom(13).setPosition3d(
    primUC->toCartesian(Vector3(0.14783, 0.14783, 0.14783)));
  primMol.addAtom(13).setPosition3d(
    primUC->toCartesian(Vector3(0.64783, 0.64783, 0.64783)));
  primMol.addAtom(13).setPosition3d(
    primUC->toCartesian(Vector3(0.85217, 0.85217, 0.85217)));

  // Now, let's build a conventional cell of corundum
  Molecule convMol;
  Matrix3 convMat;
  convMat.col(0) = Vector3(4.76060000, 0.00000000, 0.00000000);  // A
  convMat.col(1) = Vector3(-2.3803000, 4.12280054, 0.00000000);  // B
  convMat.col(2) = Vector3(0.00000000, 0.00000000, 12.99400000); // C

  UnitCell* convUC = new UnitCell(convMat);
  convMol.setUnitCell(convUC);

  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.69365000, 0.00000000, 0.25000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.69365000, 0.25000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.30635000, 0.30635000, 0.25000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.30635000, 0.00000000, 0.75000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.30635000, 0.75000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.69365000, 0.69365000, 0.75000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.36031667, 0.33333333, 0.58333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.02698333, 0.58333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.97301667, 0.63968333, 0.58333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.97301667, 0.33333333, 0.08333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.63968333, 0.08333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.36031667, 0.02698333, 0.08333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.02698333, 0.66666667, 0.91666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.36031667, 0.91666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.63968333, 0.97301667, 0.91666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.63968333, 0.66666667, 0.41666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.97301667, 0.41666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.02698333, 0.36031667, 0.41666667)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.00000000, 0.35217000)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.00000000, 0.14783000)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.00000000, 0.64783000)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.00000000, 0.85217000)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.33333333, 0.68550333)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.33333333, 0.48116333)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.33333333, 0.98116333)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.33333333, 0.18550333)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.66666667, 0.01883667)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.66666667, 0.81449667)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.66666667, 0.31449667)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.66666667, 0.51883667)));

  // This should reduce the number of atoms in convMol to be
  // equivalent to that of the primitive corundum
  EXPECT_TRUE(AvoSpglib::reduceToPrimitive(convMol, 1e-5));

  // Numbers of atoms and volumes should be equal
  ASSERT_EQ(convMol.atomCount(), primMol.atomCount());
  // We compare volumes as floats instead of doubles to allow for a little bit
  // of a difference between them.
  ASSERT_FLOAT_EQ(convMol.unitCell()->volume(), primMol.unitCell()->volume());
}

// We're going to take a primitive cell, conventionalize it,
// and check our results
TEST(SpaceGroupTest, conventionalizeCell)
{
  // Let's build a primitive cell of corundum!
  Molecule primMol;
  Matrix3 primMat;
  primMat.col(0) = Vector3(5.12980369, 0.00000000, 0.00000000); // A
  primMat.col(1) = Vector3(2.92081932, 4.21707249, 0.00000000); // B
  primMat.col(2) = Vector3(2.92081932, 1.52998182, 3.92973995); // C

  UnitCell* primUC = new UnitCell(primMat);
  primMol.setUnitCell(primUC);

  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.94365, 0.55635, 0.25000)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.25000, 0.94365, 0.55635)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.55635, 0.25000, 0.94365)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.05635, 0.44365, 0.75000)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.75000, 0.05635, 0.44365)));
  primMol.addAtom(8).setPosition3d(
    primUC->toCartesian(Vector3(0.44365, 0.75000, 0.05635)));
  primMol.addAtom(13).setPosition3d(
    primUC->toCartesian(Vector3(0.35217, 0.35217, 0.35217)));
  primMol.addAtom(13).setPosition3d(
    primUC->toCartesian(Vector3(0.14783, 0.14783, 0.14783)));
  primMol.addAtom(13).setPosition3d(
    primUC->toCartesian(Vector3(0.64783, 0.64783, 0.64783)));
  primMol.addAtom(13).setPosition3d(
    primUC->toCartesian(Vector3(0.85217, 0.85217, 0.85217)));

  // Now, let's build a conventional cell of corundum
  Molecule convMol;
  Matrix3 convMat;
  convMat.col(0) = Vector3(4.76060000, 0.00000000, 0.00000000);  // A
  convMat.col(1) = Vector3(-2.3803000, 4.12280054, 0.00000000);  // B
  convMat.col(2) = Vector3(0.00000000, 0.00000000, 12.99400000); // C

  UnitCell* convUC = new UnitCell(convMat);
  convMol.setUnitCell(convUC);

  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.69365000, 0.00000000, 0.25000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.69365000, 0.25000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.30635000, 0.30635000, 0.25000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.30635000, 0.00000000, 0.75000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.30635000, 0.75000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.69365000, 0.69365000, 0.75000000)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.36031667, 0.33333333, 0.58333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.02698333, 0.58333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.97301667, 0.63968333, 0.58333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.97301667, 0.33333333, 0.08333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.63968333, 0.08333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.36031667, 0.02698333, 0.08333333)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.02698333, 0.66666667, 0.91666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.36031667, 0.91666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.63968333, 0.97301667, 0.91666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.63968333, 0.66666667, 0.41666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.97301667, 0.41666667)));
  convMol.addAtom(8).setPosition3d(
    convUC->toCartesian(Vector3(0.02698333, 0.36031667, 0.41666667)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.00000000, 0.35217000)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.00000000, 0.14783000)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.00000000, 0.64783000)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.00000000, 0.00000000, 0.85217000)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.33333333, 0.68550333)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.33333333, 0.48116333)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.33333333, 0.98116333)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.66666667, 0.33333333, 0.18550333)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.66666667, 0.01883667)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.66666667, 0.81449667)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.66666667, 0.31449667)));
  convMol.addAtom(13).setPosition3d(
    convUC->toCartesian(Vector3(0.33333333, 0.66666667, 0.51883667)));

  // This should increase the number of atoms in primMol to match
  // that of convMol
  EXPECT_TRUE(AvoSpglib::conventionalizeCell(primMol, 1e-5));

  // Numbers of atoms and volumes should be identical
  ASSERT_EQ(convMol.atomCount(), primMol.atomCount());
  // We compare volumes as floats instead of doubles to allow for a little bit
  // of a difference between them.
  ASSERT_FLOAT_EQ(convMol.unitCell()->volume(), primMol.unitCell()->volume());
}

TEST(SpaceGroupTest, fillUnitCell)
{
  double cartTol = 1e-5;

  // MgSiO3 - post-perovskite. Space group: Cmcm. Found in the mantle of the
  // earth.
  // http://crystallography.net/cod/9009217.html
  Molecule mol1;
  Matrix3 mat1;
  mat1.col(0) = Vector3(2.456, 0.000, 0.000); // A
  mat1.col(1) = Vector3(0.000, 8.042, 0.000); // B
  mat1.col(2) = Vector3(0.000, 0.000, 6.093); // C

  UnitCell* uc1 = new UnitCell(mat1);
  mol1.setUnitCell(uc1);

  mol1.addAtom(12).setPosition3d(
    uc1->toCartesian(Vector3(0.000, 0.253, 0.250)));
  mol1.addAtom(14).setPosition3d(
    uc1->toCartesian(Vector3(0.000, 0.000, 0.000)));
  mol1.addAtom(8).setPosition3d(uc1->toCartesian(Vector3(0.000, 0.923, 0.250)));
  mol1.addAtom(8).setPosition3d(uc1->toCartesian(Vector3(0.000, 0.631, 0.436)));

  // Now, let's perform a fillUnitCell. hallNumber 298 is Cmcm
  // International: 63
  SpaceGroups::fillUnitCell(mol1, 298, cartTol);

  // It should now have a hall number of 298
  unsigned short hallNumber1 = AvoSpglib::getHallNumber(mol1, cartTol);
  ASSERT_EQ(hallNumber1, 298);

  // It should now have 20 atoms
  ASSERT_EQ(mol1.atomCount(), 20);

  // CaMg(CO3)2 - dolomite. Space group: hexagonal R -3. It is a brittle
  // mineral found in limestones and other common places.
  // http://crystallography.net/cod/1517795.html
  Molecule mol2;
  Matrix3 mat2;

  mat2.col(0) = Vector3(4.808, 0.00000, 0.000);  // A
  mat2.col(1) = Vector3(-2.404, 4.16385, 0.000); // B
  mat2.col(2) = Vector3(0.000, 0.00000, 16.022); // C

  UnitCell* uc2 = new UnitCell(mat2);
  mol2.setUnitCell(uc2);

  mol2.addAtom(20).setPosition3d(
    uc2->toCartesian(Vector3(0.0000, 0.0000, 0.0000)));
  mol2.addAtom(12).setPosition3d(
    uc2->toCartesian(Vector3(0.0000, 0.0000, 0.5000)));
  mol2.addAtom(6).setPosition3d(
    uc2->toCartesian(Vector3(0.0000, 0.0000, 0.24287)));
  mol2.addAtom(8).setPosition3d(
    uc2->toCartesian(Vector3(0.24796, 0.9653, 0.24402)));

  // Now, let's perform a fillUnitCell. hallNumber 436 is hexagonal R -3
  // International: 148
  SpaceGroups::fillUnitCell(mol2, 436, cartTol);

  // It should now have a hall number of 436
  unsigned short hallNumber2 = AvoSpglib::getHallNumber(mol2, cartTol);
  ASSERT_EQ(hallNumber2, 436);

  // It should now have 30 atoms
  ASSERT_EQ(mol2.atomCount(), 30);

  // CaSiO3 - wollastonite. Space group: P -1. It is found in limestones
  // and other common minerals. Used in ceramics, brakes, clutches,
  // metalmaking, paint filler, and plastics.
  // http://crystallography.net/cod/9005777.html
  Molecule mol3;
  Matrix3 mat3;

  mat3.col(0) = Vector3(7.92580, 0.00000, 0.00000);   // A
  mat3.col(1) = Vector3(-1.69967, 7.12014, 0.00000);  // B
  mat3.col(2) = Vector3(-0.64243, -0.16033, 7.03420); // C

  UnitCell* uc3 = new UnitCell(mat3);
  mol3.setUnitCell(uc3);

  mol3.addAtom(20).setPosition3d(
    uc3->toCartesian(Vector3(0.198310, 0.42266, 0.76060)));
  mol3.addAtom(20).setPosition3d(
    uc3->toCartesian(Vector3(0.202410, 0.92919, 0.76401)));
  mol3.addAtom(20).setPosition3d(
    uc3->toCartesian(Vector3(0.503330, 0.75040, 0.52691)));
  mol3.addAtom(14).setPosition3d(
    uc3->toCartesian(Vector3(0.185100, 0.38750, 0.26840)));
  mol3.addAtom(14).setPosition3d(
    uc3->toCartesian(Vector3(0.184900, 0.95420, 0.26910)));
  mol3.addAtom(14).setPosition3d(
    uc3->toCartesian(Vector3(0.397300, 0.72360, 0.05610)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.303400, 0.46160, 0.46280)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.301400, 0.93850, 0.46410)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.570500, 0.76880, 0.19880)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.983200, 0.37390, 0.26550)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.981900, 0.86770, 0.26480)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.401800, 0.72660, 0.82960)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.218300, 0.17850, 0.22540)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.271300, 0.87040, 0.09380)));
  mol3.addAtom(8).setPosition3d(
    uc3->toCartesian(Vector3(0.273500, 0.51260, 0.09310)));

  // Now, let's perform a fillUnitCell. hallNumber 2 is hexagonal P -1
  // International: 2
  SpaceGroups::fillUnitCell(mol3, 2, cartTol);

  // It should now have a hall number of 2
  unsigned short hallNumber3 = AvoSpglib::getHallNumber(mol3, cartTol);
  ASSERT_EQ(hallNumber3, 2);

  // It should now have 30 atoms
  ASSERT_EQ(mol3.atomCount(), 30);
}

TEST(SpaceGroupTest, reduceToAsymmetricUnit)
{
  double cartTol = 1e-5;

  // Let's build rutile for the first test
  Molecule mol1;
  mol1.setData("name", "TiO2 rutile");

  Matrix3 mat1;
  mat1.col(0) = Vector3(2.95812, 0.00000, 0.00000); // A
  mat1.col(1) = Vector3(0.00000, 4.59373, 0.00000); // B
  mat1.col(2) = Vector3(0.00000, 0.00000, 4.59373); // C

  UnitCell* uc1 = new UnitCell(mat1);

  mol1.setUnitCell(uc1);

  mol1.addAtom(8).setPosition3d(uc1->toCartesian(Vector3(0.0, 0.3053, 0.3053)));
  mol1.addAtom(8).setPosition3d(uc1->toCartesian(Vector3(0.0, 0.6947, 0.6947)));
  mol1.addAtom(8).setPosition3d(uc1->toCartesian(Vector3(0.5, 0.1947, 0.8053)));
  mol1.addAtom(8).setPosition3d(uc1->toCartesian(Vector3(0.5, 0.8053, 0.1947)));
  mol1.addAtom(22).setPosition3d(uc1->toCartesian(Vector3(0.0, 0.0, 0.0)));
  mol1.addAtom(22).setPosition3d(uc1->toCartesian(Vector3(0.5, 0.5, 0.5)));

  // This is space group international number 136 - the space group of rutile
  unsigned short hallNumber1 = 419;

  SpaceGroups::reduceToAsymmetricUnit(mol1, hallNumber1, cartTol);

  // There should now only be two atoms and two types: O and Ti
  ASSERT_EQ(mol1.atomCount(), 2);
  ASSERT_EQ(mol1.atomicNumbers().size(), 2);

  // Reducing a cell to its asymmetric unit is essentially the reverse of
  // filling a unit cell. So let's fill a unit cell, reduce it to its
  // asymmetric unit, and then check to see if it is back to its original state

  // CaMg(CO3)2 - dolomite. Space group: hexagonal R -3. It is a brittle
  // mineral found in limestones and other common places.
  // http://crystallography.net/cod/1517795.html
  Molecule mol2;
  Matrix3 mat2;

  mat2.col(0) = Vector3(4.808, 0.00000, 0.000);  // A
  mat2.col(1) = Vector3(-2.404, 4.16385, 0.000); // B
  mat2.col(2) = Vector3(0.000, 0.00000, 16.022); // C

  UnitCell* uc2 = new UnitCell(mat2);
  mol2.setUnitCell(uc2);

  mol2.addAtom(20).setPosition3d(
    uc2->toCartesian(Vector3(0.0000, 0.0000, 0.0000)));
  mol2.addAtom(12).setPosition3d(
    uc2->toCartesian(Vector3(0.0000, 0.0000, 0.5000)));
  mol2.addAtom(6).setPosition3d(
    uc2->toCartesian(Vector3(0.0000, 0.0000, 0.24287)));
  mol2.addAtom(8).setPosition3d(
    uc2->toCartesian(Vector3(0.24796, 0.9653, 0.24402)));

  // Now, let's perform a fillUnitCell. hallNumber 436 is hexagonal R -3
  // International: 148
  SpaceGroups::fillUnitCell(mol2, 436, cartTol);

  // It should now have a hall number of 436
  unsigned short hallNumber2 = AvoSpglib::getHallNumber(mol2, cartTol);
  ASSERT_EQ(hallNumber2, 436);

  // It should now have 30 atoms
  ASSERT_EQ(mol2.atomCount(), 30);

  // Now let's revert it back to its original state
  SpaceGroups::reduceToAsymmetricUnit(mol2, 436, cartTol);

  // It should have 4 atoms again and 4 atom types
  ASSERT_EQ(mol2.atomCount(), 4);
  ASSERT_EQ(mol2.atomicNumbers().size(), 4);
}

namespace {

// Write a symbol the way Open Babel and many CIFs do: screw axes without the
// underscore ("P 6_3/m m c" -> "P 63/m m c").
std::string withoutUnderscores(std::string symbol)
{
  std::string result;
  for (char c : symbol) {
    if (c != '_')
      result.push_back(c);
  }
  return result;
}

// The parts of the "international" column: "P 2_1/c = P 1 2_1/c 1"
std::vector<std::string> aliasesOf(unsigned short hall)
{
  std::vector<std::string> aliases;
  const std::string international = SpaceGroups::international(hall);
  const std::string separator = " = ";
  std::string::size_type start = 0;
  while (true) {
    std::string::size_type pos = international.find(separator, start);
    aliases.push_back(international.substr(
      start, pos == std::string::npos ? std::string::npos : pos - start));
    if (pos == std::string::npos)
      break;
    start = pos + separator.size();
  }
  return aliases;
}

bool isOriginOrAxisSetting(const std::string& setting)
{
  return !setting.empty() && (setting[0] == '1' || setting[0] == '2' ||
                              setting == "H" || setting == "R");
}

} // namespace

TEST(SpaceGroupTest, tableEntriesMapToThemselves)
{
  // Every Hall symbol finds an entry with that Hall symbol. They are unique
  // but for three pairs (322/324, 326/328, 330/332: the same operations in
  // two descriptions of the same setting), where the first one is found.
  for (unsigned short i = 1; i <= 530; ++i) {
    unsigned short hall = SpaceGroups::hallNumber(SpaceGroups::hallSymbol(i));
    EXPECT_LE(hall, i) << "hall symbol of " << i;
    EXPECT_STREQ(SpaceGroups::hallSymbol(hall), SpaceGroups::hallSymbol(i))
      << "hall symbol of " << i;
    if (i != 324 && i != 328 && i != 332)
      EXPECT_EQ(hall, i) << "hall symbol of " << i;
  }

  // The other strings in the table: an exact match was and is the first
  // entry of the table with that string, which has the right number.
  for (unsigned short i = 1; i <= 530; ++i) {
    for (const std::string& symbol :
         { std::string(SpaceGroups::international(i)),
           std::string(SpaceGroups::internationalFull(i)),
           std::string(SpaceGroups::internationalShort(i)) }) {
      unsigned short hall = SpaceGroups::hallNumber(symbol);
      ASSERT_NE(hall, 0) << symbol << " (" << i << ")";
      EXPECT_LE(hall, i) << symbol;
      EXPECT_EQ(SpaceGroups::internationalNumber(hall),
                SpaceGroups::internationalNumber(i))
        << symbol;
    }
  }
}

TEST(SpaceGroupTest, openBabelStyleSymbols)
{
  // How many entries share each full symbol (origin choices and axis
  // permutations of the same group do).
  std::map<std::string, int> fullCount;
  for (unsigned short i = 1; i <= 530; ++i)
    ++fullCount[SpaceGroups::internationalFull(i)];

  for (unsigned short i = 1; i <= 530; ++i) {
    const std::string full = SpaceGroups::internationalFull(i);
    const std::string setting = SpaceGroups::setting(i);
    std::string spelled = withoutUnderscores(full);
    // the setting is only needed when the symbol does not tell
    if (fullCount[full] > 1)
      spelled += " :" + setting;
    EXPECT_EQ(SpaceGroups::hallNumber(spelled), i) << spelled;

    // and without the space, as found in some files
    if (fullCount[full] > 1) {
      std::string glued = withoutUnderscores(full) + ":" + setting;
      EXPECT_EQ(SpaceGroups::hallNumber(glued), i) << glued;
    }

    // Open Babel appends ":1", ":2", ":H" and ":R" to the short symbols
    // (the "international" column)
    for (const std::string& alias : aliasesOf(i)) {
      std::string spelled2 = withoutUnderscores(alias);
      unsigned short hall = SpaceGroups::hallNumber(spelled2);
      // whatever it resolves to, it must be the same group
      if (hall != 0) {
        EXPECT_EQ(SpaceGroups::internationalNumber(hall),
                  SpaceGroups::internationalNumber(i))
          << spelled2;
      }
      EXPECT_EQ(SpaceGroups::internationalNumberFromString(spelled2),
                SpaceGroups::internationalNumber(i))
        << spelled2;

      if (isOriginOrAxisSetting(setting)) {
        // a hall number is only found for the exact origin / axes
        std::string withSetting = spelled2 + " :" + setting;
        EXPECT_EQ(SpaceGroups::hallNumber(withSetting), i) << withSetting;
      }
    }
  }
}

TEST(SpaceGroupTest, screwAxesAndSettingsFromFiles)
{
  // P 2_1/c with its three cell choices
  EXPECT_EQ(SpaceGroups::hallNumber("P 1 21/c 1"), 81);
  EXPECT_EQ(SpaceGroups::hallNumber("P 1 21/n 1"), 82);
  EXPECT_EQ(SpaceGroups::hallNumber("P 1 21/a 1"), 83);
  EXPECT_EQ(SpaceGroups::hallNumber("P 1 21 1"), 6);
  EXPECT_EQ(SpaceGroups::hallNumber("P 21/c"), 81);

  // hexagonal, trigonal and tetragonal screw axes
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 63/m m c")),
    194);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 63 m c")), 186);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 63 c m")), 185);
  EXPECT_EQ(SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 63")),
            173);
  EXPECT_EQ(SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 63/m")),
            176);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 62 2 2")), 180);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 31 2 1")), 152);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 32 1 2")), 153);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 32 2 1")), 154);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 41 2 2")), 91);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 4 21 2")), 90);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 41 21 2")), 92);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 42/m n m")),
    136);
  // P 4_2/n m c has two origin choices, which the symbol does not tell
  EXPECT_EQ(SpaceGroups::hallNumber("P 42/n m c"), 0);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("P 42/n m c"), 137);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 42/n m c :2")),
    137);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("C 2 2 21")), 20);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P m n 21")), 31);
  EXPECT_EQ(SpaceGroups::internationalNumber(SpaceGroups::hallNumber("P 21 3")),
            198);
  EXPECT_EQ(SpaceGroups::internationalNumber(SpaceGroups::hallNumber("I 21 3")),
            199);

  // settings: origin choices and hexagonal / rhombohedral axes
  EXPECT_EQ(SpaceGroups::hallNumber("I 41/a m d :1"), 426);
  EXPECT_EQ(SpaceGroups::hallNumber("I 41/a m d :2"), 427);
  EXPECT_EQ(SpaceGroups::hallNumber("I 41/a m d:2"), 427);
  EXPECT_EQ(SpaceGroups::hallNumber("F d -3 m :1"), 525);
  EXPECT_EQ(SpaceGroups::hallNumber("F d -3 m :2"), 526);
  EXPECT_EQ(SpaceGroups::hallNumber("R -3 m :H"), 458);
  EXPECT_EQ(SpaceGroups::hallNumber("R -3 m :R"), 459);
  EXPECT_EQ(SpaceGroups::hallNumber("R -3 :H"), 436);
  EXPECT_EQ(SpaceGroups::hallNumber("R -3 :R"), 437);
  EXPECT_EQ(SpaceGroups::hallNumber("R 3 :R"), 434);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("R -3 c :H")),
    167);
  EXPECT_EQ(
    SpaceGroups::internationalNumber(SpaceGroups::hallNumber("R 3 m :H")), 160);

  // a setting that the group does not have
  EXPECT_EQ(SpaceGroups::hallNumber("P n m a :1"), 0);
  EXPECT_EQ(SpaceGroups::hallNumber("R -3 m :X"), 0);

  // Several origin choices and no setting: the new lookup does not guess.
  EXPECT_EQ(SpaceGroups::hallNumber("I 41/a m d"), 0);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("I 41/a m d"), 141);
  // (A string that matches the table exactly keeps its old result, the first
  // entry of the table, which is origin choice 1.)
  EXPECT_EQ(SpaceGroups::hallNumber("I 4_1/a m d"), 426);
}

TEST(SpaceGroupTest, oldCubicNotation)
{
  // Pre-1983 symbols and this table write "3" for the centrosymmetric
  // cubic groups that IT writes with -3
  EXPECT_EQ(SpaceGroups::hallNumber("I m 3 m"), 529);
  EXPECT_EQ(SpaceGroups::hallNumber("I m -3 m"), 529);
  EXPECT_EQ(SpaceGroups::hallNumber("P m 3 m"), 517);
  EXPECT_EQ(SpaceGroups::hallNumber("F m 3 m"), 523);
  EXPECT_EQ(SpaceGroups::hallNumber("I m -3"), 500);
  EXPECT_EQ(SpaceGroups::hallNumber("I a -3"), 502);
  EXPECT_EQ(SpaceGroups::hallNumber("P a -3"), 501);
  EXPECT_EQ(SpaceGroups::hallNumber("P n 3 m :1"), 521);
  EXPECT_EQ(SpaceGroups::hallNumber("P n -3 m :2"), 522);
  EXPECT_EQ(SpaceGroups::hallNumber("P n -3 :1"), 495);
  EXPECT_EQ(SpaceGroups::hallNumber("F d -3 :2"), 499);
  // origin choice needed
  EXPECT_EQ(SpaceGroups::hallNumber("P n 3 m"), 0);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("P n 3 m"), 224);

  // the non-centrosymmetric cubic groups must keep their plain 3
  EXPECT_EQ(SpaceGroups::hallNumber("P 2 3"), 489);
  EXPECT_EQ(SpaceGroups::hallNumber("P 4 3 2"), 503);
  EXPECT_EQ(SpaceGroups::hallNumber("P -4 3 m"), 511);
  EXPECT_EQ(SpaceGroups::hallNumber("F -4 3 m"), 512);
  EXPECT_EQ(SpaceGroups::hallNumber("I -4 3 d"), 516);
}

TEST(SpaceGroupTest, internationalNumbers)
{
  std::map<unsigned short, std::vector<unsigned short>> halls;
  for (unsigned short i = 1; i <= 530; ++i)
    halls[SpaceGroups::internationalNumber(i)].push_back(i);
  ASSERT_EQ(halls.size(), 230u);

  for (const auto& entry : halls) {
    std::string number = std::to_string(entry.first);
    EXPECT_EQ(SpaceGroups::internationalNumberFromString(number), entry.first);
    if (entry.second.size() == 1) {
      // a single setting: nothing to guess
      EXPECT_EQ(SpaceGroups::hallNumber(number), entry.second.front())
        << number;
    } else {
      // axes, cell or origin choice: the number does not tell
      EXPECT_EQ(SpaceGroups::hallNumber(number), 0) << number;
    }
  }

  EXPECT_EQ(SpaceGroups::hallNumber("1"), 1);
  EXPECT_EQ(SpaceGroups::hallNumber(" 2 "), 2);
  EXPECT_EQ(SpaceGroups::hallNumber("229"), 529);
  EXPECT_EQ(SpaceGroups::hallNumber("74"), 0);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("74"), 74);
  EXPECT_EQ(SpaceGroups::hallNumber("227"), 0);
}

TEST(SpaceGroupTest, garbageSymbols)
{
  for (const char* garbage : { "",        " ",
                               ":",       "::",
                               "abc",     "0",
                               "231",     "1000",
                               "-1",      "74a",
                               "7 4",     "P",
                               "P 99 99", "P 1 21/c 1 :zz",
                               "C 1",     "P 6_3 m c :H",
                               ":H",      "P 22 2",
                               "P 2_3 2", "R 3 m 3",
                               "Q 1 2 3" }) {
    EXPECT_EQ(SpaceGroups::hallNumber(garbage), 0) << "'" << garbage << "'";
  }
  EXPECT_EQ(SpaceGroups::internationalNumberFromString(""), 0);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("abc"), 0);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("231"), 0);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("0"), 0);
}
