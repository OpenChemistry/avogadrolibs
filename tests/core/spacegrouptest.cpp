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
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <map>
#include <random>
#include <string>
#include <vector>

// The table of operations is private to the library. Include its data in a
// namespace of its own so that these arrays are not the library's symbols.
namespace SpaceGroupTable {
#include <avogadro/core/spacegroupdata.h>
}

using Avogadro::Matrix3;
using Avogadro::Vector3;
using Avogadro::Core::AvoSpglib;
using Avogadro::Core::Molecule;
using Avogadro::Core::SpaceGroups;
using Avogadro::Core::split;
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

// The hall number a table entry is expected to resolve to. Three pairs of
// entries (group 68) have identical operations and Hall symbols; the lower of
// each pair is returned. Every other entry has a unique set of operations.
unsigned short expectedHall(unsigned short hall)
{
  switch (hall) {
    case 324:
      return 322;
    case 328:
      return 326;
    case 332:
      return 330;
    default:
      return hall;
  }
}

// A symbol and what it is expected to resolve to (see the checks below).
struct SymbolCase
{
  const char* symbol;
  unsigned short expected;
};

// hallNumber() of each symbol is the expected Hall number (0 if the symbol
// does not name one setting).
void expectHallNumbers(std::initializer_list<SymbolCase> cases)
{
  for (const auto& test : cases)
    EXPECT_EQ(SpaceGroups::hallNumber(test.symbol), test.expected)
      << "'" << test.symbol << "'";
}

// The international table number of the hallNumber() of each symbol is the
// expected one.
void expectGroupNumbers(std::initializer_list<SymbolCase> cases)
{
  for (const auto& test : cases)
    EXPECT_EQ(
      SpaceGroups::internationalNumber(SpaceGroups::hallNumber(test.symbol)),
      test.expected)
      << "'" << test.symbol << "'";
}

// internationalNumberFromString() of each symbol is the expected number.
void expectNumbersFromStrings(std::initializer_list<SymbolCase> cases)
{
  for (const auto& test : cases)
    EXPECT_EQ(SpaceGroups::internationalNumberFromString(test.symbol),
              test.expected)
      << "'" << test.symbol << "'";
}

} // namespace

TEST(SpaceGroupTest, tableEntriesMapToThemselves)
{
  // Every Hall symbol finds an entry with that Hall symbol. They are unique
  // but for three pairs (322/324, 326/328, 330/332: the same operations in
  // two descriptions of the same setting), where the first one is found.
  for (unsigned short i = 1; i <= SpaceGroups::lastHallNumber; ++i) {
    unsigned short hall = SpaceGroups::hallNumber(SpaceGroups::hallSymbol(i));
    EXPECT_EQ(hall, expectedHall(i)) << "hall symbol of " << i;
    EXPECT_STREQ(SpaceGroups::hallSymbol(hall), SpaceGroups::hallSymbol(i))
      << "hall symbol of " << i;
  }

  // The other strings in the table: an exact match was and is the first
  // entry of the table with that string, which has the right number.
  for (unsigned short i = 1; i <= SpaceGroups::lastHallNumber; ++i) {
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
  for (unsigned short i = 1; i <= SpaceGroups::lastHallNumber; ++i)
    ++fullCount[SpaceGroups::internationalFull(i)];

  for (unsigned short i = 1; i <= SpaceGroups::lastHallNumber; ++i) {
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
  expectHallNumbers({ { "P 1 21/c 1", 81 },
                      { "P 1 21/n 1", 82 },
                      { "P 1 21/a 1", 83 },
                      { "P 1 21 1", 6 },
                      { "P 21/c", 81 } });

  // hexagonal, trigonal and tetragonal screw axes
  expectGroupNumbers({ { "P 63/m m c", 194 },
                       { "P 63 m c", 186 },
                       { "P 63 c m", 185 },
                       { "P 63", 173 },
                       { "P 63/m", 176 },
                       { "P 62 2 2", 180 },
                       { "P 31 2 1", 152 },
                       { "P 32 1 2", 153 },
                       { "P 32 2 1", 154 },
                       { "P 41 2 2", 91 },
                       { "P 4 21 2", 90 },
                       { "P 41 21 2", 92 },
                       { "P 42/m n m", 136 } });
  // P 4_2/n m c has two origin choices, which the symbol does not tell
  expectHallNumbers({ { "P 42/n m c", 0 } });
  expectNumbersFromStrings({ { "P 42/n m c", 137 } });
  expectGroupNumbers({ { "P 42/n m c :2", 137 },
                       { "C 2 2 21", 20 },
                       { "P m n 21", 31 },
                       { "P 21 3", 198 },
                       { "I 21 3", 199 } });

  // settings: origin choices and hexagonal / rhombohedral axes
  expectHallNumbers({ { "I 41/a m d :1", 426 },
                      { "I 41/a m d :2", 427 },
                      { "I 41/a m d:2", 427 },
                      { "F d -3 m :1", 525 },
                      { "F d -3 m :2", 526 },
                      { "R -3 m :H", 458 },
                      { "R -3 m :R", 459 },
                      { "R -3 :H", 436 },
                      { "R -3 :R", 437 },
                      { "R 3 :R", 434 } });
  expectGroupNumbers({ { "R -3 c :H", 167 }, { "R 3 m :H", 160 } });

  // a setting that the group does not have
  expectHallNumbers({ { "P n m a :1", 0 }, { "R -3 m :X", 0 } });

  // Several origin choices and no setting: the new lookup does not guess.
  expectHallNumbers({ { "I 41/a m d", 0 } });
  expectNumbersFromStrings({ { "I 41/a m d", 141 } });
  // (A string that matches the table exactly keeps its old result, the first
  // entry of the table, which is origin choice 1.)
  expectHallNumbers({ { "I 4_1/a m d", 426 } });
}

TEST(SpaceGroupTest, oldCubicNotation)
{
  // Pre-1983 symbols and this table write "3" for the centrosymmetric
  // cubic groups that IT writes with -3
  expectHallNumbers({ { "I m 3 m", 529 },
                      { "I m -3 m", 529 },
                      { "P m 3 m", 517 },
                      { "F m 3 m", 523 },
                      { "I m -3", 500 },
                      { "I a -3", 502 },
                      { "P a -3", 501 },
                      { "P n 3 m :1", 521 },
                      { "P n -3 m :2", 522 },
                      { "P n -3 :1", 495 },
                      { "F d -3 :2", 499 } });
  // origin choice needed
  expectHallNumbers({ { "P n 3 m", 0 } });
  expectNumbersFromStrings({ { "P n 3 m", 224 } });

  // the non-centrosymmetric cubic groups must keep their plain 3
  expectHallNumbers({ { "P 2 3", 489 },
                      { "P 4 3 2", 503 },
                      { "P -4 3 m", 511 },
                      { "F -4 3 m", 512 },
                      { "I -4 3 d", 516 } });
}

TEST(SpaceGroupTest, internationalNumbers)
{
  std::map<unsigned short, std::vector<unsigned short>> halls;
  for (unsigned short i = 1; i <= SpaceGroups::lastHallNumber; ++i)
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

namespace {

std::vector<std::string> tableOperationStrings(unsigned short hall)
{
  return split(SpaceGroupTable::Avogadro::Core::space_group_transforms[hall],
               ' ');
}

// Respell "-x+1/2,y,1/2-z" with the terms of every coordinate reversed, and
// optionally with decimals, upper case, spaces and quotes.
std::string respell(const std::string& op, bool decimals, bool upper,
                    bool spaced, bool quoted, bool shiftByOne)
{
  const std::vector<std::string> coordinates = split(op, ',', false);

  std::string result;
  for (std::string coordinate : coordinates) {
    // split into signed terms
    std::vector<std::string> terms;
    std::string term;
    for (char c : coordinate) {
      if ((c == '+' || c == '-') && !term.empty()) {
        terms.push_back(term);
        term.clear();
      }
      term.push_back(c);
    }
    terms.push_back(term);
    std::reverse(terms.begin(), terms.end());

    std::string text;
    bool hasConstant = false;
    for (std::string t : terms) {
      std::string sign = "+";
      if (t[0] == '-' || t[0] == '+') {
        sign = std::string(1, t[0]);
        t = t.substr(1);
      }
      if (std::isdigit(static_cast<unsigned char>(t[0]))) {
        hasConstant = true;
        if (decimals) {
          static const std::map<std::string, std::string> values = {
            { "1/2", "0.5" },    { "1/4", "0.25" },   { "3/4", "0.75" },
            { "1/3", "0.3333" }, { "2/3", "0.6667" }, { "1/6", "0.1667" },
            { "5/6", "0.8333" }
          };
          t = values.at(t);
        }
      }
      text += sign + t;
    }
    if (shiftByOne && !hasConstant)
      text += "+1";
    if (text[0] == '+')
      text = text.substr(1);
    if (!result.empty())
      result += spaced ? " , " : ",";
    result += text;
  }
  if (upper)
    std::transform(result.begin(), result.end(), result.begin(), [](char c) {
      return static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    });
  if (spaced)
    result = "  " + result + " ";
  if (quoted)
    result = "'" + result + "'";
  return result;
}

} // namespace

TEST(SpaceGroupTest, hallSymbolLookup)
{
  // every Hall symbol of the table finds an entry with that symbol
  for (unsigned short hall = 1; hall <= SpaceGroups::lastHallNumber; ++hall) {
    unsigned short found =
      SpaceGroups::hallNumberFromHallSymbol(SpaceGroups::hallSymbol(hall));
    EXPECT_STREQ(SpaceGroups::hallSymbol(found), SpaceGroups::hallSymbol(hall))
      << hall;
  }

  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("-P 2yn"),
            SpaceGroups::hallNumber("-P 2yn"));
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("P 1"), 1);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("-P 1"), 2);

  // spacing is not significant
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("  -P   2yn \n"),
            SpaceGroups::hallNumberFromHallSymbol("-P 2yn"));
  EXPECT_NE(SpaceGroups::hallNumberFromHallSymbol("-P 2yn"), 0);

  // a double quote is how files write the table's '='
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("P 3 2\""),
            SpaceGroups::hallNumberFromHallSymbol("P 3 2="));
  EXPECT_NE(SpaceGroups::hallNumberFromHallSymbol("P 3 2\""), 0);

  // international symbols and numbers are not Hall symbols
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("P 21/c"), 0);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("P 1 21/c 1"), 0);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("14"), 0);

  // anything else
  for (const char* garbage :
       { "", "   ", "garbage", "?", "P 2yb x", "-P 4c 2 (x,y+1/2,z)" }) {
    EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol(garbage), 0)
      << "'" << garbage << "'";
  }
}

TEST(SpaceGroupTest, originChoiceWithPermutedAxes)
{
  // The table's setting is "1cab", "2cab", ... where the symbol has permuted
  // axes; a file only gives the origin choice
  expectHallNumbers({ { "P n c b:1", 235 },
                      { "P n c b:2", 236 },
                      { "P n c b :2", 236 },
                      { "P c n a:1", 237 },
                      { "P c n a:2", 238 },
                      { "P n m m:1", 280 },
                      { "P n m m:2", 281 },
                      { "P m n m:1", 282 },
                      { "P m n m:2", 283 } });
  expectNumbersFromStrings({ { "P m n m:2", 59 } });

  // a digit that matches no setting, or no digit at all
  expectHallNumbers({ { "P n c b:3", 0 },
                      { "P n c b:0", 0 },
                      { "P n c b:12", 0 },
                      { "P n c b:cab", 0 } });
  expectNumbersFromStrings({ { "P n c b:3", 50 } });

  // an exact setting still wins over the first-digit rule
  expectHallNumbers({ { "P b a n:1", 233 },
                      { "P b a n:2", 234 },
                      { "P n c b:1cab", 235 },
                      { "P n c b:2cab", 236 } });

  // other symbols and settings are not affected
  expectHallNumbers({ { "P n m a:1", 0 }, { "C 2/c:1", 0 } });
}

namespace {

// The pre-2002 names of the groups with an "e" glide, as gemmi writes its
// extended H-M names (the origin choice is the part after the colon).
struct OldNameCase
{
  unsigned short hall;
  const char* name;
  const char* origin;
};

// clang-format off
const OldNameCase oldNameCases[] = {
  {191, "A b m 2", ""},
  {192, "B m a 2", ""},
  {193, "B 2 c m", ""},
  {194, "C 2 m b", ""},
  {195, "C m 2 a", ""},
  {196, "A c 2 m", ""},
  {203, "A b a 2", ""},
  {204, "B b a 2", ""},
  {205, "B 2 c b", ""},
  {206, "C 2 c b", ""},
  {207, "C c 2 a", ""},
  {208, "A c 2 a", ""},
  {304, "C m c a", ""},
  {305, "C c m b", ""},
  {306, "A b m a", ""},
  {307, "A c a m", ""},
  {308, "B b c m", ""},
  {309, "B m a b", ""},
  {316, "C m m a", ""},
  {317, "C m m b", ""},
  {318, "A b m m", ""},
  {319, "A c m m", ""},
  {320, "B m c m", ""},
  {321, "B m a m", ""},
  {322, "C c c a", "1"},
  {323, "C c c a", "2"},
  {324, "C c c a", "1"},
  {325, "C c c b", "2"},
  {326, "A b a a", "1"},
  {327, "A b a a", "2"},
  {328, "A b a a", "1"},
  {329, "A c a a", "2"},
  {330, "B b c b", "1"},
  {331, "B b c b", "2"},
  {332, "B b c b", "1"},
  {333, "B b a b", "2"},
};
// clang-format on

} // namespace

TEST(SpaceGroupTest, preTwoThousandTwoGlideNames)
{
  for (const auto& test : oldNameCases) {
    const unsigned short hall = test.hall;
    const std::string origin = test.origin;
    const std::string symbol =
      origin.empty() ? test.name : std::string(test.name) + ":" + origin;
    const std::string ops =
      SpaceGroupTable::Avogadro::Core::space_group_transforms[hall];

    const unsigned short found = SpaceGroups::hallNumber(symbol);
    ASSERT_NE(found, 0) << symbol;
    EXPECT_EQ(found, expectedHall(hall)) << symbol;
    // the lower number of 322/324-style pairs has the same operations
    if (found != hall)
      EXPECT_EQ(SpaceGroupTable::Avogadro::Core::space_group_transforms[found],
                ops)
        << symbol;
    EXPECT_EQ(SpaceGroups::internationalNumber(found),
              SpaceGroups::internationalNumber(hall))
      << symbol;
    EXPECT_EQ(SpaceGroups::internationalNumberFromString(symbol),
              SpaceGroups::internationalNumber(hall))
      << symbol;

    // the setting may have spaces around it
    if (!origin.empty()) {
      EXPECT_EQ(
        SpaceGroups::hallNumber(std::string(test.name) + " : " + origin),
        expectedHall(hall))
        << symbol;
    }
    // the name alone, when no origin choice is given
    EXPECT_EQ(SpaceGroups::internationalNumberFromString(test.name),
              SpaceGroups::internationalNumber(hall))
      << symbol;
    int sharing = 0;
    for (const auto& other : oldNameCases) {
      if (std::string(other.name) == test.name)
        ++sharing;
    }
    if (sharing == 1) {
      EXPECT_EQ(SpaceGroups::hallNumber(test.name), hall) << symbol;
    } else if (std::string(test.name) != "B b c b") {
      // shared by several origin choices: do not guess
      EXPECT_EQ(SpaceGroups::hallNumber(test.name), 0) << symbol;
    }
  }

  // 'e' is not a wildcard: these two settings share "C m m e" in the table
  EXPECT_EQ(SpaceGroups::hallNumber("C m m a"), 316);
  EXPECT_EQ(SpaceGroups::hallNumber("C m m b"), 317);
  EXPECT_EQ(SpaceGroups::hallNumber("C m m e"), 316);
  EXPECT_EQ(SpaceGroups::hallNumber("C m m c"), 0);
  EXPECT_EQ(SpaceGroups::hallNumber("C m c c"), 0);

  EXPECT_EQ(SpaceGroups::internationalNumberFromString("C m c a"), 64);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("C m c e"), 64);
  EXPECT_EQ(SpaceGroups::internationalNumberFromString("C c c a"), 68);
  EXPECT_EQ(SpaceGroups::hallNumber("C c c a:1"), 322);
  EXPECT_EQ(SpaceGroups::hallNumber("C c c a:2"), 323);
  EXPECT_EQ(SpaceGroups::hallNumber("C c c b:2"), 325);
  EXPECT_EQ(SpaceGroups::hallNumber("A b a a:1"), 326);
  EXPECT_EQ(SpaceGroups::hallNumber("B b c b:1"), 330);
  EXPECT_EQ(SpaceGroups::hallNumber("B b c b:2"), 331);
  // (the table spells 331 "B b c b" and keeps finding it for the bare name)
  EXPECT_EQ(SpaceGroups::hallNumber("B b c b"), 331);

  // the 2002 spelling works with the same settings
  EXPECT_EQ(SpaceGroups::hallNumber("C c c e:1"), 322);
  EXPECT_EQ(SpaceGroups::hallNumber("C c c e:2"), 323);

  // symbols that are not old names of these groups
  EXPECT_EQ(SpaceGroups::hallNumber("C m m c"), 0);
  EXPECT_EQ(SpaceGroups::hallNumber("A b m e"), 0);
  EXPECT_EQ(SpaceGroups::hallNumber("C c c a:3"), 0);
  EXPECT_EQ(SpaceGroups::hallNumber("C m c a:1"), 0);
}

namespace {

// spglib's spellings of Hall symbols that differ from the table's, each with
// the Hall number it stands for.
struct HallAliasCase
{
  unsigned short hall;
  const char* symbol;
};

// clang-format off
const HallAliasCase hallAliasCases[] = {
  {40, "A -2yab"},
  {43, "C -2yac"},
  {46, "B -2ab"},
  {49, "A -2ab"},
  {52, "C -2xac"},
  {55, "B -2xab"},
  {91, "-A 2yab"},
  {94, "-C 2yac"},
  {97, "-B 2ab"},
  {100, "-A 2ab"},
  {103, "-C 2xac"},
  {106, "-B 2xab"},
  {191, "A 2 -2b"},
  {192, "B 2 -2a"},
  {193, "B -2a 2"},
  {194, "C -2a 2"},
  {195, "C -2a -2a"},
  {196, "A -2b -2b"},
  {203, "A 2 -2ab"},
  {204, "B 2 -2ab"},
  {205, "B -2ab 2"},
  {206, "C -2ac 2"},
  {207, "C -2ac -2ac"},
  {208, "A -2ab -2ab"},
  {304, "-C 2ac 2"},
  {305, "-C 2ac 2ac"},
  {306, "-A 2ab 2ab"},
  {307, "-A 2 2ab"},
  {308, "-B 2 2ab"},
  {309, "-B 2ab 2"},
  {316, "-C 2a 2"},
  {317, "-C 2a 2a"},
  {318, "-A 2b 2b"},
  {319, "-A 2 2b"},
  {320, "-B 2 2a"},
  {321, "-B 2a 2"},
  {322, "C 2 2 -1ac"},
  {323, "-C 2a 2ac"},
  {325, "-C 2a 2c"},
  {326, "A 2 2 -1ab"},
  {327, "-A 2a 2b"},
  {329, "-A 2ab 2b"},
  {330, "B 2 2 -1ab"},
  {331, "-B 2ab 2b"},
  {333, "-B 2b 2ab"},
  {440, "P 31 2 (0 0 4)"},
  {442, "P 32 2 (0 0 2)"},
  {472, "P 61 2 (0 0 5)"},
  {474, "P 62 2 (0 0 4)"},
  {475, "P 64 2 (0 0 2)"},
  {515, "F -4a 2 3"},
  {524, "-F 4a 2 3"},
  {527, "F 4d 2 3 -1ad"},
  {528, "-F 4ud 2vw 3"},
};
// clang-format on

} // namespace

TEST(SpaceGroupTest, spglibHallSymbolSpellings)
{
  for (const auto& test : hallAliasCases) {
    EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol(test.symbol), test.hall)
      << test.symbol;
    // spacing is not significant
    EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol(
                "  " + std::string(test.symbol) + " \n"),
              test.hall)
      << test.symbol;
    // the general lookup takes them as well
    EXPECT_EQ(SpaceGroups::hallNumber(test.symbol), test.hall) << test.symbol;
  }

  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("A -2yab"), 40);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("A -2yac"), 40);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("P 31 2 (0 0 4)"), 440);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("P 31 2c (0 0 1)"), 440);

  // identical operations in the table: the lower number of each pair
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("C 2 2 -1ac"), 322);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("A 2 2 -1ab"), 326);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("B 2 2 -1ab"), 330);

  // not Hall symbols
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("A -2yaa"), 0);
  EXPECT_EQ(SpaceGroups::hallNumberFromHallSymbol("P 31 2 (0 0 3)"), 0);
}

TEST(SpaceGroupTest, transformsResolveToTheirOwnEntry)
{
  for (unsigned short hall = 1; hall <= SpaceGroups::lastHallNumber; ++hall) {
    std::vector<std::string> ops = tableOperationStrings(hall);
    ASSERT_FALSE(ops.empty()) << hall;
    EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(ops), expectedHall(hall))
      << hall << " " << SpaceGroups::hallSymbol(hall);
  }
}

TEST(SpaceGroupTest, transformsInAnyOrderAndSpelling)
{
  std::mt19937 rng(20261006);
  for (unsigned short hall = 1; hall <= SpaceGroups::lastHallNumber; ++hall) {
    std::vector<std::string> base = tableOperationStrings(hall);

    auto expectResolved = [&](const std::vector<std::string>& ops,
                              const std::string& what) {
      EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(ops), expectedHall(hall))
        << what << " " << hall;
    };

    // shuffled
    std::vector<std::string> ops = base;
    std::shuffle(ops.begin(), ops.end(), rng);
    expectResolved(ops, "shuffled");

    // repeated operations do not matter
    ops = base;
    ops.insert(ops.end(), base.begin(), base.end());
    std::shuffle(ops.begin(), ops.end(), rng);
    expectResolved(ops, "repeated");

    // terms reversed ("1/2+x" -> "x+1/2") is style 0; the others add
    // decimals, upper case, spaces and quotes in every combination
    for (int style = 0; style < 16; ++style) {
      ops.clear();
      for (const std::string& op : base)
        ops.push_back(
          respell(op, style & 1, style & 2, style & 4, style & 8, false));
      std::shuffle(ops.begin(), ops.end(), rng);
      expectResolved(ops, "style " + std::to_string(style));
    }

    // a full lattice translation added to some constants
    ops.clear();
    for (const std::string& op : base)
      ops.push_back(respell(op, true, true, true, true, true));
    expectResolved(ops, "shifted");
  }
}

TEST(SpaceGroupTest, transformsCifSpellings)
{
  // as written by CIF files: quoted, spaced, leading constants, decimals
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(
              { "'x, y, z'", "'-x, y+1/2, -z+1/2'", "'-x, -y, -z'",
                "'x, -y+1/2, z+1/2'" }),
            SpaceGroups::hallNumber("P 1 21/c 1"));
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(
              { "x,y,z", "-x,y+0.5,-z+0.5", "-x,-y,-z", "x,-y+0.5,z+0.5" }),
            SpaceGroups::hallNumber("P 1 21/c 1"));
  // hexagonal operations with a combination of axes
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(
              { "X,Y,Z", "-Y,X-Y,Z+1/3", "-X+Y,-X,Z+2/3" }),
            SpaceGroups::hallNumber("P 3_1"));
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(
              { "x,y,z", "-y,x-y,z+0.3333", "-x+y,-x,z+0.6667" }),
            SpaceGroups::hallNumber("P 3_1"));
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(
              { "x,y,z", "-y,x-y,z+2/3", "-x+y,-x,z+1/3" }),
            SpaceGroups::hallNumber("P 3_2"));
  // translations outside [0, 1) are reduced
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms({ "x,y,z", "-x,-y,-z" }), 2);
  EXPECT_EQ(
    SpaceGroups::hallNumberFromTransforms({ "x+1,y-1,z+2", "-x+1,-y,-z-3" }),
    2);
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms({ "x,y,z" }), 1);
}

TEST(SpaceGroupTest, transformsWrongSetsAreNotMatched)
{
  for (unsigned short hall = 2; hall <= SpaceGroups::lastHallNumber; ++hall) {
    std::vector<std::string> base = tableOperationStrings(hall);

    // one fewer operation: either not a space group or a different one
    for (std::size_t i = 0; i < base.size(); i += 1 + base.size() / 5) {
      std::vector<std::string> ops = base;
      ops.erase(ops.begin() + i);
      unsigned short found = SpaceGroups::hallNumberFromTransforms(ops);
      EXPECT_NE(found, expectedHall(hall)) << hall << " minus " << base[i];
    }

    // one operation too many (a twelfth step the table never contains)
    std::vector<std::string> ops = base;
    ops.emplace_back("x+1/12,y,z");
    EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(ops), 0) << hall;

    // one operation changed
    ops = base;
    ops.back() = "x,y,z+1/12";
    EXPECT_NE(SpaceGroups::hallNumberFromTransforms(ops), hall) << hall;
  }

  // a set that is not a group
  EXPECT_EQ(
    SpaceGroups::hallNumberFromTransforms({ "x,y,z", "-x,y,-z", "-x,-y,-z" }),
    0);
  // an inversion alone is not a space group in the table either
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms({ "-x,-y,-z" }), 0);
}

TEST(SpaceGroupTest, transformsGarbage)
{
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms({}), 0);
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms({ "" }), 0);
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms({ "x,y,z", "" }), 0);
  for (const char* garbage : { "garbage",
                               "x,y",
                               "x,y,z,x",
                               "x,,z",
                               ",,",
                               "x,y,",
                               "-",
                               "x,y,-",
                               "x,y,z+",
                               "x,y,2z",
                               "2x,y,z",
                               "x,y,w",
                               "x,y,1/0",
                               "x,y,z+1/",
                               "x,y,z+.",
                               "x,y,z+0.1",
                               "x,y,z+1/5",
                               "x,y,z+1e3",
                               "x*2,y,z",
                               "(x,y,z)",
                               "x;y;z",
                               "'",
                               "\"\"",
                               "x y z",
                               "x,y,z+99999999999999999999",
                               "x,y,xxxxxxx",
                               "x,y,0" }) {
    EXPECT_EQ(SpaceGroups::hallNumberFromTransforms({ "x,y,z", garbage }), 0)
      << "'" << garbage << "'";
    EXPECT_EQ(SpaceGroups::hallNumberFromTransforms({ garbage }), 0)
      << "'" << garbage << "'";
  }
  // very long input must not misbehave
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(
              { std::string(100000, 'x') + ",y,z" }),
            0);
  EXPECT_EQ(SpaceGroups::hallNumberFromTransforms(
              { std::string(100000, '1') + ",y,z" }),
            0);
}

TEST(SpaceGroupTest, setSpaceGroup)
{
  const char* key = SpaceGroups::internationalNumberKey();

  // one setting: the Hall number
  Molecule exact;
  EXPECT_TRUE(SpaceGroups::setSpaceGroup(exact, "P 63/m m c"));
  EXPECT_EQ(exact.hallNumber(), 488);
  EXPECT_FALSE(exact.hasData(key));

  // a spelling that resolves through the setting rules
  Molecule suffixed;
  EXPECT_TRUE(SpaceGroups::setSpaceGroup(suffixed, "F d -3 m :2"));
  EXPECT_EQ(suffixed.hallNumber(), 526);

  // several settings: only the international number is kept
  Molecule ambiguous;
  EXPECT_TRUE(SpaceGroups::setSpaceGroup(ambiguous, "74"));
  EXPECT_EQ(ambiguous.hallNumber(), 0);
  ASSERT_TRUE(ambiguous.hasData(key));
  EXPECT_EQ(ambiguous.data(key).toInt(), 74);

  // a Hall number found later replaces it
  EXPECT_TRUE(SpaceGroups::setSpaceGroup(ambiguous, "F d -3 m :2"));
  EXPECT_EQ(ambiguous.hallNumber(), 526);
  EXPECT_FALSE(ambiguous.hasData(key));

  // not a space group: nothing changes
  Molecule nonsense;
  EXPECT_FALSE(SpaceGroups::setSpaceGroup(nonsense, "C 1"));
  EXPECT_FALSE(SpaceGroups::setSpaceGroup(nonsense, ""));
  EXPECT_EQ(nonsense.hallNumber(), 0);
  EXPECT_FALSE(nonsense.hasData(key));

  Molecule known;
  known.setHallNumber(5);
  EXPECT_FALSE(SpaceGroups::setSpaceGroup(known, "C 1"));
  EXPECT_EQ(known.hallNumber(), 5);
}
