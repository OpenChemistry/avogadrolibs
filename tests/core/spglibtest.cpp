/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/avospglib.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

using Avogadro::Matrix3;
using Avogadro::Vector3;
using Avogadro::Core::AvoSpglib;
using Avogadro::Core::Molecule;
using Avogadro::Core::SpaceGroups;
using Avogadro::Core::UnitCell;

TEST(SpglibTest, getSpaceGroup)
{
  Molecule mol;

  // First, let's build rutile
  mol.setData("name", "TiO2 rutile");

  Matrix3 mat;
  mat.col(0) = Vector3(2.95812, 0.00000, 0.00000); // A
  mat.col(1) = Vector3(0.00000, 4.59373, 0.00000); // B
  mat.col(2) = Vector3(0.00000, 0.00000, 4.59373); // C

  UnitCell *uc = new UnitCell(mat);

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
  EXPECT_EQ(schoenflies, std::string("D4h^14"));
  EXPECT_EQ(hallSymbol, std::string("-P 4n 2n"));
  EXPECT_EQ(intSymbol, std::string("P 4_2/m 2_1/n 2/m"));
}

// We're going to take a conventional cell, reduce it to the primitive form,
// and check our results
TEST(SpglibTest, reduceToPrimitive)
{
  // Let's build a primitive cell of corundum!
  Molecule primMol;
  Matrix3 primMat;
  primMat.col(0) = Vector3(5.12980369, 0.00000000, 0.00000000); // A
  primMat.col(1) = Vector3(2.92081932, 4.21707249, 0.00000000); // B
  primMat.col(2) = Vector3(2.92081932, 1.52998182, 3.92973995); // C

  UnitCell *primUC = new UnitCell(primMat);
  primMol.setUnitCell(primUC);

  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.94365, 0.55635, 0.25)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.25000, 0.94365, 0.55635)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.55635, 0.25000, 0.94365)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.05635, 0.44365, 0.75000)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.75000, 0.05635, 0.44365)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.44365, 0.75000, 0.05635)));
  primMol.addAtom(13)
    .setPosition3d(primUC->toCartesian(Vector3(0.35217, 0.35217, 0.35217)));
  primMol.addAtom(13)
    .setPosition3d(primUC->toCartesian(Vector3(0.14783, 0.14783, 0.14783)));
  primMol.addAtom(13)
    .setPosition3d(primUC->toCartesian(Vector3(0.64783,0.64783,0.64783)));
  primMol.addAtom(13)
    .setPosition3d(primUC->toCartesian(Vector3(0.85217,0.85217,0.85217)));

  // Now, let's build a conventional cell of corundum
  Molecule convMol;
  Matrix3 convMat;
  convMat.col(0) = Vector3(4.76060000, 0.00000000, 0.00000000); // A
  convMat.col(1) = Vector3(-2.3803000, 4.12280054, 0.00000000); // B
  convMat.col(2) = Vector3(0.00000000, 0.00000000,12.99400000); // C

  UnitCell *convUC = new UnitCell(convMat);
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
TEST(SpglibTest, conventionalizeCell)
{
  // Let's build a primitive cell of corundum!
  Molecule primMol;
  Matrix3 primMat;
  primMat.col(0) = Vector3(5.12980369, 0.00000000, 0.00000000); // A
  primMat.col(1) = Vector3(2.92081932, 4.21707249, 0.00000000); // B
  primMat.col(2) = Vector3(2.92081932, 1.52998182, 3.92973995); // C

  UnitCell *primUC = new UnitCell(primMat);
  primMol.setUnitCell(primUC);

  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.94365, 0.55635, 0.25000)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.25000, 0.94365, 0.55635)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.55635, 0.25000, 0.94365)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.05635, 0.44365, 0.75000)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.75000, 0.05635, 0.44365)));
  primMol.addAtom(8)
    .setPosition3d(primUC->toCartesian(Vector3(0.44365, 0.75000, 0.05635)));
  primMol.addAtom(13)
    .setPosition3d(primUC->toCartesian(Vector3(0.35217, 0.35217, 0.35217)));
  primMol.addAtom(13)
    .setPosition3d(primUC->toCartesian(Vector3(0.14783, 0.14783, 0.14783)));
  primMol.addAtom(13)
    .setPosition3d(primUC->toCartesian(Vector3(0.64783, 0.64783, 0.64783)));
  primMol.addAtom(13)
    .setPosition3d(primUC->toCartesian(Vector3(0.85217, 0.85217, 0.85217)));

  // Now, let's build a conventional cell of corundum
  Molecule convMol;
  Matrix3 convMat;
  convMat.col(0) = Vector3(4.76060000, 0.00000000, 0.00000000); // A
  convMat.col(1) = Vector3(-2.3803000, 4.12280054, 0.00000000); // B
  convMat.col(2) = Vector3(0.00000000, 0.00000000,12.99400000); // C

  UnitCell *convUC = new UnitCell(convMat);
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
