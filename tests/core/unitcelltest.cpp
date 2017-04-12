/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

using namespace Avogadro;
using namespace Avogadro::Core;

namespace {
// use alpha, beta, gamma in degrees
Molecule createCrystal(Real a, Real b, Real c, Real alpha, Real beta,
                       Real gamma)
{
  Molecule mol;
  mol.setUnitCell(new UnitCell);
  mol.unitCell()->setCellParameters(a, b, c, alpha * DEG_TO_RAD,
                                    beta * DEG_TO_RAD, gamma * DEG_TO_RAD);
  return mol;
}

// use alpha, beta, gamma in degrees
bool checkParams(const UnitCell& cell, Real a, Real b, Real c, Real alpha,
                 Real beta, Real gamma)
{
  Real aRad = alpha * DEG_TO_RAD;
  Real bRad = beta * DEG_TO_RAD;
  Real gRad = gamma * DEG_TO_RAD;
  if (std::fabs(cell.a() - a) > 1e-3 || std::fabs(cell.b() - b) > 1e-3 ||
      std::fabs(cell.c() - c) > 1e-3 || std::fabs(cell.alpha() - aRad) > 1e-3 ||
      std::fabs(cell.beta() - bRad) > 1e-3 ||
      std::fabs(cell.gamma() - gRad) > 1e-3) {
    std::cerr << "Actual cell: "
              << "a=" << cell.a() << " "
              << "b=" << cell.b() << " "
              << "c=" << cell.c() << " "
              << "alpha=" << cell.alpha() * RAD_TO_DEG << " "
              << "beta=" << cell.beta() * RAD_TO_DEG << " "
              << "gamma=" << cell.gamma() * RAD_TO_DEG << std::endl;
    return false;
  }
  return true;
}
}

TEST(UnitCellTest, cellParameters)
{
  Real a = static_cast<Real>(2.0);
  Real b = static_cast<Real>(3.0);
  Real c = static_cast<Real>(4.0);
  Real alpha = static_cast<Real>(70 * DEG_TO_RAD);
  Real beta = static_cast<Real>(120 * DEG_TO_RAD);
  Real gamma = static_cast<Real>(85 * DEG_TO_RAD);

  UnitCell unitCell;
  unitCell.setCellParameters(a, b, c, alpha, beta, gamma);
  EXPECT_FLOAT_EQ(static_cast<float>(a), static_cast<float>(unitCell.a()));
  EXPECT_FLOAT_EQ(static_cast<float>(b), static_cast<float>(unitCell.b()));
  EXPECT_FLOAT_EQ(static_cast<float>(c), static_cast<float>(unitCell.c()));
  EXPECT_FLOAT_EQ(static_cast<float>(alpha),
                  static_cast<float>(unitCell.alpha()));
  EXPECT_FLOAT_EQ(static_cast<float>(beta),
                  static_cast<float>(unitCell.beta()));
  EXPECT_FLOAT_EQ(static_cast<float>(gamma),
                  static_cast<float>(unitCell.gamma()));
}

TEST(UnitCellTest, niggliReduce_G1973)
{
  // Test from Gruber 1973
  Molecule mol =
    createCrystal(static_cast<Real>(2.0), static_cast<Real>(11.661904),
                  static_cast<Real>(8.7177979), static_cast<Real>(139.66731),
                  static_cast<Real>(152.74610), static_cast<Real>(19.396626));
  EXPECT_FALSE(CrystalTools::isNiggliReduced(mol));
  EXPECT_TRUE(CrystalTools::niggliReduce(mol));
  EXPECT_TRUE(CrystalTools::isNiggliReduced(mol));
  EXPECT_TRUE(
    checkParams(*mol.unitCell(), static_cast<Real>(2.0), static_cast<Real>(4.0),
                static_cast<Real>(4.0), static_cast<Real>(60.0000),
                static_cast<Real>(79.1931), static_cast<Real>(75.5225)));
}

TEST(UnitCellTest, niggliReduce_GK1976)
{
  // Test from Gruber-Krivy 1976
  Molecule mol =
    createCrystal(static_cast<Real>(3.0), static_cast<Real>(5.1961524),
                  static_cast<Real>(2.0), static_cast<Real>(103.91975),
                  static_cast<Real>(109.47122), static_cast<Real>(134.88211));
  EXPECT_FALSE(CrystalTools::isNiggliReduced(mol));
  EXPECT_TRUE(CrystalTools::niggliReduce(mol));
  EXPECT_TRUE(CrystalTools::isNiggliReduced(mol));
  EXPECT_TRUE(
    checkParams(*mol.unitCell(), static_cast<Real>(2.0), static_cast<Real>(3.0),
                static_cast<Real>(3.0), static_cast<Real>(60.0000),
                static_cast<Real>(75.5225), static_cast<Real>(70.5288)));
}

// For the rotate test, just make sure that the cell parameters are the same
// before and after the rotation.
#define RTSO_INIT                                                              \
  Real a, b, c, alpha, beta, gamma;                                            \
  Matrix3 mat;                                                                 \
  Molecule mol
#define RTSO_DO_TEST                                                           \
  a = mol.unitCell()->a();                                                     \
  b = mol.unitCell()->b();                                                     \
  c = mol.unitCell()->c();                                                     \
  alpha = mol.unitCell()->alpha();                                             \
  beta = mol.unitCell()->beta();                                               \
  gamma = mol.unitCell()->gamma();                                             \
  EXPECT_TRUE(CrystalTools::rotateToStandardOrientation(mol));                 \
  EXPECT_FLOAT_EQ(static_cast<float>(a),                                       \
                  static_cast<float>(mol.unitCell()->a()));                    \
  EXPECT_FLOAT_EQ(static_cast<float>(b),                                       \
                  static_cast<float>(mol.unitCell()->b()));                    \
  EXPECT_FLOAT_EQ(static_cast<float>(c),                                       \
                  static_cast<float>(mol.unitCell()->c()));                    \
  EXPECT_FLOAT_EQ(static_cast<float>(alpha),                                   \
                  static_cast<float>(mol.unitCell()->alpha()));                \
  EXPECT_FLOAT_EQ(static_cast<float>(beta),                                    \
                  static_cast<float>(mol.unitCell()->beta()));                 \
  EXPECT_FLOAT_EQ(static_cast<float>(gamma),                                   \
                  static_cast<float>(mol.unitCell()->gamma()))
#define RTSO_TEST_PARAMS(a_, b_, c_, alpha_, beta_, gamma_)                    \
  mol = createCrystal(static_cast<Real>(a_), static_cast<Real>(b_),            \
                      static_cast<Real>(c_), static_cast<Real>(alpha_),        \
                      static_cast<Real>(beta_), static_cast<Real>(gamma_));    \
  RTSO_DO_TEST
#define RTSO_TEST_MATRIX(v1x, v1y, v1z, v2x, v2y, v2z, v3x, v3y, v3z)          \
  mat.col(0) = Vector3(static_cast<Real>(v1x), static_cast<Real>(v1y),         \
                       static_cast<Real>(v1z));                                \
  mat.col(1) = Vector3(static_cast<Real>(v2x), static_cast<Real>(v2y),         \
                       static_cast<Real>(v2z));                                \
  mat.col(2) = Vector3(static_cast<Real>(v3x), static_cast<Real>(v3y),         \
                       static_cast<Real>(v3z));                                \
  CrystalTools::setCellMatrix(mol, mat);                                       \
  RTSO_DO_TEST

TEST(UnitCellTest, rotateToStandardOrientation)
{
  RTSO_INIT;
  RTSO_TEST_PARAMS(3, 3, 3, 90, 90, 90);
  RTSO_TEST_PARAMS(3, 3, 3, 70, 90, 80);
  RTSO_TEST_PARAMS(3, 3, 3, 120, 123, 100);
  RTSO_TEST_PARAMS(4, 3, 1, 75.44444, 68.33333, 123.15682);
  RTSO_TEST_MATRIX(1, -4, 3, 0, 5, -8, 0, 0, -3);
  RTSO_TEST_MATRIX(1, 3, 6, -4, 5, -1, 3, -8, -3);
}

TEST(UnitCellTest, setVolume)
{
  Molecule mol = createCrystal(
    static_cast<Real>(3.0), static_cast<Real>(3.0), static_cast<Real>(3.0),
    static_cast<Real>(90.0), static_cast<Real>(120.0), static_cast<Real>(77.0));
  EXPECT_TRUE(CrystalTools::setVolume(mol, static_cast<Real>(1.0)));
  EXPECT_FLOAT_EQ(1.f, static_cast<float>(mol.unitCell()->volume()));
  EXPECT_FLOAT_EQ(90.f,
                  static_cast<float>(mol.unitCell()->alpha() * RAD_TO_DEG));
  EXPECT_FLOAT_EQ(120.f,
                  static_cast<float>(mol.unitCell()->beta() * RAD_TO_DEG));
  EXPECT_FLOAT_EQ(77.f,
                  static_cast<float>(mol.unitCell()->gamma() * RAD_TO_DEG));
}

TEST(UnitCellTest, fractionalCoordinates)
{
  Molecule mol = createCrystal(
    static_cast<Real>(3.0), static_cast<Real>(4.0), static_cast<Real>(5.0),
    static_cast<Real>(90.0), static_cast<Real>(120.0), static_cast<Real>(77.0));
  mol.addAtom(1).setPosition3d(
    Vector3(static_cast<Real>(0), static_cast<Real>(0), static_cast<Real>(0)));
  mol.addAtom(1).setPosition3d(Vector3(static_cast<Real>(0.7),
                                       static_cast<Real>(2.23733),
                                       static_cast<Real>(2.14574)));
  mol.addAtom(1).setPosition3d(Vector3(static_cast<Real>(2.07490),
                                       static_cast<Real>(2.09303),
                                       static_cast<Real>(1.07287)));
  mol.addAtom(1).setPosition3d(
    Vector3(static_cast<Real>(3), static_cast<Real>(0), static_cast<Real>(0)));
  mol.addAtom(1).setPosition3d(Vector3(static_cast<Real>(0.89980),
                                       static_cast<Real>(3.89748),
                                       static_cast<Real>(0)));
  mol.addAtom(1).setPosition3d(Vector3(static_cast<Real>(-2.5),
                                       static_cast<Real>(0.57717),
                                       static_cast<Real>(4.29149)));
  Array<Vector3> ccoords_ref = mol.atomPositions3d();

  Array<Vector3> fcoords;
  EXPECT_TRUE(CrystalTools::fractionalCoordinates(mol, fcoords));
  EXPECT_EQ(mol.atomCount(), fcoords.size());
  EXPECT_TRUE(std::fabs(fcoords[0][0] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[0][1] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[0][2] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[1][0] - static_cast<Real>(0.5)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[1][1] - static_cast<Real>(0.5)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[1][2] - static_cast<Real>(0.5)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[2][0] - static_cast<Real>(0.75)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[2][1] - static_cast<Real>(0.5)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[2][2] - static_cast<Real>(0.25)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[3][0] - static_cast<Real>(1)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[3][1] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[3][2] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[4][0] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[4][1] - static_cast<Real>(1)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[4][2] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[5][0] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[5][1] - static_cast<Real>(0)) < 1e-4);
  EXPECT_TRUE(std::fabs(fcoords[5][2] - static_cast<Real>(1)) < 1e-4);

  mol.atomPositions3d().clear();
  EXPECT_TRUE(CrystalTools::setFractionalCoordinates(mol, fcoords));
  Array<Vector3> ccoords = mol.atomPositions3d();
  for (int i = 0; i < 6; ++i) {
    for (int j = 0; j < 3; ++j) {
      EXPECT_FLOAT_EQ(static_cast<float>(ccoords_ref[i][j]),
                      static_cast<float>(ccoords[i][j]))
        << " (i=" << i << "j=" << j << ")";
    }
  }
}

TEST(UnitCellTest, wrapAtomsToUnitCell)
{
  Molecule mol = createCrystal(
    static_cast<Real>(3.0), static_cast<Real>(4.0), static_cast<Real>(5.0),
    static_cast<Real>(90.0), static_cast<Real>(120.0), static_cast<Real>(77.0));
  for (int i = 0; i < 10; ++i)
    mol.addAtom(1).setPosition3d(Vector3::Zero());

  Array<Vector3> fcoords;
  for (int i = 0; i < 10; ++i) {
    fcoords.push_back(Vector3(static_cast<Real>(i + i / 10.),
                              static_cast<Real>(i + 2 * i / 10.),
                              static_cast<Real>(i + 3 * i / 10.)));
  }

  EXPECT_TRUE(CrystalTools::setFractionalCoordinates(mol, fcoords));
  EXPECT_TRUE(CrystalTools::wrapAtomsToUnitCell(mol));
  fcoords.clear();
  EXPECT_TRUE(CrystalTools::fractionalCoordinates(mol, fcoords));
  for (std::vector<Vector3>::const_iterator it = fcoords.begin(),
                                            itEnd = fcoords.end();
       it != itEnd; ++it) {
    EXPECT_GE(it->x(), static_cast<Real>(0.0));
    EXPECT_LE(it->x(), static_cast<Real>(1.0));
    EXPECT_GE(it->y(), static_cast<Real>(0.0));
    EXPECT_LE(it->y(), static_cast<Real>(1.0));
    EXPECT_GE(it->z(), static_cast<Real>(0.0));
    EXPECT_LE(it->z(), static_cast<Real>(1.0));
  }
}
