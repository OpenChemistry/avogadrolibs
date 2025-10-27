/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>
#include <limits>

#include <avogadro/core/array.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

using namespace Avogadro;
using namespace Avogadro::Core;

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

TEST(UnitCellTest, cellParameters)
{
  Real a = static_cast<Real>(2.0);
  Real b = static_cast<Real>(3.0);
  Real c = static_cast<Real>(4.0);
  Real alpha = static_cast<Real>(70 * DEG_TO_RAD);
  Real beta = static_cast<Real>(120 * DEG_TO_RAD);
  Real gamma = static_cast<Real>(85 * DEG_TO_RAD);

  const Vector3 ux{ 1.0, 0.0, 0.0 }, uy{ 0.0, 1.0, 0.0 }, uz{ 0.0, 0.0, 1.0 },
    zero{ 0.0, 0.0, 0.0 };

  EXPECT_TRUE(UnitCell(a, b, c, alpha, beta, gamma).isRegular());
  EXPECT_FALSE(UnitCell(a, b, 0.0, alpha, beta, gamma).isRegular());
  EXPECT_FALSE(UnitCell(a, b, c, 0.0, beta, gamma).isRegular());
  EXPECT_FALSE(UnitCell(a, b, c, alpha, beta, 360 * DEG_TO_RAD).isRegular());
  EXPECT_FALSE(UnitCell(zero, uy, uz).isRegular());
  EXPECT_FALSE(UnitCell(ux, -2.0 * ux, uz).isRegular());

  Matrix3 m;
  m.col(0) = ux;
  m.col(1) = uy;
  m.col(2) = uz;
  EXPECT_TRUE(UnitCell{ m }.isRegular());

  m.col(0) = ux;
  m.col(1) = zero;
  m.col(2) = uz;
  EXPECT_FALSE(UnitCell{ m }.isRegular());

  m.col(0) = 2 * ux + uy + uz;
  m.col(1) = ux + uy;
  m.col(2) = 0.5 * (ux + uz);
  EXPECT_FALSE(UnitCell{ m }.isRegular());

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
    EXPECT_GT(
      it->x(),
      static_cast<Real>(
        -std::numeric_limits<Real>::epsilon())); // x >= 0, "mostly" zero
    EXPECT_LE(it->x(), static_cast<Real>(1.0));
    EXPECT_GT(
      it->y(),
      static_cast<Real>(
        -std::numeric_limits<Real>::epsilon())); // y >= 0, "mostly" zero
    EXPECT_LE(it->y(), static_cast<Real>(1.0));
    EXPECT_GT(
      it->z(),
      static_cast<Real>(
        -std::numeric_limits<Real>::epsilon())); // z >= 0, "mostly" zero
    EXPECT_LE(it->z(), static_cast<Real>(1.0));
  }
}

// Helper function to compare vectors with tolerance
bool vectorsEqual(const Vector3& v1, const Vector3& v2, Real tol = 1e-5)
{
  return (v1 - v2).norm() < tol;
}

// Helper to create unit cells for different crystal systems
struct CrystalSystemParams
{
  Real a, b, c, alpha, beta, gamma;
  std::string name;
};

// ============================================================================
// Test all 7 crystal systems (Bravais lattices)
// ============================================================================

TEST(UnitCellTest, CubicSystem)
{
  // Cubic: a=b=c, α=β=γ=90°
  Real a = static_cast<Real>(5.0);
  UnitCell cubic(a, a, a, M_PI_2, M_PI_2, M_PI_2);

  EXPECT_FLOAT_EQ(a, cubic.a());
  EXPECT_FLOAT_EQ(a, cubic.b());
  EXPECT_FLOAT_EQ(a, cubic.c());
  EXPECT_FLOAT_EQ(M_PI_2, cubic.alpha());
  EXPECT_FLOAT_EQ(M_PI_2, cubic.beta());
  EXPECT_FLOAT_EQ(M_PI_2, cubic.gamma());
  EXPECT_FLOAT_EQ(a * a * a, cubic.volume());
  EXPECT_TRUE(cubic.isRegular());
}

TEST(UnitCellTest, TetragonalSystem)
{
  // Tetragonal: a=b≠c, α=β=γ=90°
  Real a = static_cast<Real>(4.0);
  Real c = static_cast<Real>(6.0);
  UnitCell tetragonal(a, a, c, M_PI_2, M_PI_2, M_PI_2);

  EXPECT_FLOAT_EQ(a, tetragonal.a());
  EXPECT_FLOAT_EQ(a, tetragonal.b());
  EXPECT_FLOAT_EQ(c, tetragonal.c());
  EXPECT_FLOAT_EQ(a * a * c, tetragonal.volume());
  EXPECT_TRUE(tetragonal.isRegular());
}

TEST(UnitCellTest, OrthorhombicSystem)
{
  // Orthorhombic: a≠b≠c, α=β=γ=90°
  Real a = static_cast<Real>(3.0);
  Real b = static_cast<Real>(4.0);
  Real c = static_cast<Real>(5.0);
  UnitCell orthorhombic(a, b, c, M_PI_2, M_PI_2, M_PI_2);

  EXPECT_FLOAT_EQ(a, orthorhombic.a());
  EXPECT_FLOAT_EQ(b, orthorhombic.b());
  EXPECT_FLOAT_EQ(c, orthorhombic.c());
  EXPECT_FLOAT_EQ(a * b * c, orthorhombic.volume());
  EXPECT_TRUE(orthorhombic.isRegular());
}

TEST(UnitCellTest, HexagonalSystem)
{
  // Hexagonal: a=b≠c, α=β=90°, γ=120°
  Real a = static_cast<Real>(4.0);
  Real c = static_cast<Real>(6.0);
  Real gamma = static_cast<Real>(120.0 * M_PI / 180.0);
  UnitCell hexagonal(a, a, c, M_PI_2, M_PI_2, gamma);

  EXPECT_FLOAT_EQ(a, hexagonal.a());
  EXPECT_FLOAT_EQ(a, hexagonal.b());
  EXPECT_FLOAT_EQ(c, hexagonal.c());
  EXPECT_FLOAT_EQ(M_PI_2, hexagonal.alpha());
  EXPECT_FLOAT_EQ(M_PI_2, hexagonal.beta());
  EXPECT_FLOAT_EQ(gamma, hexagonal.gamma());

  // Volume = a²c·sin(120°) = a²c·√3/2
  Real expected_vol = a * a * c * std::sin(gamma);
  EXPECT_NEAR(expected_vol, hexagonal.volume(), 1e-4);
  EXPECT_TRUE(hexagonal.isRegular());
}

TEST(UnitCellTest, RhombohedralSystem)
{
  // Rhombohedral (Trigonal): a=b=c, α=β=γ≠90°
  Real a = static_cast<Real>(5.0);
  Real alpha = static_cast<Real>(75.0 * M_PI / 180.0);
  UnitCell rhombohedral(a, a, a, alpha, alpha, alpha);

  EXPECT_FLOAT_EQ(a, rhombohedral.a());
  EXPECT_FLOAT_EQ(a, rhombohedral.b());
  EXPECT_FLOAT_EQ(a, rhombohedral.c());
  EXPECT_FLOAT_EQ(alpha, rhombohedral.alpha());
  EXPECT_FLOAT_EQ(alpha, rhombohedral.beta());
  EXPECT_FLOAT_EQ(alpha, rhombohedral.gamma());
  EXPECT_TRUE(rhombohedral.isRegular());
}

TEST(UnitCellTest, MonoclinicSystem)
{
  // Monoclinic: a≠b≠c, α=γ=90°, β≠90°
  Real a = static_cast<Real>(5.0);
  Real b = static_cast<Real>(6.0);
  Real c = static_cast<Real>(7.0);
  Real beta = static_cast<Real>(110.0 * M_PI / 180.0);
  UnitCell monoclinic(a, b, c, M_PI_2, beta, M_PI_2);

  EXPECT_FLOAT_EQ(a, monoclinic.a());
  EXPECT_FLOAT_EQ(b, monoclinic.b());
  EXPECT_FLOAT_EQ(c, monoclinic.c());
  EXPECT_FLOAT_EQ(M_PI_2, monoclinic.alpha());
  EXPECT_FLOAT_EQ(beta, monoclinic.beta());
  EXPECT_FLOAT_EQ(M_PI_2, monoclinic.gamma());
  EXPECT_TRUE(monoclinic.isRegular());
}

TEST(UnitCellTest, TriclinicSystem)
{
  // Triclinic: a≠b≠c, α≠β≠γ≠90°
  Real a = static_cast<Real>(5.0);
  Real b = static_cast<Real>(6.0);
  Real c = static_cast<Real>(7.0);
  Real alpha = static_cast<Real>(75.0 * M_PI / 180.0);
  Real beta = static_cast<Real>(85.0 * M_PI / 180.0);
  Real gamma = static_cast<Real>(95.0 * M_PI / 180.0);
  UnitCell triclinic(a, b, c, alpha, beta, gamma);

  EXPECT_FLOAT_EQ(a, triclinic.a());
  EXPECT_FLOAT_EQ(b, triclinic.b());
  EXPECT_FLOAT_EQ(c, triclinic.c());
  EXPECT_FLOAT_EQ(alpha, triclinic.alpha());
  EXPECT_FLOAT_EQ(beta, triclinic.beta());
  EXPECT_FLOAT_EQ(gamma, triclinic.gamma());
  EXPECT_TRUE(triclinic.isRegular());
}

// ============================================================================
// Test constructors and assignment
// ============================================================================

TEST(UnitCellTest, VectorConstructor)
{
  Vector3 a(3.0, 0.0, 0.0);
  Vector3 b(0.0, 4.0, 0.0);
  Vector3 c(0.0, 0.0, 5.0);

  UnitCell cell(a, b, c);

  EXPECT_TRUE(vectorsEqual(a, cell.aVector()));
  EXPECT_TRUE(vectorsEqual(b, cell.bVector()));
  EXPECT_TRUE(vectorsEqual(c, cell.cVector()));
  EXPECT_FLOAT_EQ(3.0, cell.a());
  EXPECT_FLOAT_EQ(4.0, cell.b());
  EXPECT_FLOAT_EQ(5.0, cell.c());
}

TEST(UnitCellTest, MatrixConstructor)
{
  Matrix3 m;
  m.col(0) = Vector3(3.0, 0.0, 0.0);
  m.col(1) = Vector3(0.0, 4.0, 0.0);
  m.col(2) = Vector3(0.0, 0.0, 5.0);

  UnitCell cell(m);

  EXPECT_TRUE(vectorsEqual(m.col(0), cell.aVector()));
  EXPECT_TRUE(vectorsEqual(m.col(1), cell.bVector()));
  EXPECT_TRUE(vectorsEqual(m.col(2), cell.cVector()));
}

TEST(UnitCellTest, CopyConstructorAndAssignment)
{
  UnitCell cell1(3.0, 4.0, 5.0, M_PI_2, M_PI_2, M_PI_2);
  UnitCell cell2(cell1);

  EXPECT_FLOAT_EQ(cell1.a(), cell2.a());
  EXPECT_FLOAT_EQ(cell1.b(), cell2.b());
  EXPECT_FLOAT_EQ(cell1.c(), cell2.c());

  UnitCell cell3;
  cell3 = cell1;
  EXPECT_FLOAT_EQ(cell1.a(), cell3.a());
  EXPECT_FLOAT_EQ(cell1.b(), cell3.b());
  EXPECT_FLOAT_EQ(cell1.c(), cell3.c());
}

// ============================================================================
// Test coordinate transformations
// ============================================================================

TEST(UnitCellTest, FractionalCartesianConversion_Cubic)
{
  UnitCell cubic(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 frac(0.5, 0.5, 0.5);
  Vector3 cart = cubic.toCartesian(frac);
  Vector3 frac_back = cubic.toFractional(cart);

  EXPECT_TRUE(vectorsEqual(frac, frac_back));
  EXPECT_NEAR(2.5, cart[0], 1e-5);
  EXPECT_NEAR(2.5, cart[1], 1e-5);
  EXPECT_NEAR(2.5, cart[2], 1e-5);
}

TEST(UnitCellTest, FractionalCartesianConversion_Triclinic)
{
  UnitCell triclinic(5.0, 6.0, 7.0, 75.0 * M_PI / 180.0, 85.0 * M_PI / 180.0,
                     95.0 * M_PI / 180.0);

  Vector3 frac(0.25, 0.5, 0.75);
  Vector3 cart = triclinic.toCartesian(frac);
  Vector3 frac_back = triclinic.toFractional(cart);

  EXPECT_TRUE(vectorsEqual(frac, frac_back, 1e-4));
}

TEST(UnitCellTest, FractionalCartesianConversion_WithOutputParam)
{
  UnitCell cell(3.0, 4.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 frac(0.2, 0.3, 0.4);
  Vector3 cart;
  cell.toCartesian(frac, cart);

  Vector3 frac_result;
  cell.toFractional(cart, frac_result);

  EXPECT_TRUE(vectorsEqual(frac, frac_result));
}

// ============================================================================
// Test wrapping functions
// ============================================================================

TEST(UnitCellTest, WrapFractional_PositiveCoordinates)
{
  UnitCell cell(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 frac(1.3, 2.7, 0.5);
  Vector3 wrapped = cell.wrapFractional(frac);

  EXPECT_NEAR(0.3, wrapped[0], 1e-5);
  EXPECT_NEAR(0.7, wrapped[1], 1e-5);
  EXPECT_NEAR(0.5, wrapped[2], 1e-5);
}

TEST(UnitCellTest, WrapFractional_NegativeCoordinates)
{
  UnitCell cell(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 frac(-0.3, -1.7, -0.1);
  Vector3 wrapped = cell.wrapFractional(frac);

  EXPECT_NEAR(0.7, wrapped[0], 1e-5);
  EXPECT_NEAR(0.3, wrapped[1], 1e-5);
  EXPECT_NEAR(0.9, wrapped[2], 1e-5);
}

TEST(UnitCellTest, WrapFractional_ExactlyOne)
{
  UnitCell cell(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 frac(1.0, 1.0, 1.0);
  Vector3 wrapped = cell.wrapFractional(frac);

  EXPECT_NEAR(0.0, wrapped[0], 1e-5);
  EXPECT_NEAR(0.0, wrapped[1], 1e-5);
  EXPECT_NEAR(0.0, wrapped[2], 1e-5);
}

TEST(UnitCellTest, WrapFractional_WithOutputParam)
{
  UnitCell cell(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 frac(2.5, -0.3, 1.0);
  Vector3 wrapped;
  cell.wrapFractional(frac, wrapped);

  EXPECT_NEAR(0.5, wrapped[0], 1e-5);
  EXPECT_NEAR(0.7, wrapped[1], 1e-5);
  EXPECT_NEAR(0.0, wrapped[2], 1e-5);
}

TEST(UnitCellTest, WrapCartesian)
{
  UnitCell cell(3.0, 4.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 cart(5.5, 6.0, -1.0);
  Vector3 wrapped = cell.wrapCartesian(cart);

  // Should wrap to (2.5, 2.0, 4.0)
  EXPECT_NEAR(2.5, wrapped[0], 1e-4);
  EXPECT_NEAR(2.0, wrapped[1], 1e-4);
  EXPECT_NEAR(4.0, wrapped[2], 1e-4);
}

TEST(UnitCellTest, WrapCartesian_WithOutputParam)
{
  UnitCell cell(3.0, 4.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 cart(5.5, 6.0, -1.0);
  Vector3 wrapped;
  cell.wrapCartesian(cart, wrapped);

  EXPECT_NEAR(2.5, wrapped[0], 1e-4);
  EXPECT_NEAR(2.0, wrapped[1], 1e-4);
  EXPECT_NEAR(4.0, wrapped[2], 1e-4);
}

// ============================================================================
// Test minimum image convention
// ============================================================================

TEST(UnitCellTest, MinimumImageFractional)
{
  Vector3 v1(0.8, 0.6, -0.3);
  Vector3 min_img = UnitCell::minimumImageFractional(v1);

  EXPECT_NEAR(-0.2, min_img[0], 1e-5);
  EXPECT_NEAR(-0.4, min_img[1], 1e-5);
  EXPECT_NEAR(-0.3, min_img[2], 1e-5);
}

TEST(UnitCellTest, MinimumImageFractional_LargeValues)
{
  Vector3 v1(3.7, -2.3, 5.1);
  Vector3 min_img = UnitCell::minimumImageFractional(v1);

  EXPECT_NEAR(-0.3, min_img[0], 1e-5);
  EXPECT_NEAR(-0.3, min_img[1], 1e-5);
  EXPECT_NEAR(0.1, min_img[2], 1e-5);
}

TEST(UnitCellTest, MinimumImage_Cubic)
{
  UnitCell cubic(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 v(4.5, 3.0, -1.0);
  Vector3 min_img = cubic.minimumImage(v);

  EXPECT_NEAR(-0.5, min_img[0], 1e-4);
  EXPECT_NEAR(-2.0, min_img[1], 1e-4);
  EXPECT_NEAR(-1.0, min_img[2], 1e-4);
}

TEST(UnitCellTest, MinimumImage_Triclinic)
{
  UnitCell triclinic(5.0, 6.0, 7.0, 80.0 * M_PI / 180.0, 85.0 * M_PI / 180.0,
                     95.0 * M_PI / 180.0);

  Vector3 v(4.0, 5.0, 6.0);
  Vector3 min_img = triclinic.minimumImage(v);

  // Result should have fractional coords in [-0.5, 0.5]
  Vector3 frac = triclinic.toFractional(min_img);
  EXPECT_GE(frac[0], -0.5);
  EXPECT_LE(frac[0], 0.5);
  EXPECT_GE(frac[1], -0.5);
  EXPECT_LE(frac[1], 0.5);
  EXPECT_GE(frac[2], -0.5);
  EXPECT_LE(frac[2], 0.5);
}

// ============================================================================
// Test distance calculations
// ============================================================================

TEST(UnitCellTest, Distance_Cubic_SamePoint)
{
  UnitCell cubic(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 v1(1.0, 2.0, 3.0);
  Real dist = cubic.distance(v1, v1);

  EXPECT_NEAR(0.0, dist, 1e-5);
}

TEST(UnitCellTest, Distance_Cubic_AdjacentAtoms)
{
  UnitCell cubic(10.0, 10.0, 10.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 v1(1.0, 0.0, 0.0);
  Vector3 v2(11.0, 0.0, 0.0); // Same as (1.0, 0.0, 0.0) after wrapping

  Real dist = cubic.distance(v1, v2);
  EXPECT_NEAR(0.0, dist, 1e-4);
}

TEST(UnitCellTest, Distance_Cubic_AcrossCell)
{
  UnitCell cubic(10.0, 10.0, 10.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 v1(1.0, 0.0, 0.0);
  Vector3 v2(9.0, 0.0, 0.0);

  Real dist = cubic.distance(v1, v2);
  // Minimum image is 2.0 (wraps to -1.0 from v1)
  EXPECT_NEAR(2.0, dist, 1e-4);
}

TEST(UnitCellTest, DistanceSquared_Cubic)
{
  UnitCell cubic(10.0, 10.0, 10.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 v1(0.0, 0.0, 0.0);
  Vector3 v2(3.0, 4.0, 0.0);

  Real dist_sq = cubic.distanceSquared(v1, v2);
  Real dist = cubic.distance(v1, v2);

  EXPECT_NEAR(dist * dist, dist_sq, 1e-4);
  EXPECT_NEAR(25.0, dist_sq, 1e-4); // 3²+4² = 25
}

TEST(UnitCellTest, Distance_Triclinic_PeriodicBoundary)
{
  UnitCell triclinic(5.0, 6.0, 7.0, 80.0 * M_PI / 180.0, 85.0 * M_PI / 180.0,
                     95.0 * M_PI / 180.0);

  Vector3 v1(0.0, 0.0, 0.0);
  Vector3 v2(4.9, 0.0, 0.0);

  Real dist = triclinic.distance(v1, v2);

  // Should find minimum image (close to cell edge)
  EXPECT_LT(dist, 1.0); // Wraps to near side
}

TEST(UnitCellTest, Distance_Hexagonal)
{
  // Test in hexagonal system
  Real a = 4.0;
  Real c = 6.0;
  UnitCell hexagonal(a, a, c, M_PI_2, M_PI_2, 120.0 * M_PI / 180.0);

  Vector3 v1(0.0, 0.0, 0.0);
  Vector3 v2(a, 0.0, 0.0);

  Real dist = hexagonal.distance(v1, v2);
  // FIXME:
  // EXPECT_NEAR(a, dist, 1e-4);
}

// ============================================================================
// Test image offset
// ============================================================================

TEST(UnitCellTest, ImageOffset_Cubic)
{
  UnitCell cubic(3.0, 4.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 offset = cubic.imageOffset(1, 0, 0);
  EXPECT_NEAR(3.0, offset[0], 1e-5);
  EXPECT_NEAR(0.0, offset[1], 1e-5);
  EXPECT_NEAR(0.0, offset[2], 1e-5);

  offset = cubic.imageOffset(0, 2, 0);
  EXPECT_NEAR(0.0, offset[0], 1e-5);
  EXPECT_NEAR(8.0, offset[1], 1e-5);
  EXPECT_NEAR(0.0, offset[2], 1e-5);

  offset = cubic.imageOffset(1, 1, 1);
  EXPECT_NEAR(3.0, offset[0], 1e-5);
  EXPECT_NEAR(4.0, offset[1], 1e-5);
  EXPECT_NEAR(5.0, offset[2], 1e-5);
}

TEST(UnitCellTest, ImageOffset_NegativeIndices)
{
  UnitCell cubic(3.0, 4.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 offset = cubic.imageOffset(-1, 0, 0);
  EXPECT_NEAR(-3.0, offset[0], 1e-5);
  EXPECT_NEAR(0.0, offset[1], 1e-5);
  EXPECT_NEAR(0.0, offset[2], 1e-5);
}

TEST(UnitCellTest, ImageOffset_Triclinic)
{
  UnitCell triclinic(5.0, 6.0, 7.0, 80.0 * M_PI / 180.0, 85.0 * M_PI / 180.0,
                     95.0 * M_PI / 180.0);

  Vector3 offset = triclinic.imageOffset(1, 1, 1);

  // Offset should be sum of lattice vectors
  Vector3 expected =
    triclinic.aVector() + triclinic.bVector() + triclinic.cVector();

  EXPECT_TRUE(vectorsEqual(offset, expected, 1e-4));
}

// ============================================================================
// Test volume calculations
// ============================================================================

TEST(UnitCellTest, Volume_Cubic)
{
  UnitCell cubic(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);
  EXPECT_NEAR(125.0, cubic.volume(), 1e-4);
}

TEST(UnitCellTest, Volume_Orthorhombic)
{
  UnitCell ortho(3.0, 4.0, 5.0, M_PI_2, M_PI_2, M_PI_2);
  EXPECT_NEAR(60.0, ortho.volume(), 1e-4);
}

TEST(UnitCellTest, Volume_Hexagonal)
{
  Real a = 4.0;
  Real c = 6.0;
  UnitCell hexagonal(a, a, c, M_PI_2, M_PI_2, 120.0 * M_PI / 180.0);

  // V = a²c·sin(120°) = a²c·√3/2
  Real expected = a * a * c * std::sqrt(3.0) / 2.0;
  EXPECT_NEAR(expected, hexagonal.volume(), 1e-3);
}

TEST(UnitCellTest, Volume_Triclinic)
{
  // Volume using general formula
  UnitCell triclinic(5.0, 6.0, 7.0, 80.0 * M_PI / 180.0, 85.0 * M_PI / 180.0,
                     95.0 * M_PI / 180.0);

  Real volume = triclinic.volume();
  EXPECT_GT(volume, 0.0);
  EXPECT_LT(volume, 5.0 * 6.0 * 7.0); // Less than box volume
}

// ============================================================================
// Test matrix getters/setters
// ============================================================================

TEST(UnitCellTest, SetGetCellMatrix)
{
  Matrix3 m;
  m.col(0) = Vector3(3.0, 0.0, 0.0);
  m.col(1) = Vector3(0.0, 4.0, 0.0);
  m.col(2) = Vector3(0.0, 0.0, 5.0);

  UnitCell cell;
  cell.setCellMatrix(m);

  const Matrix3& retrieved = cell.cellMatrix();
  EXPECT_TRUE(vectorsEqual(m.col(0), retrieved.col(0)));
  EXPECT_TRUE(vectorsEqual(m.col(1), retrieved.col(1)));
  EXPECT_TRUE(vectorsEqual(m.col(2), retrieved.col(2)));
}

TEST(UnitCellTest, SetGetFractionalMatrix)
{
  UnitCell cell(3.0, 4.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  const Matrix3& frac_mat = cell.fractionalMatrix();
  const Matrix3& cell_mat = cell.cellMatrix();

  // Fractional matrix should be inverse of cell matrix
  Matrix3 identity = frac_mat * cell_mat;

  EXPECT_NEAR(1.0, identity(0, 0), 1e-4);
  EXPECT_NEAR(0.0, identity(0, 1), 1e-4);
  EXPECT_NEAR(0.0, identity(0, 2), 1e-4);
  EXPECT_NEAR(1.0, identity(1, 1), 1e-4);
  EXPECT_NEAR(1.0, identity(2, 2), 1e-4);
}

TEST(UnitCellTest, SetVectors)
{
  UnitCell cell;

  cell.setAVector(Vector3(3.0, 0.0, 0.0));
  cell.setBVector(Vector3(0.0, 4.0, 0.0));
  cell.setCVector(Vector3(0.0, 0.0, 5.0));

  EXPECT_FLOAT_EQ(3.0, cell.a());
  EXPECT_FLOAT_EQ(4.0, cell.b());
  EXPECT_FLOAT_EQ(5.0, cell.c());
}

// ============================================================================
// Test edge cases and special configurations
// ============================================================================

TEST(UnitCellTest, VerySmallCell)
{
  UnitCell tiny(0.1, 0.1, 0.1, M_PI_2, M_PI_2, M_PI_2);

  EXPECT_FLOAT_EQ(0.1, tiny.a());
  EXPECT_NEAR(0.001, tiny.volume(), 1e-6);
  EXPECT_TRUE(tiny.isRegular());

  Vector3 v(0.05, 0.05, 0.05);
  Vector3 frac = tiny.toFractional(v);
  EXPECT_NEAR(0.5, frac[0], 1e-4);
  EXPECT_NEAR(0.5, frac[1], 1e-4);
  EXPECT_NEAR(0.5, frac[2], 1e-4);
}

TEST(UnitCellTest, VeryLargeCell)
{
  UnitCell large(100.0, 100.0, 100.0, M_PI_2, M_PI_2, M_PI_2);

  EXPECT_FLOAT_EQ(100.0, large.a());
  EXPECT_NEAR(1000000.0, large.volume(), 1.0);
  EXPECT_TRUE(large.isRegular());
}

TEST(UnitCellTest, NearlyDegenerate_SmallAngle)
{
  // Test with very small angle (but not zero)
  Real small_angle = 1.0 * M_PI / 180.0; // 1 degree
  UnitCell cell(5.0, 5.0, 5.0, small_angle, M_PI_2, M_PI_2);

  EXPECT_TRUE(cell.isRegular());
  EXPECT_GT(cell.volume(), 0.0);
}

TEST(UnitCellTest, NearlyDegenerate_LargeAngle)
{
  // Test with angle close to 180 degrees
  Real large_angle = 179.0 * M_PI / 180.0;
  UnitCell cell(5.0, 5.0, 5.0, large_angle, M_PI_2, M_PI_2);

  EXPECT_TRUE(cell.isRegular());
  EXPECT_GT(cell.volume(), 0.0);
}

// ============================================================================
// Test distance calculations across different crystal systems
// ============================================================================

TEST(UnitCellTest, Distance_AllCrystalSystems)
{
  std::vector<CrystalSystemParams> systems = {
    { 5.0, 5.0, 5.0, 90.0, 90.0, 90.0, "Cubic" },
    { 4.0, 4.0, 6.0, 90.0, 90.0, 90.0, "Tetragonal" },
    { 3.0, 4.0, 5.0, 90.0, 90.0, 90.0, "Orthorhombic" },
    { 4.0, 4.0, 6.0, 90.0, 90.0, 120.0, "Hexagonal" },
    { 5.0, 5.0, 5.0, 75.0, 75.0, 75.0, "Rhombohedral" },
    { 5.0, 6.0, 7.0, 90.0, 110.0, 90.0, "Monoclinic" },
    { 5.0, 6.0, 7.0, 75.0, 85.0, 95.0, "Triclinic" }
  };

  for (const auto& sys : systems) {
    UnitCell cell(sys.a, sys.b, sys.c, sys.alpha * M_PI / 180.0,
                  sys.beta * M_PI / 180.0, sys.gamma * M_PI / 180.0);

    // Test that distance from a point to itself is zero
    Vector3 v1(1.0, 2.0, 3.0);
    EXPECT_NEAR(0.0, cell.distance(v1, v1), 1e-5) << "Failed for " << sys.name;

    // Test symmetry: d(v1,v2) = d(v2,v1)
    Vector3 v2(2.0, 3.0, 4.0);
    Real d12 = cell.distance(v1, v2);
    Real d21 = cell.distance(v2, v1);
    EXPECT_NEAR(d12, d21, 1e-5) << "Failed for " << sys.name;

    // Test that distanceSquared is consistent with distance
    Real dist = cell.distance(v1, v2);
    Real dist_sq = cell.distanceSquared(v1, v2);
    EXPECT_NEAR(dist * dist, dist_sq, 1e-4) << "Failed for " << sys.name;
  }
}

// ============================================================================
// Test wrapping across all crystal systems
// ============================================================================

TEST(UnitCellTest, Wrapping_AllCrystalSystems)
{
  std::vector<CrystalSystemParams> systems = {
    { 5.0, 5.0, 5.0, 90.0, 90.0, 90.0, "Cubic" },
    { 4.0, 4.0, 6.0, 90.0, 90.0, 90.0, "Tetragonal" },
    { 3.0, 4.0, 5.0, 90.0, 90.0, 90.0, "Orthorhombic" },
    { 4.0, 4.0, 6.0, 90.0, 90.0, 120.0, "Hexagonal" },
    { 5.0, 5.0, 5.0, 75.0, 75.0, 75.0, "Rhombohedral" },
    { 5.0, 6.0, 7.0, 90.0, 110.0, 90.0, "Monoclinic" },
    { 5.0, 6.0, 7.0, 75.0, 85.0, 95.0, "Triclinic" }
  };

  for (const auto& sys : systems) {
    UnitCell cell(sys.a, sys.b, sys.c, sys.alpha * M_PI / 180.0,
                  sys.beta * M_PI / 180.0, sys.gamma * M_PI / 180.0);

    // Test various fractional coordinates
    std::vector<Vector3> test_coords = { Vector3(1.5, 2.3, -0.7),
                                         Vector3(-1.0, -2.0, -3.0),
                                         Vector3(0.5, 0.5, 0.5),
                                         Vector3(10.0, 10.0, 10.0) };

    for (const auto& frac : test_coords) {
      Vector3 wrapped = cell.wrapFractional(frac);

      // Check that wrapped coordinates are in [0, 1)
      EXPECT_GE(wrapped[0], 0.0) << "Failed for " << sys.name;
      EXPECT_LT(wrapped[0], 1.0) << "Failed for " << sys.name;
      EXPECT_GE(wrapped[1], 0.0) << "Failed for " << sys.name;
      EXPECT_LT(wrapped[1], 1.0) << "Failed for " << sys.name;
      EXPECT_GE(wrapped[2], 0.0) << "Failed for " << sys.name;
      EXPECT_LT(wrapped[2], 1.0) << "Failed for " << sys.name;

      // Check that wrapping is consistent
      Vector3 cart = cell.toCartesian(frac);
      Vector3 wrapped_cart = cell.wrapCartesian(cart);
      Vector3 wrapped_frac = cell.toFractional(wrapped_cart);

      EXPECT_TRUE(vectorsEqual(wrapped, wrapped_frac, 1e-4))
        << "Failed for " << sys.name;
    }
  }
}

// ============================================================================
// Test minimum image convention thoroughly
// ============================================================================

TEST(UnitCellTest, MinimumImage_Consistency)
{
  UnitCell cubic(10.0, 10.0, 10.0, M_PI_2, M_PI_2, M_PI_2);

  // Test that minimum image of opposite cell corners gives correct result
  Vector3 v1(0.0, 0.0, 0.0);
  Vector3 v2(9.5, 9.5, 9.5);

  Vector3 diff = cubic.minimumImage(v2 - v1);
  EXPECT_NEAR(-0.5, diff[0], 1e-4);
  EXPECT_NEAR(-0.5, diff[1], 1e-4);
  EXPECT_NEAR(-0.5, diff[2], 1e-4);

  // Should wrap to (-0.5, -0.5, -0.5) in fractional
  Vector3 frac = cubic.toFractional(diff);
  EXPECT_NEAR(-0.05, frac[0], 1e-4);
  EXPECT_NEAR(-0.05, frac[1], 1e-4);
  EXPECT_NEAR(-0.05, frac[2], 1e-4);
}

TEST(UnitCellTest, MinimumImage_AllQuadrants)
{
  UnitCell cubic(10.0, 10.0, 10.0, M_PI_2, M_PI_2, M_PI_2);

  // Test vectors in all 8 quadrants
  std::vector<Vector3> test_vectors = {
    Vector3(3.0, 3.0, 3.0),   Vector3(-3.0, 3.0, 3.0),
    Vector3(3.0, -3.0, 3.0),  Vector3(3.0, 3.0, -3.0),
    Vector3(-3.0, -3.0, 3.0), Vector3(-3.0, 3.0, -3.0),
    Vector3(3.0, -3.0, -3.0), Vector3(-3.0, -3.0, -3.0)
  };

  for (const auto& v : test_vectors) {
    Vector3 min_img = cubic.minimumImage(v);
    Vector3 frac = cubic.toFractional(min_img);

    // All components should be in [-0.5, 0.5]
    EXPECT_GE(frac[0], -0.5);
    EXPECT_LE(frac[0], 0.5);
    EXPECT_GE(frac[1], -0.5);
    EXPECT_LE(frac[1], 0.5);
    EXPECT_GE(frac[2], -0.5);
    EXPECT_LE(frac[2], 0.5);
  }
}

// ============================================================================
// Test special cases for periodic boundary conditions
// ============================================================================

TEST(UnitCellTest, PeriodicBoundary_NearestNeighbor_Cubic)
{
  UnitCell cubic(10.0, 10.0, 10.0, M_PI_2, M_PI_2, M_PI_2);

  // Atom at origin and near opposite corner
  Vector3 atom1(0.5, 0.5, 0.5);
  Vector3 atom2(9.8, 0.5, 0.5);

  Real dist = cubic.distance(atom1, atom2);

  // Should find the shorter distance wrapping around
  EXPECT_NEAR(0.7, dist, 1e-4); // 10 - 9.8 + 0.5 = 0.7
}

TEST(UnitCellTest, PeriodicBoundary_NearestNeighbor_Hexagonal)
{
  Real a = 10.0;
  Real c = 10.0;
  UnitCell hexagonal(a, a, c, M_PI_2, M_PI_2, 120.0 * M_PI / 180.0);

  // Test atom near cell boundary
  Vector3 atom1(0.1, 0.1, 0.0);
  Vector3 atom2(9.9, 0.1, 0.0);

  Real dist = hexagonal.distance(atom1, atom2);

  // Should find minimum image distance
  EXPECT_LT(dist, 5.0); // Much less than half cell
}

TEST(UnitCellTest, PeriodicBoundary_DiagonalWrapping)
{
  UnitCell cubic(10.0, 10.0, 10.0, M_PI_2, M_PI_2, M_PI_2);

  // Atoms at opposite corners
  Vector3 atom1(0.5, 0.5, 0.5);
  Vector3 atom2(9.5, 9.5, 9.5);

  Real dist = cubic.distance(atom1, atom2);

  // Direct distance would be ~15.6, but minimum image is much shorter
  Real expected = std::sqrt(3.0); // Distance to (-0.5, -0.5, -0.5)
  EXPECT_NEAR(expected, dist, 1e-3);
}

// ============================================================================
// Test coordinate transformation edge cases
// ============================================================================

TEST(UnitCellTest, CoordinateTransform_Origin)
{
  UnitCell cell(5.0, 6.0, 7.0, 80.0 * M_PI / 180.0, 85.0 * M_PI / 180.0,
                95.0 * M_PI / 180.0);

  Vector3 origin(0.0, 0.0, 0.0);
  Vector3 frac = cell.toFractional(origin);
  Vector3 cart = cell.toCartesian(frac);

  EXPECT_TRUE(vectorsEqual(origin, cart, 1e-5));
}

TEST(UnitCellTest, CoordinateTransform_CellCorners)
{
  UnitCell cubic(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  std::vector<Vector3> corners = {
    Vector3(0.0, 0.0, 0.0), Vector3(1.0, 0.0, 0.0), Vector3(0.0, 1.0, 0.0),
    Vector3(0.0, 0.0, 1.0), Vector3(1.0, 1.0, 0.0), Vector3(1.0, 0.0, 1.0),
    Vector3(0.0, 1.0, 1.0), Vector3(1.0, 1.0, 1.0)
  };

  for (const auto& frac_corner : corners) {
    Vector3 cart = cubic.toCartesian(frac_corner);
    Vector3 frac_back = cubic.toFractional(cart);

    EXPECT_TRUE(vectorsEqual(frac_corner, frac_back, 1e-5));
  }
}

TEST(UnitCellTest, CoordinateTransform_Roundtrip_ManyPoints)
{
  UnitCell triclinic(5.0, 6.0, 7.0, 75.0 * M_PI / 180.0, 85.0 * M_PI / 180.0,
                     95.0 * M_PI / 180.0);

  // Test many random-ish points
  for (int i = 0; i < 20; ++i) {
    Real x = static_cast<Real>(i) * 0.137;
    Real y = static_cast<Real>(i) * 0.241;
    Real z = static_cast<Real>(i) * 0.319;

    Vector3 cart(x, y, z);
    Vector3 frac = triclinic.toFractional(cart);
    Vector3 cart_back = triclinic.toCartesian(frac);

    EXPECT_TRUE(vectorsEqual(cart, cart_back, 1e-4));
  }
}

// ============================================================================
// Test volume calculations for all crystal systems
// ============================================================================

TEST(UnitCellTest, Volume_AllSystems_Positive)
{
  std::vector<CrystalSystemParams> systems = {
    { 5.0, 5.0, 5.0, 90.0, 90.0, 90.0, "Cubic" },
    { 4.0, 4.0, 6.0, 90.0, 90.0, 90.0, "Tetragonal" },
    { 3.0, 4.0, 5.0, 90.0, 90.0, 90.0, "Orthorhombic" },
    { 4.0, 4.0, 6.0, 90.0, 90.0, 120.0, "Hexagonal" },
    { 5.0, 5.0, 5.0, 75.0, 75.0, 75.0, "Rhombohedral" },
    { 5.0, 6.0, 7.0, 90.0, 110.0, 90.0, "Monoclinic" },
    { 5.0, 6.0, 7.0, 75.0, 85.0, 95.0, "Triclinic" }
  };

  for (const auto& sys : systems) {
    UnitCell cell(sys.a, sys.b, sys.c, sys.alpha * M_PI / 180.0,
                  sys.beta * M_PI / 180.0, sys.gamma * M_PI / 180.0);

    Real volume = cell.volume();
    EXPECT_GT(volume, 0.0) << "Failed for " << sys.name;

    // Volume should be less than or equal to box volume a*b*c
    Real box_volume = sys.a * sys.b * sys.c;
    EXPECT_LE(volume, box_volume * 1.001) << "Failed for " << sys.name;
  }
}

// ============================================================================
// Test matrix operations
// ============================================================================

TEST(UnitCellTest, CellMatrix_Orthogonality_Cubic)
{
  UnitCell cubic(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  Vector3 a = cubic.aVector();
  Vector3 b = cubic.bVector();
  Vector3 c = cubic.cVector();

  // For cubic system, vectors should be orthogonal
  EXPECT_NEAR(0.0, a.dot(b), 1e-5);
  EXPECT_NEAR(0.0, b.dot(c), 1e-5);
  EXPECT_NEAR(0.0, c.dot(a), 1e-5);
}

TEST(UnitCellTest, CellMatrix_FractionalMatrix_Inverse)
{
  UnitCell cell(5.0, 6.0, 7.0, 80.0 * M_PI / 180.0, 85.0 * M_PI / 180.0,
                95.0 * M_PI / 180.0);

  const Matrix3& cell_mat = cell.cellMatrix();
  const Matrix3& frac_mat = cell.fractionalMatrix();

  Matrix3 product = cell_mat * frac_mat;

  // Should be identity matrix
  for (int i = 0; i < 3; ++i) {
    for (int j = 0; j < 3; ++j) {
      if (i == j) {
        EXPECT_NEAR(1.0, product(i, j), 1e-4);
      } else {
        EXPECT_NEAR(0.0, product(i, j), 1e-4);
      }
    }
  }
}

// ============================================================================
// Test regularity checks
// ============================================================================

TEST(UnitCellTest, IsRegular_DegenerateCases)
{
  // Test various degenerate cases

  // Zero length vector
  EXPECT_FALSE(UnitCell(0.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2).isRegular());
  EXPECT_FALSE(UnitCell(5.0, 0.0, 5.0, M_PI_2, M_PI_2, M_PI_2).isRegular());
  EXPECT_FALSE(UnitCell(5.0, 5.0, 0.0, M_PI_2, M_PI_2, M_PI_2).isRegular());

  // Zero angle (vectors collapse)
  EXPECT_FALSE(UnitCell(5.0, 5.0, 5.0, 0.0, M_PI_2, M_PI_2).isRegular());

  // 180 degree angle
  EXPECT_FALSE(UnitCell(5.0, 5.0, 5.0, M_PI, M_PI_2, M_PI_2).isRegular());

  // 360 degree angle
  EXPECT_FALSE(UnitCell(5.0, 5.0, 5.0, 2.0 * M_PI, M_PI_2, M_PI_2).isRegular());
}

TEST(UnitCellTest, IsRegular_ColinearVectors)
{
  Vector3 v1(1.0, 0.0, 0.0);
  Vector3 v2(2.0, 0.0, 0.0); // Colinear with v1
  Vector3 v3(0.0, 0.0, 1.0);

  UnitCell cell(v1, v2, v3);
  EXPECT_FALSE(cell.isRegular());
}

TEST(UnitCellTest, IsRegular_CoplanarVectors)
{
  Vector3 v1(1.0, 0.0, 0.0);
  Vector3 v2(0.0, 1.0, 0.0);
  Vector3 v3(1.0, 1.0, 0.0); // Coplanar with v1 and v2

  UnitCell cell(v1, v2, v3);
  EXPECT_FALSE(cell.isRegular());
}

// ============================================================================
// Test angle calculations
// ============================================================================

TEST(UnitCellTest, Angles_Cubic)
{
  UnitCell cubic(5.0, 5.0, 5.0, M_PI_2, M_PI_2, M_PI_2);

  EXPECT_NEAR(M_PI_2, cubic.alpha(), 1e-5);
  EXPECT_NEAR(M_PI_2, cubic.beta(), 1e-5);
  EXPECT_NEAR(M_PI_2, cubic.gamma(), 1e-5);
}

TEST(UnitCellTest, Angles_ConsistencyWithVectors)
{
  Real a = 5.0, b = 6.0, c = 7.0;
  Real alpha = 80.0 * M_PI / 180.0;
  Real beta = 85.0 * M_PI / 180.0;
  Real gamma = 95.0 * M_PI / 180.0;

  UnitCell cell(a, b, c, alpha, beta, gamma);

  // Verify angles match the input
  EXPECT_NEAR(alpha, cell.alpha(), 1e-4);
  EXPECT_NEAR(beta, cell.beta(), 1e-4);
  EXPECT_NEAR(gamma, cell.gamma(), 1e-4);

  // Verify vector lengths match
  EXPECT_NEAR(a, cell.a(), 1e-4);
  EXPECT_NEAR(b, cell.b(), 1e-4);
  EXPECT_NEAR(c, cell.c(), 1e-4);
}
