/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/eeqmodel.h>

#include <avogadro/core/molecule.h>

#include <algorithm>
#include <cmath>
#include <memory>
#include <vector>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using Avogadro::MatrixX;
using Avogadro::Vector3;

namespace {

struct RefAtom
{
  unsigned char atomicNumber;
  double x, y, z; // Angstrom
};

// Geometries are arbitrary but reasonable; the reference charges were
// generated with multicharge 0.3.0 (grimme-lab, EEQ 2019 model, the default):
//   multicharge --json -c <total charge> molecule.xyz
struct ReferenceCase
{
  const char* name;
  int totalCharge;
  std::vector<RefAtom> atoms;
  std::vector<double> charges; // e
};

const ReferenceCase waterCase = { "Water",
                                  0,
                                  {
                                    { 8, 0.897950, 0.055590, 0.038200 },
                                    { 1, 1.865830, 0.014660, 0.016240 },
                                    { 1, 0.619120, -0.762190, -0.400470 },
                                  },
                                  {
                                    -0.585939667410,
                                    0.292969223031,
                                    0.292970444379,
                                  } };

const ReferenceCase glyzCase = { "GlycineZwitterion",
                                 0,
                                 {
                                   { 7, 1.018590, -0.060440, 0.048500 },
                                   { 6, 2.527110, -0.062220, 0.091600 },
                                   { 6, 3.025310, -0.123130, 1.553360 },
                                   { 8, 2.041430, -0.158100, 2.357700 },
                                   { 8, 4.262760, -0.128590, 1.724030 },
                                   { 1, 0.589200, -0.022260, -0.872380 },
                                   { 1, 0.726940, 0.711550, 0.665900 },
                                   { 1, 0.727120, -0.881010, 0.599840 },
                                   { 1, 2.855870, 0.858090, -0.397710 },
                                   { 1, 2.855860, -0.938720, -0.472450 },
                                 },
                                 {
                                   -0.732261069326,
                                   0.007024978352,
                                   0.328887383476,
                                   -0.357840455573,
                                   -0.345962962655,
                                   0.267304248106,
                                   0.283824839158,
                                   0.283863384953,
                                   0.132587353140,
                                   0.132572300368,
                                 } };

const ReferenceCase acetateCase = { "Acetate",
                                    -1,
                                    {
                                      { 6, 1.098100, -0.040130, -0.067630 },
                                      { 6, 2.616840, -0.029450, -0.057010 },
                                      { 8, 3.167230, -0.835100, -0.857790 },
                                      { 8, 3.135010, 0.787470, 0.754970 },
                                      { 1, 0.709440, -0.765620, -0.788730 },
                                      { 1, 0.722410, 0.951280, -0.337740 },
                                      { 1, 0.722410, -0.304230, 0.925400 },
                                    },
                                    {
                                      -0.250715048360,
                                      0.257151775328,
                                      -0.559706421330,
                                      -0.558884333151,
                                      0.040368569364,
                                      0.035892824148,
                                      0.035892634000,
                                    } };

const ReferenceCase ferroceneCase = {
  "Ferrocene",
  0,
  {
    { 26, 0.000000, 0.000000, 0.000000 },
    { 6, 1.190000, 0.000000, 1.650000 },
    { 6, 0.367730, 1.131757, 1.650000 },
    { 6, -0.962730, 0.699464, 1.650000 },
    { 6, -0.962730, -0.699464, 1.650000 },
    { 6, 0.367730, -1.131757, 1.650000 },
    { 1, 2.270000, 0.000000, 1.700000 },
    { 1, 0.701469, 2.158898, 1.700000 },
    { 1, -1.836469, 1.334273, 1.700000 },
    { 1, -1.836469, -1.334273, 1.700000 },
    { 1, 0.701469, -2.158898, 1.700000 },
    { 6, 1.190000, 0.000000, -1.650000 },
    { 6, 0.367730, 1.131757, -1.650000 },
    { 6, -0.962730, 0.699464, -1.650000 },
    { 6, -0.962730, -0.699464, -1.650000 },
    { 6, 0.367730, -1.131757, -1.650000 },
    { 1, 2.270000, 0.000000, -1.700000 },
    { 1, 0.701469, 2.158898, -1.700000 },
    { 1, -1.836469, 1.334273, -1.700000 },
    { 1, -1.836469, -1.334273, -1.700000 },
    { 1, 0.701469, -2.158898, -1.700000 },
  },
  {
    0.383088711355,  -0.130151375917, -0.130151307821, -0.130151232860,
    -0.130151232860, -0.130151307821, 0.091842450255,  0.091842437448,
    0.091842388225,  0.091842388225,  0.091842437448,  -0.130151375917,
    -0.130151307821, -0.130151232860, -0.130151232860, -0.130151307821,
    0.091842450255,  0.091842437448,  0.091842388225,  0.091842388225,
    0.091842437448,
  }
};

const ReferenceCase uo2f4Case = { "UranylFluoride",
                                  -2,
                                  {
                                    { 92, 0.000000, 0.000000, 0.000000 },
                                    { 8, 0.000000, 0.000000, 1.780000 },
                                    { 8, 0.000000, 0.000000, -1.780000 },
                                    { 9, 2.260000, 0.000000, 0.000000 },
                                    { 9, 0.000000, 2.260000, 0.000000 },
                                    { 9, -2.260000, 0.000000, 0.000000 },
                                    { 9, -0.000000, -2.260000, 0.000000 },
                                  },
                                  {
                                    0.914106457540,
                                    -0.630035889761,
                                    -0.630035889761,
                                    -0.413508669504,
                                    -0.413508669504,
                                    -0.413508669504,
                                    -0.413508669504,
                                  } };

const ReferenceCase cu13Case = { "Cu13CoordinationCap",
                                 0,
                                 {
                                   { 29, 0.000000, 0.000000, 0.000000 },
                                   { 29, -1.803122, -1.803122, 0.000000 },
                                   { 29, -1.803122, 0.000000, -1.803122 },
                                   { 29, 0.000000, -1.803122, -1.803122 },
                                   { 29, -1.803122, 1.803122, 0.000000 },
                                   { 29, -1.803122, 0.000000, 1.803122 },
                                   { 29, 0.000000, -1.803122, 1.803122 },
                                   { 29, 1.803122, -1.803122, 0.000000 },
                                   { 29, 1.803122, 0.000000, -1.803122 },
                                   { 29, 0.000000, 1.803122, -1.803122 },
                                   { 29, 1.803122, 1.803122, 0.000000 },
                                   { 29, 1.803122, 0.000000, 1.803122 },
                                   { 29, 0.000000, 1.803122, 1.803122 },
                                 },
                                 {
                                   -0.133132037893,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                   0.011094336491,
                                 } };

Molecule buildMolecule(const ReferenceCase& c)
{
  Molecule mol;
  for (const auto& a : c.atoms) {
    auto atom = mol.addAtom(a.atomicNumber);
    atom.setPosition3d(Vector3(a.x, a.y, a.z));
  }
  mol.setData("totalCharge", c.totalCharge);
  return mol;
}

} // namespace

TEST(EEQModelTest, Identity)
{
  EEQModel model;
  EXPECT_EQ(model.identifier(), "eeq");
  EXPECT_FALSE(model.name().empty());
  const auto mask = model.elements();
  EXPECT_FALSE(mask.test(0));
  EXPECT_TRUE(mask.test(1));
  EXPECT_TRUE(mask.test(103));
  EXPECT_FALSE(mask.test(104));
  EXPECT_EQ(mask.count(), 103u);
  std::unique_ptr<ChargeModel> copy(model.newInstance());
  EXPECT_EQ(copy->identifier(), "eeq");
}

TEST(EEQModelTest, MatchesMulticharge)
{
  const ReferenceCase* cases[] = { &waterCase,     &glyzCase,  &acetateCase,
                                   &ferroceneCase, &uo2f4Case, &cu13Case };
  EEQModel model;
  for (const ReferenceCase* c : cases) {
    Molecule mol = buildMolecule(*c);
    const MatrixX charges = model.partialCharges(mol);
    ASSERT_EQ(charges.rows(), static_cast<Eigen::Index>(c->charges.size()))
      << c->name;
    ASSERT_EQ(charges.cols(), 1) << c->name;
    double maxDiff = 0.0;
    for (std::size_t i = 0; i < c->charges.size(); ++i)
      maxDiff =
        std::max(maxDiff, std::abs(charges(static_cast<Eigen::Index>(i), 0) -
                                   c->charges[i]));
    EXPECT_LT(maxDiff, 1.0e-6) << c->name;
    EXPECT_NEAR(charges.sum(), c->totalCharge, 1.0e-9) << c->name;
  }
}

TEST(EEQModelTest, ConstAndNonConstOverloadsAgree)
{
  EEQModel model;
  Molecule mol = buildMolecule(waterCase);
  const Molecule& constMol = mol;
  const MatrixX a = model.partialCharges(mol);
  const MatrixX b = model.partialCharges(constMol);
  EXPECT_EQ(a, b);
}

TEST(EEQModelTest, EmptyMolecule)
{
  EEQModel model;
  Molecule mol;
  const MatrixX charges = model.partialCharges(mol);
  EXPECT_EQ(charges.rows(), 0);
}

TEST(EEQModelTest, SingleAtomTakesTotalCharge)
{
  EEQModel model;
  Molecule mol;
  mol.addAtom(26).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.setData("totalCharge", 2);
  MatrixX charges = model.partialCharges(mol);
  ASSERT_EQ(charges.rows(), 1);
  EXPECT_NEAR(charges(0, 0), 2.0, 1.0e-12);

  mol.setData("totalCharge", 0);
  charges = model.partialCharges(mol);
  EXPECT_NEAR(charges(0, 0), 0.0, 1.0e-12);
}

TEST(EEQModelTest, UnsupportedElementFailsCleanly)
{
  EEQModel model;
  for (unsigned char z :
       { static_cast<unsigned char>(0), static_cast<unsigned char>(104),
         static_cast<unsigned char>(118) }) {
    Molecule mol;
    mol.addAtom(8).setPosition3d(Vector3(0.0, 0.0, 0.0));
    mol.addAtom(z).setPosition3d(Vector3(1.5, 0.0, 0.0));
    // a failure has fewer rows than atoms, so it is never taken as charges
    const MatrixX charges = model.partialCharges(mol);
    EXPECT_EQ(charges.rows(), 0) << static_cast<int>(z);
  }
}

TEST(EEQModelTest, TooManyAtomsRejected)
{
  EEQModel model;
  Molecule mol;
  // Positions are left at the origin; the size check comes first.
  for (std::size_t i = 0; i <= EEQModel::maxAtoms(); ++i)
    mol.addAtom(1);
  const MatrixX charges = model.partialCharges(mol);
  EXPECT_EQ(charges.rows(), 0);
}

TEST(EEQModelTest, CoincidentAtomsAreFinite)
{
  EEQModel model;
  Molecule mol;
  mol.addAtom(8).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(1).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(1).setPosition3d(Vector3(0.96, 0.0, 0.0));
  const MatrixX charges = model.partialCharges(mol);
  ASSERT_EQ(charges.rows(), 3);
  EXPECT_TRUE(charges.allFinite());
  EXPECT_NEAR(charges.sum(), 0.0, 1.0e-9);

  // All atoms on one point
  Molecule pile;
  for (int i = 0; i < 4; ++i)
    pile.addAtom(6).setPosition3d(Vector3(1.0, 1.0, 1.0));
  const MatrixX pileCharges = model.partialCharges(pile);
  EXPECT_TRUE(pileCharges.allFinite());
}

TEST(EEQModelTest, RegisteredWithChargeManager)
{
  auto& manager = ChargeManager::instance();
  EXPECT_EQ(manager.nameForModel("eeq"), EEQModel().name());

  Molecule mol = buildMolecule(waterCase);
  const auto ids = manager.identifiersForMolecule(mol);
  EXPECT_TRUE(ids.find("eeq") != ids.end());

  const MatrixX viaManager = manager.partialCharges("eeq", mol);
  const MatrixX direct = EEQModel().partialCharges(mol);
  ASSERT_EQ(viaManager.rows(), 3);
  EXPECT_NEAR((viaManager - direct).norm(), 0.0, 1.0e-12);
}
