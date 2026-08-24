/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>
#include <avogadro/core/molecule.h>

#include <algorithm>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using Avogadro::MatrixX;
using Avogadro::Vector3;

class MismatchedChargeModel : public ChargeModel
{
public:
  ChargeModel* newInstance() const override
  {
    return new MismatchedChargeModel;
  }
  std::string identifier() const override { return "mismatched"; }
  std::string name() const override { return "Mismatched"; }
  Molecule::ElementMask elements() const override
  {
    Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Molecule& mol) const override
  {
    return MatrixX::Ones(static_cast<Eigen::Index>(mol.atomCount()) + 1, 1);
  }
  MatrixX partialCharges(const Molecule& mol) const override
  {
    return MatrixX::Ones(static_cast<Eigen::Index>(mol.atomCount()) + 1, 1);
  }
};

/// Returns fewer charge rows than the molecule has atoms.
class ShortChargeModel : public ChargeModel
{
public:
  ChargeModel* newInstance() const override { return new ShortChargeModel; }
  std::string identifier() const override { return "short"; }
  std::string name() const override { return "Short"; }
  Molecule::ElementMask elements() const override
  {
    Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Molecule& mol) const override { return charges(mol); }
  MatrixX partialCharges(const Molecule& mol) const override
  {
    return charges(mol);
  }

private:
  static MatrixX charges(const Molecule& mol)
  {
    const auto rows = static_cast<Eigen::Index>(mol.atomCount()) - 1;
    return MatrixX::Ones(std::max<Eigen::Index>(rows, 0), 1);
  }
};

/// Returns the right number of rows, but no charge column at all.
class NoColumnChargeModel : public ChargeModel
{
public:
  ChargeModel* newInstance() const override { return new NoColumnChargeModel; }
  std::string identifier() const override { return "nocolumn"; }
  std::string name() const override { return "No Column"; }
  Molecule::ElementMask elements() const override
  {
    Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Molecule& mol) const override { return charges(mol); }
  MatrixX partialCharges(const Molecule& mol) const override
  {
    return charges(mol);
  }

private:
  static MatrixX charges(const Molecule& mol)
  {
    return MatrixX(static_cast<Eigen::Index>(mol.atomCount()), 0);
  }
};

/// A well-behaved model, used to check that a failed removal is harmless.
class ConstantChargeModel : public ChargeModel
{
public:
  ChargeModel* newInstance() const override { return new ConstantChargeModel; }
  std::string identifier() const override { return "constant_test"; }
  std::string name() const override { return "Constant Test"; }
  Molecule::ElementMask elements() const override
  {
    Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Molecule& mol) const override
  {
    return MatrixX::Ones(static_cast<Eigen::Index>(mol.atomCount()), 1);
  }
  MatrixX partialCharges(const Molecule& mol) const override
  {
    return MatrixX::Ones(static_cast<Eigen::Index>(mol.atomCount()), 1);
  }
};

class ChargeManagerTest : public testing::Test
{
protected:
  Molecule m_testMolecule;
  ChargeManager* m_chargeManager;

  void SetUp() override
  {
    // Create a simple water molecule (H2O)
    auto o1 = m_testMolecule.addAtom(8); // Oxygen
    auto h2 = m_testMolecule.addAtom(1); // Hydrogen
    auto h3 = m_testMolecule.addAtom(1); // Hydrogen

    o1.setPosition3d(Vector3(0, 0, 0));
    h2.setPosition3d(Vector3(0.6, -0.5, 0));
    h3.setPosition3d(Vector3(-0.6, -0.5, 0));

    m_testMolecule.addBond(o1, h2, 1); // Single bond
    m_testMolecule.addBond(o1, h3, 1); // Single bond

    m_chargeManager = &ChargeManager::instance();
  }
};

TEST_F(ChargeManagerTest, RemovingUnknownModelFailsSafely)
{
  // Register a real model first: removeModel() used to look the identifier up
  // with operator[], which default-inserted index 0 and then deleted whichever
  // model happened to be stored there.
  ASSERT_TRUE(m_chargeManager->addModel(new ConstantChargeModel));

  EXPECT_FALSE(m_chargeManager->removeModel("not_registered"));

  // The registered model must have survived the failed removal.
  EXPECT_EQ(m_chargeManager->nameForModel("constant_test"), "Constant Test");
  const MatrixX charges =
    m_chargeManager->partialCharges("constant_test", m_testMolecule);
  EXPECT_EQ(charges.rows(), 3);
  ASSERT_EQ(charges.cols(), 1);
  EXPECT_DOUBLE_EQ(charges(0, 0), 1.0);

  EXPECT_TRUE(m_chargeManager->removeModel("constant_test"));
}

TEST_F(ChargeManagerTest, MismatchedPartialChargesAreBoundedByAtomCount)
{
  MismatchedChargeModel model;

  // Four unit charges are returned for three atoms; only the three that line
  // up with real positions may contribute.
  const Vector3 expectedDipole =
    (Vector3(0, 0, 0) + Vector3(0.6, -0.5, 0) + Vector3(-0.6, -0.5, 0)) *
    4.80320471257;
  const Vector3 dipole = model.dipoleMoment(m_testMolecule);
  EXPECT_TRUE(dipole.allFinite());
  EXPECT_NEAR(dipole.x(), expectedDipole.x(), 1e-9);
  EXPECT_NEAR(dipole.y(), expectedDipole.y(), 1e-9);
  EXPECT_NEAR(dipole.z(), expectedDipole.z(), 1e-9);

  const Vector3 probe(2.0, 0.0, 0.0);
  const double expectedPotential =
    1.0 / (Vector3(0, 0, 0) - probe).norm() +
    1.0 / (Vector3(0.6, -0.5, 0) - probe).norm() +
    1.0 / (Vector3(-0.6, -0.5, 0) - probe).norm();
  EXPECT_NEAR(model.potential(m_testMolecule, probe), expectedPotential, 1e-9);
}

TEST_F(ChargeManagerTest, TooFewPartialChargesAreBoundedByChargeCount)
{
  ShortChargeModel model;

  // Two unit charges for three atoms: only the first two atoms contribute.
  const Vector3 expectedDipole =
    (Vector3(0, 0, 0) + Vector3(0.6, -0.5, 0)) * 4.80320471257;
  const Vector3 dipole = model.dipoleMoment(m_testMolecule);
  EXPECT_NEAR(dipole.x(), expectedDipole.x(), 1e-9);
  EXPECT_NEAR(dipole.y(), expectedDipole.y(), 1e-9);
  EXPECT_NEAR(dipole.z(), expectedDipole.z(), 1e-9);

  const Vector3 probe(2.0, 0.0, 0.0);
  const double expectedPotential = 1.0 / (Vector3(0, 0, 0) - probe).norm() +
                                   1.0 / (Vector3(0.6, -0.5, 0) - probe).norm();
  EXPECT_NEAR(model.potential(m_testMolecule, probe), expectedPotential, 1e-9);
}

TEST_F(ChargeManagerTest, MissingChargeColumnYieldsZeroResults)
{
  NoColumnChargeModel model;

  // No charge column means there is nothing to read - charges(i, 0) would be
  // out of bounds, so the result must simply be zero.
  const Vector3 dipole = model.dipoleMoment(m_testMolecule);
  EXPECT_NEAR(dipole.norm(), 0.0, 1e-12);
  EXPECT_NEAR(model.potential(m_testMolecule, Vector3(2.0, 0.0, 0.0)), 0.0,
              1e-12);
}
