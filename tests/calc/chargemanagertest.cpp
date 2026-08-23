/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>
#include <avogadro/core/molecule.h>

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
  EXPECT_FALSE(m_chargeManager->removeModel("not_registered"));
}

TEST_F(ChargeManagerTest, MismatchedPartialChargesAreBoundedByAtomCount)
{
  MismatchedChargeModel model;

  EXPECT_TRUE(model.dipoleMoment(m_testMolecule).allFinite());
  EXPECT_TRUE(model.potential(m_testMolecule, Vector3(2.0, 0.0, 0.0)) > 0.0);
}
