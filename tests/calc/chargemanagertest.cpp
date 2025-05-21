/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>
#include <avogadro/core/molecule.h>

using Avogadro::Calc::ChargeManager;
using Avogadro::Calc::ChargeModel;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Molecule;

class ChargeManagerTest : public testing::Test
{
protected:
  Molecule m_testMolecule;
  ChargeManager m_chargeManager;

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
  }
};

// Test: Register and retrieve a charge model
TEST_F(ChargeManagerTest, RegisterAndRetrieveModel)
{
  class MockChargeModel : public ChargeModel
  {
  public:
    std::string identifier() const override { return "MockModel"; }
    bool computeCharges(Molecule& molecule) override { return true; }
  };

  MockChargeModel mockModel;
  m_chargeManager.registerModel(&mockModel);

  EXPECT_EQ(m_chargeManager.model("MockModel"), &mockModel);
}

// Test: Unregister a charge model
TEST_F(ChargeManagerTest, UnregisterModel)
{
  class MockChargeModel : public ChargeModel
  {
  public:
    std::string identifier() const override { return "MockModel"; }
    bool computeCharges(Molecule& molecule) override { return true; }
  };

  MockChargeModel mockModel;
  m_chargeManager.registerModel(&mockModel);

  EXPECT_TRUE(m_chargeManager.unregisterModel("MockModel"));
  EXPECT_EQ(m_chargeManager.model("MockModel"), nullptr);
}

// Test: Get identifiers for available charge models
TEST_F(ChargeManagerTest, GetIdentifiers)
{
  class MockChargeModel : public ChargeModel
  {
  public:
    std::string identifier() const override { return "MockModel"; }
    bool computeCharges(Molecule& molecule) override { return true; }
  };

  MockChargeModel mockModel;
  m_chargeManager.registerModel(&mockModel);

  auto identifiers = m_chargeManager.identifiers();
  EXPECT_NE(identifiers.find("MockModel"), identifiers.end());
}

// Test: Assign charges using a valid charge model
TEST_F(ChargeManagerTest, AssignChargesValidModel)
{
  // Mock or use a simple charge model
  class MockChargeModel : public ChargeModel
  {
  public:
    bool computeCharges(Molecule& molecule) override
    {
      for (Index i = 0; i < molecule.atomCount(); ++i) {
        molecule.setPartialCharge(
          i, static_cast<double>(i)); // Assign mock charges
      }
      return true;
    }
  };

  MockChargeModel mockModel;
  m_chargeManager.setModel(&mockModel);

  EXPECT_TRUE(m_chargeManager.computeCharges(m_testMolecule));

  // Verify charges are assigned
  for (Index i = 0; i < m_testMolecule.atomCount(); ++i) {
    EXPECT_DOUBLE_EQ(m_testMolecule.partialCharge(i), static_cast<double>(i));
  }
}

// Test: Handle null charge model
TEST_F(ChargeManagerTest, NullChargeModel)
{
  m_chargeManager.setModel(nullptr);
  EXPECT_FALSE(m_chargeManager.computeCharges(m_testMolecule));
}

// Test: Handle empty molecule
TEST_F(ChargeManagerTest, EmptyMolecule)
{
  Molecule emptyMolecule;
  class MockChargeModel : public ChargeModel
  {
  public:
    bool computeCharges(Molecule& molecule) override
    {
      return molecule.atomCount() > 0;
    }
  };

  MockChargeModel mockModel;
  m_chargeManager.setModel(&mockModel);

  EXPECT_FALSE(m_chargeManager.computeCharges(emptyMolecule));
}

// Test: Edge case with a single atom
TEST_F(ChargeManagerTest, SingleAtomMolecule)
{
  Molecule singleAtomMolecule;
  auto atom = singleAtomMolecule.addAtom(1); // Hydrogen
  atom.setPosition3d(Vector3(0, 0, 0));

  class MockChargeModel : public ChargeModel
  {
  public:
    bool computeCharges(Molecule& molecule) override
    {
      if (molecule.atomCount() == 1) {
        molecule.setPartialCharge(0, 0.5); // Assign a mock charge
        return true;
      }
      return false;
    }
  };

  MockChargeModel mockModel;
  m_chargeManager.setModel(&mockModel);

  EXPECT_TRUE(m_chargeManager.computeCharges(singleAtomMolecule));
  EXPECT_DOUBLE_EQ(singleAtomMolecule.partialCharge(0), 0.5);
}
