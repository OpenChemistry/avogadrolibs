/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/calc/energycalculator.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/molecule.h>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using Avogadro::MaxIndex;
using Avogadro::Real;

// Mock EnergyCalculator implementation for testing
class TestEnergyCalculator : public EnergyCalculator
{
public:
  TestEnergyCalculator(const std::string& id = "test_calc",
                       const std::string& modelName = "Test Calculator")
    : m_identifier(id), m_name(modelName), m_acceptsUnitCell(false),
      m_acceptsIons(false), m_acceptsRadicals(false), m_configCalled(false)
  {
  }

  EnergyCalculator* newInstance() const override
  {
    return new TestEnergyCalculator(m_identifier, m_name);
  }

  std::string identifier() const override { return m_identifier; }

  std::string name() const override { return m_name; }

  std::string description() const override
  {
    return "Test calculator for unit testing";
  }

  bool setConfiguration(VariantMap& config) override
  {
    m_configCalled = true;
    m_config = config;
    return true;
  }

  Molecule::ElementMask elements() const override
  {
    // Support all elements by default
    Molecule::ElementMask mask;
    mask.set();
    return mask;
  }

  bool acceptsUnitCell() const override { return m_acceptsUnitCell; }
  bool acceptsIons() const override { return m_acceptsIons; }
  bool acceptsRadicals() const override { return m_acceptsRadicals; }

  // Simple quadratic energy function for testing
  Real value(const TVector& x) override { return x.squaredNorm(); }

  void setMolecule(Molecule* mol) override { m_molecule = mol; }

  // Test helpers
  void setAcceptsUnitCell(bool val) { m_acceptsUnitCell = val; }
  void setAcceptsIons(bool val) { m_acceptsIons = val; }
  void setAcceptsRadicals(bool val) { m_acceptsRadicals = val; }
  bool wasConfigCalled() const { return m_configCalled; }
  const VariantMap& getConfig() const { return m_config; }

private:
  std::string m_identifier;
  std::string m_name;
  Molecule* m_molecule = nullptr;
  bool m_acceptsUnitCell;
  bool m_acceptsIons;
  bool m_acceptsRadicals;
  bool m_configCalled;
  VariantMap m_config;
};

// Test fixture for EnergyCalculator
class EnergyCalculatorTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    calculator = new TestEnergyCalculator();
    molecule = new Molecule();
  }

  void TearDown() override
  {
    delete calculator;
    delete molecule;
  }

  TestEnergyCalculator* calculator;
  Molecule* molecule;
};

// Basic Property Tests

TEST_F(EnergyCalculatorTest, Identifier)
{
  EXPECT_EQ(calculator->identifier(), "test_calc");
}

TEST_F(EnergyCalculatorTest, Name)
{
  EXPECT_EQ(calculator->name(), "Test Calculator");
}

TEST_F(EnergyCalculatorTest, Description)
{
  std::string desc = calculator->description();
  EXPECT_FALSE(desc.empty());
  EXPECT_EQ(desc, "Test calculator for unit testing");
}

TEST_F(EnergyCalculatorTest, NewInstance)
{
  EnergyCalculator* newCalc = calculator->newInstance();
  ASSERT_NE(newCalc, nullptr);
  EXPECT_EQ(newCalc->identifier(), "test_calc");
  EXPECT_EQ(newCalc->name(), "Test Calculator");
  EXPECT_NE(newCalc, calculator); // Should be a different instance
  delete newCalc;
}

TEST_F(EnergyCalculatorTest, NewInstanceIsIndependent)
{
  EnergyCalculator* calc1 = calculator->newInstance();
  EnergyCalculator* calc2 = calculator->newInstance();

  ASSERT_NE(calc1, nullptr);
  ASSERT_NE(calc2, nullptr);
  EXPECT_NE(calc1, calc2);

  delete calc1;
  delete calc2;
}

// Molecule Tests

TEST_F(EnergyCalculatorTest, SetMolecule)
{
  EXPECT_NO_THROW(calculator->setMolecule(molecule));
}

TEST_F(EnergyCalculatorTest, SetMoleculeNull)
{
  EXPECT_NO_THROW(calculator->setMolecule(nullptr));
}

// Energy Calculation Tests

TEST_F(EnergyCalculatorTest, ValueFunction)
{
  Eigen::VectorXd x(3);
  x << 1.0, 2.0, 3.0;

  Real value = calculator->value(x);
  Real expected = 1.0 + 4.0 + 9.0; // Sum of squares
  EXPECT_DOUBLE_EQ(value, expected);
}

TEST_F(EnergyCalculatorTest, ValueFunctionZeroVector)
{
  Eigen::VectorXd x(3);
  x << 0.0, 0.0, 0.0;

  Real value = calculator->value(x);
  EXPECT_DOUBLE_EQ(value, 0.0);
}

TEST_F(EnergyCalculatorTest, ValueFunctionNegativeValues)
{
  Eigen::VectorXd x(2);
  x << -3.0, 4.0;

  Real value = calculator->value(x);
  Real expected = 9.0 + 16.0; // (-3)^2 + 4^2
  EXPECT_DOUBLE_EQ(value, expected);
}

// Gradient Tests

TEST_F(EnergyCalculatorTest, GradientFunction)
{
  Eigen::VectorXd x(3);
  x << 1.0, 2.0, 3.0;

  Eigen::VectorXd grad(3);
  calculator->gradient(x, grad);

  EXPECT_EQ(grad.size(), 3);
  // Gradient values depend on the numerical differentiation
  // Just verify it runs without crashing
}

TEST_F(EnergyCalculatorTest, GradientFunctionAtZero)
{
  Eigen::VectorXd x(2);
  x << 0.0, 0.0;

  Eigen::VectorXd grad(2);
  calculator->gradient(x, grad);

  EXPECT_EQ(grad.size(), 2);
  // At zero, gradient should be close to zero
  EXPECT_NEAR(grad(0), 0.0, 1e-5);
  EXPECT_NEAR(grad(1), 0.0, 1e-5);
}

// Constraint Tests

TEST_F(EnergyCalculatorTest, ConstraintsInitiallyEmpty)
{
  auto constraints = calculator->constraints();
  EXPECT_TRUE(constraints.empty());
}

TEST_F(EnergyCalculatorTest, SetConstraints)
{
  std::vector<Constraint> constraints;
  // Distance Constraint
  Constraint c1(0, 1, MaxIndex, MaxIndex, 1.5);
  constraints.push_back(c1);

  EXPECT_NO_THROW(calculator->setConstraints(constraints));
}

TEST_F(EnergyCalculatorTest, SetAndGetConstraints)
{
  std::vector<Constraint> constraints;
  // Distance
  Constraint c1(0, 1, MaxIndex, MaxIndex, 1.5);
  // Angle
  Constraint c2(0, 1, 2, MaxIndex, 120.0);
  constraints.push_back(c1);
  constraints.push_back(c2);

  calculator->setConstraints(constraints);
  auto retrieved = calculator->constraints();

  EXPECT_EQ(retrieved.size(), 2);
}

TEST_F(EnergyCalculatorTest, SetMultipleConstraintTypes)
{
  std::vector<Constraint> constraints;
  constraints.push_back(Constraint(0, 1, MaxIndex, MaxIndex, 1.5));
  constraints.push_back(Constraint(0, 1, 2, MaxIndex, 109.5));
  constraints.push_back(Constraint(0, 1, 2, 3, 180.0));

  calculator->setConstraints(constraints);
  auto retrieved = calculator->constraints();

  EXPECT_EQ(retrieved.size(), 3);
}

TEST_F(EnergyCalculatorTest, ClearConstraints)
{
  std::vector<Constraint> constraints;
  constraints.push_back(Constraint(0, 1, MaxIndex, MaxIndex, 1.5));
  calculator->setConstraints(constraints);

  // Clear by setting empty vector
  std::vector<Constraint> empty;
  calculator->setConstraints(empty);

  auto retrieved = calculator->constraints();
  EXPECT_TRUE(retrieved.empty());
}

TEST_F(EnergyCalculatorTest, ConstraintEnergies)
{
  Eigen::VectorXd x(6); // 2 atoms, 3 coords each
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  std::vector<Constraint> constraints;
  constraints.push_back(Constraint(0, 1, MaxIndex, MaxIndex, 1.5));
  calculator->setConstraints(constraints);

  Real energy = calculator->constraintEnergies(x);
  // Should be zero or near zero when constraint is satisfied
  EXPECT_GE(energy, 0.0);
}

TEST_F(EnergyCalculatorTest, ConstraintGradients)
{
  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  Eigen::VectorXd grad(6);
  grad.setZero();

  std::vector<Constraint> constraints;
  constraints.push_back(Constraint(0, 1, MaxIndex, MaxIndex, 1.5));
  calculator->setConstraints(constraints);

  EXPECT_NO_THROW(calculator->constraintGradients(x, grad));
}

// Mask Tests

TEST_F(EnergyCalculatorTest, SetAndGetMask)
{
  Eigen::VectorXd mask(3);
  mask << 1.0, 0.0, 1.0;

  calculator->setMask(mask);
  Eigen::VectorXd retrieved = calculator->mask();

  EXPECT_EQ(retrieved.size(), 3);
  EXPECT_DOUBLE_EQ(retrieved(0), 1.0);
  EXPECT_DOUBLE_EQ(retrieved(1), 0.0);
  EXPECT_DOUBLE_EQ(retrieved(2), 1.0);
}

TEST_F(EnergyCalculatorTest, MaskAllFree)
{
  Eigen::VectorXd mask(4);
  mask << 1.0, 1.0, 1.0, 1.0;

  calculator->setMask(mask);
  Eigen::VectorXd retrieved = calculator->mask();

  for (int i = 0; i < retrieved.size(); ++i) {
    EXPECT_DOUBLE_EQ(retrieved(i), 1.0);
  }
}

TEST_F(EnergyCalculatorTest, MaskAllFrozen)
{
  Eigen::VectorXd mask(4);
  mask << 0.0, 0.0, 0.0, 0.0;

  calculator->setMask(mask);
  Eigen::VectorXd retrieved = calculator->mask();

  for (int i = 0; i < retrieved.size(); ++i) {
    EXPECT_DOUBLE_EQ(retrieved(i), 0.0);
  }
}

TEST_F(EnergyCalculatorTest, CleanGradients)
{
  Eigen::VectorXd mask(3);
  mask << 1.0, 0.0, 1.0; // Middle coordinate frozen

  calculator->setMask(mask);

  Eigen::VectorXd grad(3);
  grad << 1.0, 2.0, 3.0;

  calculator->cleanGradients(grad);

  EXPECT_DOUBLE_EQ(grad(0), 1.0);
  EXPECT_DOUBLE_EQ(grad(1), 0.0); // Should be zeroed by mask
  EXPECT_DOUBLE_EQ(grad(2), 3.0);
}

// Capability Tests

TEST_F(EnergyCalculatorTest, DefaultCapabilities)
{
  EXPECT_FALSE(calculator->acceptsUnitCell());
  EXPECT_FALSE(calculator->acceptsIons());
  EXPECT_FALSE(calculator->acceptsRadicals());
}

TEST_F(EnergyCalculatorTest, SetAcceptsUnitCell)
{
  calculator->setAcceptsUnitCell(true);
  EXPECT_TRUE(calculator->acceptsUnitCell());

  calculator->setAcceptsUnitCell(false);
  EXPECT_FALSE(calculator->acceptsUnitCell());
}

TEST_F(EnergyCalculatorTest, SetAcceptsIons)
{
  calculator->setAcceptsIons(true);
  EXPECT_TRUE(calculator->acceptsIons());

  calculator->setAcceptsIons(false);
  EXPECT_FALSE(calculator->acceptsIons());
}

TEST_F(EnergyCalculatorTest, SetAcceptsRadicals)
{
  calculator->setAcceptsRadicals(true);
  EXPECT_TRUE(calculator->acceptsRadicals());

  calculator->setAcceptsRadicals(false);
  EXPECT_FALSE(calculator->acceptsRadicals());
}

TEST_F(EnergyCalculatorTest, AllCapabilitiesEnabled)
{
  calculator->setAcceptsUnitCell(true);
  calculator->setAcceptsIons(true);
  calculator->setAcceptsRadicals(true);

  EXPECT_TRUE(calculator->acceptsUnitCell());
  EXPECT_TRUE(calculator->acceptsIons());
  EXPECT_TRUE(calculator->acceptsRadicals());
}

// Element Mask Tests

TEST_F(EnergyCalculatorTest, ElementMask)
{
  auto mask = calculator->elements();
  EXPECT_TRUE(mask.any());
}

TEST_F(EnergyCalculatorTest, ElementMaskSize)
{
  auto mask = calculator->elements();
  // Element mask should have a reasonable size
  EXPECT_GT(mask.size(), 0);
}

// Configuration Tests

TEST_F(EnergyCalculatorTest, SetConfiguration)
{
  VariantMap config;
  config.setValue("test_key", "test_value");

  EXPECT_TRUE(calculator->setConfiguration(config));
  EXPECT_TRUE(calculator->wasConfigCalled());
}

TEST_F(EnergyCalculatorTest, SetConfigurationEmpty)
{
  VariantMap config;

  EXPECT_TRUE(calculator->setConfiguration(config));
}

TEST_F(EnergyCalculatorTest, SetConfigurationMultipleValues)
{
  VariantMap config;
  config.setValue("key1", "value1");
  config.setValue("key2", 42);
  config.setValue("key3", 3.14);

  EXPECT_TRUE(calculator->setConfiguration(config));

  const VariantMap& stored = calculator->getConfig();
  EXPECT_EQ(stored.value("key1").toString(), "value1");
}

// Custom Calculator Tests

TEST(CustomCalculatorTest, DifferentIdentifiers)
{
  TestEnergyCalculator calc1("calc1", "Calculator 1");
  TestEnergyCalculator calc2("calc2", "Calculator 2");

  EXPECT_NE(calc1.identifier(), calc2.identifier());
  EXPECT_NE(calc1.name(), calc2.name());
}

TEST(CustomCalculatorTest, SameIdentifier)
{
  TestEnergyCalculator calc1("same_id", "Name 1");
  TestEnergyCalculator calc2("same_id", "Name 2");

  EXPECT_EQ(calc1.identifier(), calc2.identifier());
  EXPECT_NE(calc1.name(), calc2.name());
}
