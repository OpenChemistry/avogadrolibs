/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/energymanager.h>
#include <avogadro/core/molecule.h>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;

using Avogadro::Real;

// Mock EnergyCalculator for testing EnergyManager
class MockEnergyCalculator : public EnergyCalculator
{
public:
  MockEnergyCalculator(const std::string& id, const std::string& modelName,
                       bool unitCell = false, bool ions = false,
                       bool radicals = false)
    : m_identifier(id), m_name(modelName), m_acceptsUnitCell(unitCell),
      m_acceptsIons(ions), m_acceptsRadicals(radicals)
  {
  }

  EnergyCalculator* newInstance() const override
  {
    return new MockEnergyCalculator(m_identifier, m_name, m_acceptsUnitCell,
                                    m_acceptsIons, m_acceptsRadicals);
  }

  std::string identifier() const override { return m_identifier; }
  std::string name() const override { return m_name; }
  std::string description() const override
  {
    return "Mock calculator for testing";
  }

  Molecule::ElementMask elements() const override
  {
    Molecule::ElementMask mask;
    mask.set();
    return mask;
  }

  Real value(const Eigen::VectorXd& x) override { return x.squaredNorm(); }
  void setMolecule(Molecule* mol) override { m_molecule = mol; }

  bool acceptsUnitCell() const override { return m_acceptsUnitCell; }
  bool acceptsIons() const override { return m_acceptsIons; }
  bool acceptsRadicals() const override { return m_acceptsRadicals; }

private:
  std::string m_identifier;
  std::string m_name;
  bool m_acceptsUnitCell;
  bool m_acceptsIons;
  bool m_acceptsRadicals;
  Molecule* m_molecule = nullptr;
};

// Test fixture for EnergyManager
class EnergyManagerTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // Get singleton instance
    manager = &EnergyManager::instance();
  }

  void TearDown() override
  {
    // Clean up any registered models
    auto ids = manager->identifiers();
    for (const auto& id : ids) {
      manager->removeModel(id);
    }
  }

  EnergyManager* manager;
};

// EnergyManager Tests

TEST_F(EnergyManagerTest, SingletonInstance)
{
  EnergyManager& instance1 = EnergyManager::instance();
  EnergyManager& instance2 = EnergyManager::instance();
  EXPECT_EQ(&instance1, &instance2);
}

TEST_F(EnergyManagerTest, RegisterAndUnregisterModel)
{
  auto* model = new MockEnergyCalculator("test_model", "Test Model");
  EXPECT_TRUE(EnergyManager::registerModel(model));

  auto ids = manager->identifiers();
  EXPECT_TRUE(ids.find("test_model") != ids.end());

  EXPECT_TRUE(EnergyManager::unregisterModel("test_model"));
  ids = manager->identifiers();
  EXPECT_TRUE(ids.find("test_model") == ids.end());
}

TEST_F(EnergyManagerTest, AddAndRemoveModel)
{
  auto* model = new MockEnergyCalculator("add_test", "Add Test");
  EXPECT_TRUE(manager->addModel(model));

  auto ids = manager->identifiers();
  EXPECT_TRUE(ids.find("add_test") != ids.end());

  EXPECT_TRUE(manager->removeModel("add_test"));
  ids = manager->identifiers();
  EXPECT_TRUE(ids.find("add_test") == ids.end());
}

TEST_F(EnergyManagerTest, RetrieveModel)
{
  auto* model = new MockEnergyCalculator("retrieve_test", "Retrieve Test");
  manager->addModel(model);

  EnergyCalculator* retrieved = manager->model("retrieve_test");
  ASSERT_NE(retrieved, nullptr);
  EXPECT_EQ(retrieved->identifier(), "retrieve_test");

  delete retrieved;
  manager->removeModel("retrieve_test");
}

TEST_F(EnergyManagerTest, RetrieveNonExistentModel)
{
  EnergyCalculator* retrieved = manager->model("nonexistent");
  EXPECT_EQ(retrieved, nullptr);
}

TEST_F(EnergyManagerTest, GetNameForModel)
{
  auto* model = new MockEnergyCalculator("name_test", "Name Test Model");
  manager->addModel(model);

  std::string name = manager->nameForModel("name_test");
  EXPECT_EQ(name, "Name Test Model");

  manager->removeModel("name_test");
}

TEST_F(EnergyManagerTest, GetNameForNonExistentModel)
{
  std::string name = manager->nameForModel("nonexistent");
  EXPECT_EQ(name, "nonexistent");
}

TEST_F(EnergyManagerTest, GetIdentifiers)
{
  auto* model1 = new MockEnergyCalculator("id1", "Model 1");
  auto* model2 = new MockEnergyCalculator("id2", "Model 2");
  auto* model3 = new MockEnergyCalculator("id3", "Model 3");

  manager->addModel(model1);
  manager->addModel(model2);
  manager->addModel(model3);

  auto ids = manager->identifiers();
  EXPECT_GE(ids.size(), 3);
  EXPECT_TRUE(ids.find("id1") != ids.end());
  EXPECT_TRUE(ids.find("id2") != ids.end());
  EXPECT_TRUE(ids.find("id3") != ids.end());

  manager->removeModel("id1");
  manager->removeModel("id2");
  manager->removeModel("id3");
}

TEST_F(EnergyManagerTest, IdentifiersForMolecule)
{
  auto* model1 = new MockEnergyCalculator("model1", "Model 1");
  auto* model2 = new MockEnergyCalculator("model2", "Model 2");

  manager->addModel(model1);
  manager->addModel(model2);

  Molecule mol;
  auto ids = manager->identifiersForMolecule(mol);

  EXPECT_GE(ids.size(), 2);
  EXPECT_TRUE(ids.find("model1") != ids.end());
  EXPECT_TRUE(ids.find("model2") != ids.end());

  manager->removeModel("model1");
  manager->removeModel("model2");
}

TEST_F(EnergyManagerTest, IdentifiersForMoleculeWithUnitCell)
{
  auto* model1 =
    new MockEnergyCalculator("no_cell", "No Cell", false, false, false);
  auto* model2 =
    new MockEnergyCalculator("with_cell", "With Cell", true, false, false);

  manager->addModel(model1);
  manager->addModel(model2);

  Molecule mol;
  // TODO: Set unit cell on molecule when that functionality is available

  auto ids = manager->identifiersForMolecule(mol);
  EXPECT_GE(ids.size(), 1);

  manager->removeModel("no_cell");
  manager->removeModel("with_cell");
}

TEST_F(EnergyManagerTest, RecommendedModel)
{
  auto* model = new MockEnergyCalculator("recommended", "Recommended Model");
  manager->addModel(model);

  Molecule mol;
  std::string recommended = manager->recommendedModel(mol);

  // Should return a valid model
  EXPECT_FALSE(recommended.empty());

  manager->removeModel("recommended");
}

TEST_F(EnergyManagerTest, PreventDuplicateRegistration)
{
  auto* model1 = new MockEnergyCalculator("duplicate", "Duplicate 1");
  auto* model2 = new MockEnergyCalculator("duplicate", "Duplicate 2");

  EXPECT_TRUE(manager->addModel(model1));
  EXPECT_FALSE(manager->addModel(model2));

  // Second model should be rejected, so we need to clean it up
  delete model2;

  auto ids = manager->identifiers();
  EXPECT_TRUE(ids.find("duplicate") != ids.end());

  // Verify only one model with this ID exists
  EnergyCalculator* retrieved = manager->model("duplicate");
  EXPECT_EQ(retrieved->name(), "Duplicate 1");
  delete retrieved;

  manager->removeModel("duplicate");
}

TEST_F(EnergyManagerTest, MultipleModelsLifecycle)
{
  // Add multiple models
  auto* model1 = new MockEnergyCalculator("multi1", "Multi 1");
  auto* model2 = new MockEnergyCalculator("multi2", "Multi 2");
  auto* model3 = new MockEnergyCalculator("multi3", "Multi 3");

  EXPECT_TRUE(manager->addModel(model1));
  EXPECT_TRUE(manager->addModel(model2));
  EXPECT_TRUE(manager->addModel(model3));

  auto ids = manager->identifiers();
  EXPECT_GE(ids.size(), 3);

  // Remove one model
  EXPECT_TRUE(manager->removeModel("multi2"));
  ids = manager->identifiers();
  EXPECT_TRUE(ids.find("multi2") == ids.end());
  EXPECT_TRUE(ids.find("multi1") != ids.end());
  EXPECT_TRUE(ids.find("multi3") != ids.end());

  // Clean up remaining models
  manager->removeModel("multi1");
  manager->removeModel("multi3");
}

TEST_F(EnergyManagerTest, ErrorHandling)
{
  // Initially no errors
  std::string error = manager->error();
  // Error string may or may not be empty initially, just verify it's accessible
  EXPECT_NO_THROW(manager->error());
}

// Integration test
TEST_F(EnergyManagerTest, CompleteWorkflow)
{
  // Register a model
  auto* model = new MockEnergyCalculator("workflow", "Workflow Test");
  ASSERT_TRUE(manager->addModel(model));

  // Verify it's in the identifiers list
  auto ids = manager->identifiers();
  EXPECT_TRUE(ids.find("workflow") != ids.end());

  // Get the name
  std::string name = manager->nameForModel("workflow");
  EXPECT_EQ(name, "Workflow Test");

  // Retrieve and use the model
  EnergyCalculator* retrieved = manager->model("workflow");
  ASSERT_NE(retrieved, nullptr);
  EXPECT_EQ(retrieved->identifier(), "workflow");

  Eigen::VectorXd x(2);
  x << 1.0, 1.0;
  Real energy = retrieved->value(x);
  EXPECT_GT(energy, 0.0);

  delete retrieved;

  // Remove the model
  EXPECT_TRUE(manager->removeModel("workflow"));
  ids = manager->identifiers();
  EXPECT_TRUE(ids.find("workflow") == ids.end());
}
