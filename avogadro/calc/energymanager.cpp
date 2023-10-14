/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energymanager.h"
#include "energycalculator.h"
#include "lennardjones.h"

#include <algorithm>
#include <memory>

namespace Avogadro::Calc {

EnergyManager& EnergyManager::instance()
{
  static EnergyManager instance;
  return instance;
}

void EnergyManager::appendError(const std::string& errorMessage)
{
  m_error += errorMessage + "\n";
}

bool EnergyManager::registerModel(EnergyCalculator* model)
{
  return instance().addModel(model);
}

bool EnergyManager::unregisterModel(const std::string& identifier)
{
  return instance().removeModel(identifier);
}

bool EnergyManager::addModel(EnergyCalculator* model)
{
  if (model == nullptr) {
    appendError("Supplied model was null.");
    return false;
  }

  if (m_identifiers.find(model->identifier()) != m_identifiers.end()) {
    appendError("Model " + model->identifier() + " already loaded.");
    return false;
  }

  // If we got here then the format is unique enough to be added.
  size_t index = m_models.size();
  m_models.push_back(model);
  m_identifiers[model->identifier()] = index;
  m_identifierToName[model->identifier()] = model->name();

  return true;
}

bool EnergyManager::removeModel(const std::string& identifier)
{
  auto ids = m_identifiers[identifier];
  m_identifiers.erase(identifier);
  m_identifierToName.erase(identifier);

  auto* model = m_models[ids];

  if (model != nullptr) {
    m_models[ids] = nullptr;
    delete model;
  }

  return true;
}

std::string EnergyManager::nameForModel(const std::string& identifier) const
{
  auto it = m_identifierToName.find(identifier);
  if (it == m_identifierToName.end()) {
    return identifier;
  }
  return it->second;
}

EnergyManager::EnergyManager()
{
  // add any default models here

  // LJ is the fallback, since it can handle anything
  // (maybe not well, but it can handle it)
  addModel(new LennardJones);
}

EnergyManager::~EnergyManager()
{
  // Delete the models that were loaded.
  for (auto& m_model : m_models) {
    delete m_model;
  }
  m_models.clear();
}

std::set<std::string> EnergyManager::identifiersForMolecule(
  const Core::Molecule& molecule) const
{
  std::set<std::string> identifiers;

  // check our models for compatibility
  for (auto m_model : m_models) {
    // we can check easy things first
    // - is the molecule an ion based on total charge
    // - is the molecule a radical based on spin multiplicity
    // - does the molecule have a unit cell
    if (molecule.totalCharge() != 0 && !m_model->acceptsIons())
      continue;
    if (molecule.totalSpinMultiplicity() != 1 && !m_model->acceptsRadicals())
      continue;
    if (molecule.unitCell() != nullptr && !m_model->acceptsUnitCell())
      continue;

    // Finally, we check that every element in the molecule
    // is handled by the model
    auto mask = m_model->elements() & molecule.elements();
    if (mask.count() == molecule.elements().count())
      identifiers.insert(m_model->identifier()); // this one will work
  }

  return identifiers;
}

} // namespace Avogadro::Calc
