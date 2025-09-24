/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energymanager.h"
#include "energycalculator.h"
#include "lennardjones.h"
#include "uff.h"

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

  // If we got here then the model is unique enough to be added.
  size_t index = m_models.size();
  m_models.push_back(model);
  m_identifiers[model->identifier()] = index;
  m_identifierToName[model->identifier()] = model->name();

  return true;
}

EnergyCalculator* EnergyManager::model(const std::string& identifier) const
{
  auto it = m_identifiers.find(identifier);
  if (it == m_identifiers.end()) {
    return nullptr;
  }
  return m_models[it->second]->newInstance();
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
  // UFF is good for a wide range of molecules
  addModel(new UFF);
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
  for (auto* m_model : m_models) {
    if (m_model == nullptr)
      continue;

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

std::string EnergyManager::recommendedModel(
  const Core::Molecule& molecule) const
{
  auto identifiers = identifiersForMolecule(molecule);
  if (identifiers.empty())
    return "LJ"; // shouldn't really ever happen

  // iterate to see what we have
  std::string bestOption;
  for (auto option : identifiers) {
    // GAFF is better than MMFF94 which is better than UFF
    if (option == "UFF" && bestOption != "GAFF" && bestOption != "MMFF94")
      bestOption = option;
    if (option == "MMFF94" && bestOption != "GAFF")
      bestOption = option;
    // feel free to add other methods, e.g. GFN-FF, AIMNET, etc.
    // these may not be available though
  }
  if (!bestOption.empty())
    return bestOption;
  else
    return "LJ"; // this will always work
}

} // namespace Avogadro::Calc
