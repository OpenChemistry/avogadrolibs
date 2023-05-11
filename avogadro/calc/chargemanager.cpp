/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "chargemanager.h"
#include "chargemodel.h"
#include "defaultmodel.h"

#include <algorithm>
#include <memory>


namespace Avogadro::Calc {

ChargeManager& ChargeManager::instance()
{
  static ChargeManager instance;
  return instance;
}

void ChargeManager::appendError(const std::string& errorMessage)
{
  m_error += errorMessage + "\n";
}

bool ChargeManager::registerModel(ChargeModel* model)
{
  return instance().addModel(model);
}

bool ChargeManager::unregisterModel(const std::string& identifier)
{
  return instance().removeModel(identifier);
}

bool ChargeManager::addModel(ChargeModel* model)
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

bool ChargeManager::removeModel(const std::string& identifier)
{
  auto ids = m_identifiers[identifier];
  m_identifiers.erase(identifier);
  m_identifierToName.erase(identifier);

  ChargeModel* model = m_models[ids];

  if (model != nullptr) {
    m_models[ids] = nullptr;
    delete model;
  }

  return true;
}

std::string ChargeManager::nameForModel(const std::string& identifier) const
{
  auto it = m_identifierToName.find(identifier);
  if (it == m_identifierToName.end()) {
    return identifier;
  }
  return it->second;
}

ChargeManager::ChargeManager()
{
  // add any default models here (EEM maybe?)
}

ChargeManager::~ChargeManager()
{
  // Delete the models that were loaded.
  for (auto & m_model : m_models) {
    delete m_model;
  }
  m_models.clear();
}

std::set<std::string> ChargeManager::identifiersForMolecule(
  const Core::Molecule& molecule) const
{
  // start with the types already in the molecule
  std::set<std::string> identifiers = molecule.partialChargeTypes();

  // check our models for compatibility
  for (auto m_model : m_models) {

    // We check that every element in the molecule
    // is handled by the model
    auto mask = m_model->elements() & molecule.elements();
    if (mask.count() == molecule.elements().count())
      identifiers.insert(m_model->identifier()); // this one will work
  }

  return identifiers;
}

MatrixX ChargeManager::partialCharges(
  const std::string& identifier, Core::Molecule& molecule) const
{
  // first check if the type is found in the molecule
  // (i.e., read from a file not computed dynamically)
  auto molIdentifiers = molecule.partialChargeTypes();

  if (molIdentifiers.find(identifier) != molIdentifiers.end()) {
    return molecule.partialCharges(identifier);
  }

  // otherwise go through our list
  if (m_identifiers.find(identifier) == m_identifiers.end()) {
    MatrixX charges(molecule.atomCount(),
                    1); // we have to return something, so zeros
    return charges;
  }

  const auto id = m_identifiers[identifier];
  const ChargeModel* model = m_models[id];
  return model->partialCharges(molecule);
}

double ChargeManager::potential(const std::string& identifier,
                                Core::Molecule& molecule,
                                const Vector3& point) const
{
  // If the type is found in the molecule
  // we'll use the DefaultModel to handle the potential
  auto molIdentifiers = molecule.partialChargeTypes();

  if (molIdentifiers.find(identifier) != molIdentifiers.end()) {
    DefaultModel model(identifier); // so it knows which charges to use
    return model.potential(molecule, point);
  }

  // otherwise go through our list
  if (m_identifiers.find(identifier) == m_identifiers.end()) {
    return 0.0;
  }

  const auto id = m_identifiers[identifier];
  const ChargeModel* model = m_models[id];
  return model->potential(molecule, point);
}

Core::Array<double> ChargeManager::potentials(
  const std::string& identifier, Core::Molecule& molecule,
  const Core::Array<Vector3>& points) const
{
  // As above
  auto molIdentifiers = molecule.partialChargeTypes();

  if (molIdentifiers.find(identifier) != molIdentifiers.end()) {
    DefaultModel model(identifier); // so it knows which charges to use
    return model.potentials(molecule, points);
  }

  if (m_identifiers.find(identifier) == m_identifiers.end()) {
    Core::Array<double> potentials(points.size(), 0.0);
    return potentials;
  }

  const auto id = m_identifiers[identifier];
  const ChargeModel* model = m_models[id];
  return model->potentials(molecule, points);
}

} // namespace Avogadro
