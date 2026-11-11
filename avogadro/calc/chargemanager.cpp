/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "chargemanager.h"
#include "chargemodel.h"
#include "defaultmodel.h"

#include <avogadro/core/utilities.h>

#include <optional>

namespace Avogadro::Calc {

using Core::toLower;

namespace {
// Finds the key under which the molecule stores charges for this identifier.
// Readers store types verbatim ("Mulliken", "From File"), so try the exact
// name first and then the lowercase one.
std::optional<std::string> moleculeChargeKey(const Core::Molecule& molecule,
                                             const std::string& identifier)
{
  const auto types = molecule.partialChargeTypes();
  if (types.find(identifier) != types.end())
    return identifier;
  const std::string lowerId = toLower(identifier);
  if (types.find(lowerId) != types.end())
    return lowerId;
  return std::nullopt;
}
} // namespace

const ChargeModel* ChargeManager::registeredModel(
  const std::string& identifier) const
{
  const auto it = m_identifiers.find(toLower(identifier));
  return it == m_identifiers.end() ? nullptr : m_models[it->second];
}

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
  std::string lowerId = toLower(model->identifier());
  m_identifiers[lowerId] = index;
  m_identifierToName[lowerId] = model->name();

  return true;
}

bool ChargeManager::removeModel(const std::string& identifier)
{
  std::string lowerId = toLower(identifier);

  const auto it = m_identifiers.find(lowerId);
  if (it == m_identifiers.end()) {
    appendError("Model " + identifier + " was not loaded.");
    return false;
  }

  const auto ids = it->second;
  m_identifiers.erase(lowerId);
  m_identifierToName.erase(lowerId);

  ChargeModel* model = m_models[ids];

  if (model != nullptr) {
    m_models[ids] = nullptr;
    delete model;
  }

  return true;
}

std::string ChargeManager::nameForModel(const std::string& identifier) const
{
  std::string lowerId = toLower(identifier);

  auto it = m_identifierToName.find(lowerId);
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
  for (auto& m_model : m_models) {
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
  for (auto* m_model : m_models) {
    if (m_model == nullptr)
      continue;
    // We check that every element in the molecule
    // is handled by the model
    auto mask = m_model->elements() & molecule.elements();
    if (mask.count() == molecule.elements().count())
      identifiers.insert(m_model->identifier()); // this one will work
  }

  return identifiers;
}

// order of preference for the built-in methods
const std::vector<std::string> METHOD_TIER_LIST = { "eem", "mmff94",
                                                    "gasteiger" };

std::string ChargeManager::recommendedModel(
  const Core::Molecule& molecule) const
{
  auto identifiers = identifiersForMolecule(molecule);

  // first, we look through the identifiers to see if there's
  // something not in the built-in list
  // i.e., read from a file or installed by a user, try that first
  for (auto option : identifiers) {
    if (std::find(METHOD_TIER_LIST.begin(), METHOD_TIER_LIST.end(), option) ==
        METHOD_TIER_LIST.end())
      return option;
  }

  // if not, we look through the built-in list in order
  // of preference (e.g., eem > mmff94 > gasteiger)
  for (auto option : METHOD_TIER_LIST) {
    if (identifiers.find(option) != identifiers.end()) {
      return option;
    }
  }
  return "";
}

MatrixX ChargeManager::partialCharges(const std::string& identifier,
                                      Core::Molecule& molecule) const
{
  // first check if the type is found in the molecule
  // (i.e., read from a file not computed dynamically)
  if (const auto key = moleculeChargeKey(molecule, identifier))
    return molecule.partialCharges(*key);

  // otherwise go through our list
  const ChargeModel* model = registeredModel(identifier);
  if (model == nullptr) {
    MatrixX charges(molecule.atomCount(),
                    1); // we have to return something, so zeros
    return charges;
  }

  return model->partialCharges(molecule);
}

Vector3 ChargeManager::dipoleMoment(const std::string& identifier,
                                    const Core::Molecule& molecule) const
{
  // If the type is found in the molecule
  // we'll use the DefaultModel to handle the dipole moment
  if (const auto key = moleculeChargeKey(molecule, identifier)) {
    DefaultModel model(*key); // so it knows which charges to use
    return model.dipoleMoment(molecule);
  }

  // otherwise go through our list
  const ChargeModel* model = registeredModel(identifier);
  if (model == nullptr || molecule.atomCount() < 2)
    return Vector3(0.0, 0.0, 0.0);

  return model->dipoleMoment(molecule);
}

double ChargeManager::potential(const std::string& identifier,
                                Core::Molecule& molecule,
                                const Vector3& point) const
{
  // If the type is found in the molecule
  // we'll use the DefaultModel to handle the potential
  if (const auto key = moleculeChargeKey(molecule, identifier)) {
    DefaultModel model(*key); // so it knows which charges to use
    return model.potential(molecule, point);
  }

  // otherwise go through our list
  const ChargeModel* model = registeredModel(identifier);
  return model == nullptr ? 0.0 : model->potential(molecule, point);
}

Core::Array<double> ChargeManager::potentials(
  const std::string& identifier, Core::Molecule& molecule,
  const Core::Array<Vector3>& points) const
{
  // As above
  if (const auto key = moleculeChargeKey(molecule, identifier)) {
    DefaultModel model(*key); // so it knows which charges to use
    return model.potentials(molecule, points);
  }

  const ChargeModel* model = registeredModel(identifier);
  if (model == nullptr)
    return Core::Array<double>(points.size(), 0.0);

  return model->potentials(molecule, points);
}

bool ChargeManager::hasCustomPotentials(const std::string& identifier,
                                        const Core::Molecule& molecule) const
{
  // Mirrors potentials(): charges stored in the molecule use DefaultModel
  if (moleculeChargeKey(molecule, identifier))
    return false;

  const ChargeModel* model = registeredModel(identifier);
  return model != nullptr && model->hasCustomPotentials();
}

} // namespace Avogadro::Calc
