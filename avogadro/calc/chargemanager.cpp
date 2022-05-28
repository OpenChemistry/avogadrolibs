/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "chargemanager.h"
#include "chargemodel.h"

#include <algorithm>
#include <memory>

using std::unique_ptr;

namespace Avogadro {
namespace Calc {

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
  if (!model) {
    appendError("Supplied model was null.");
    return false;
  }
  if (m_identifiers.count(model->identifier()) > 0) {
    appendError("Model " + model->identifier() + " already loaded.");
    return false;
  }
  for (std::vector<ChargeModel*>::const_iterator it = m_models.begin();
       it != m_models.end(); ++it) {
    if (*it == model) {
      appendError("The model object was already loaded.");
      return false;
    }
  }

  // If we got here then the format is unique enough to be added.
  size_t index = m_models.size();
  m_models.push_back(model);
  m_identifiers[model->identifier()].push_back(index);

  return true;
}

namespace {
// Lookup each key from "keys" in "map", and remove "val" from the Map's
// data value (which is a vector of ValueType)
template <typename Map, typename VectorOfKeys, typename ValueType>
void removeFromMap(Map& map, const VectorOfKeys& keys, const ValueType& val)
{
  typedef typename VectorOfKeys::const_iterator KeysIter;
  for (KeysIter key = keys.begin(), keyEnd = keys.end(); key != keyEnd; ++key) {
    typename Map::iterator mapMatch = map.find(*key);
    if (mapMatch == map.end())
      continue;
    typename Map::mapped_type& vec = mapMatch->second;
    if (vec.size() <= 1) {
      map.erase(*key);
    } else {
      typename Map::mapped_type::iterator newEnd =
        std::remove(vec.begin(), vec.end(), val);
      vec.resize(newEnd - vec.begin());
    }
  }
}
} // namespace

bool ChargeManager::removeModel(const std::string& identifier)
{
  ChargeIdVector ids = m_identifiers[identifier];
  m_identifiers.erase(identifier);

  if (ids.empty())
    return false;

  for (ChargeIdVector::const_iterator it = ids.begin(), itEnd = ids.end();
       it != itEnd; ++it) {
    ChargeModel* model = m_models[*it];

    if (model == nullptr)
      continue;

    m_models[*it] = nullptr;
    delete model;
  }

  return true;
}

ChargeManager::ChargeManager()
{
  // add any default models (EEM maybe?)
}

ChargeManager::~ChargeManager()
{
  // Delete the models that were loaded.
  for (std::vector<ChargeModel*>::const_iterator it = m_models.begin();
       it != m_models.end(); ++it) {
    delete (*it);
  }
  m_models.clear();
}

} // namespace Calc
} // namespace Avogadro
