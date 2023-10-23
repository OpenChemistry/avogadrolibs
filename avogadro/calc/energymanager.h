/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_ENERGYMANAGER_H
#define AVOGADRO_CALC_ENERGYMANAGER_H

#include "avogadrocalcexport.h"

#include <avogadro/core/array.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace Calc {

class EnergyCalculator;

/**
 * @class EnergyManager chargemanager.h
 * <avogadro/calc/energymanager.h>
 * @brief Class to manage registration, searching and creation of force field
 * (energy) calculators.
 * @author Geoffrey R. Hutchison
 *
 * The energy manager is a singleton class that handles the runtime
 * registration, search, creation and eventual destruction of calculators
 * for geometry optimization and molecular dynamics.
 * It can be used to gain a listing of available models, register new
 * models, etc.
 *
 * All energy calculation can take place independent of this code, but for
 * automated registration and look up, this is the preferred API.
 */
class AVOGADROCALC_EXPORT EnergyManager
{
public:
  /**
   * Get the singleton instance of the energy manager. This instance should
   * not be deleted.
   */
  static EnergyManager& instance();

  /**
   * @brief Register a new model with the manager.
   * @param model An instance of the calculator to manage, the manager assumes
   * ownership of the object passed in.
   * @return True on success, false on failure.
   */
  static bool registerModel(EnergyCalculator* model);

  /**
   * @brief Unregister a charge model from the manager.
   * @param identifier The identifier for the model to remove.
   * @return True on success, false on failure.
   */
  static bool unregisterModel(const std::string& identifier);

  /**
   * Add the supplied @p model to the manager, registering its ID and other
   * relevant data for later lookup. The manager assumes ownership of the
   * supplied object.
   * @return True on success, false on failure.
   */
  bool addModel(EnergyCalculator* model);

  /**
   * Remove the model with the identifier @a identifier from the manager.
   * @return True on success, false on failure.
   */
  bool removeModel(const std::string& identifier);

  /**
   * New instance of the model for the specified @p identifier. Ownership
   * is passed to the caller.
   * @param identifier The unique identifier of the model.
   * @return Instance of the model, nullptr if not found. Ownership passes to
   * the caller.
   */
  EnergyCalculator* model(const std::string& identifier) const;

  /**
   * Get a list of all loaded identifiers
   */
  std::set<std::string> identifiers() const;

  /**
   * @brief Get a list of models that work for this molecule.
   *
   * This is probably the method you want to get a list for a user
   */
  std::set<std::string> identifiersForMolecule(
    const Core::Molecule& molecule) const;

  /**
   * @brief Get the name of the model for the specified identifier.
   *
   * The name is a user-visible string, and may be translated.
   * @param identifier The unique identifier of the model.
   * @return The name of the model, or an empty string if not found.
   */
  std::string nameForModel(const std::string& identifier) const;

  /**
   * Get any errors that have been logged when loading models.
   */
  std::string error() const;

private:
  typedef std::map<std::string, size_t> ModelIdMap;

  EnergyManager();
  ~EnergyManager();

  EnergyManager(const EnergyManager&);            // Not implemented.
  EnergyManager& operator=(const EnergyManager&); // Not implemented.

  /**
   * @brief Append warnings/errors to the error message string.
   * @param errorMessage The error message to append.
   */
  void appendError(const std::string& errorMessage);

  std::vector<EnergyCalculator*> m_models;
  mutable ModelIdMap m_identifiers;
  mutable std::map<std::string, std::string> m_identifierToName;

  std::string m_error;
};

} // namespace Calc
} // namespace Avogadro

#endif // AVOGADRO_CALC_ENERGYMANAGER_H
