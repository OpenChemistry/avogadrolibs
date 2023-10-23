/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_CHARGEMANAGER_H
#define AVOGADRO_CALC_CHARGEMANAGER_H

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

class ChargeModel;

/**
 * @class ChargeManager chargemanager.h
 * <avogadro/calc/chargemanager.h>
 * @brief Class to manage registration, searching and creation of partial charge
 * models.
 * @author Geoffrey R. Hutchison
 *
 * The charge manager is a singleton class that handles the runtime
 * registration, search, creation and eventual destruction of electrostatics
 * models. It can be used to gain a listing of available models, register new
 * models, etc.
 *
 * All electrostatics can take place independent of this code, but for automated
 * registration and look up, this is the preferred API. It is possible to use
 * the convenience API without ever dealing directly with a model class.
 */

class AVOGADROCALC_EXPORT ChargeManager
{
public:
  /**
   * Get the singleton instance of the charge manager. This instance should
   * not be deleted.
   */
  static ChargeManager& instance();

  /**
   * @brief Register a new charge model with the manager.
   * @param model An instance of the model to manage, the manager assumes
   * ownership of the object passed in.
   * @return True on success, false on failure.
   */
  static bool registerModel(ChargeModel* model);

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
  bool addModel(ChargeModel* model);

  /**
   * Remove the model with the identifier @a identifier from the manager.
   * @return True on success, false on failure.
   */
  bool removeModel(const std::string& identifier);

  /**
   * Get a list of all loaded identifiers
   */
  std::set<std::string> identifiers() const;

  /**
   * @brief Get a list of models that work for this molecule.
   *
   * Includes partial charge types in the molecule itself (e.g., from a file)
   * This is probably the method you want to get a list for a user
   */
  std::set<std::string> identifiersForMolecule(
    const Core::Molecule& molecule) const;

  std::string nameForModel(const std::string& identifier) const;

  /**
   * Note that some models do not have well-defined atomic partial charges
   * @return atomic partial charges for the molecule, or 0.0 if undefined
   */
  MatrixX partialCharges(const std::string& identifier,
                         Core::Molecule& mol) const;

  /**
   * @return the potential at the point for the molecule, or 0.0 if the model is
   * not available
   */
  double potential(const std::string& identifier, Core::Molecule& mol,
                   const Vector3& point) const;

  /**
   * @return the potentials at the point for the molecule, or an array of 0.0 if
   * the model is not available
   */
  Core::Array<double> potentials(const std::string& identifier,
                                 Core::Molecule& mol,
                                 const Core::Array<Vector3>& points) const;

  /**
   * Get any errors that have been logged when loading models.
   */
  std::string error() const;

private:
  typedef std::map<std::string, size_t> ChargeIdMap;

  ChargeManager();
  ~ChargeManager();

  ChargeManager(const ChargeManager&);            // Not implemented.
  ChargeManager& operator=(const ChargeManager&); // Not implemented.

  /**
   * @brief Append warnings/errors to the error message string.
   * @param errorMessage The error message to append.
   */
  void appendError(const std::string& errorMessage);

  std::vector<ChargeModel*> m_models;
  mutable ChargeIdMap m_identifiers;
  mutable std::map<std::string, std::string> m_identifierToName;

  std::string m_error;
};

} // namespace Calc
} // namespace Avogadro

#endif // AVOGADRO_CALC_CHARGEMANAGER_H
