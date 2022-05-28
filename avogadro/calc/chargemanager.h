/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_CHARGEMANAGER_H
#define AVOGADRO_CALC_CHARGEMANAGER_H

#include "avogadrocalcexport.h"

#include <map>
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
   * @param format An instance of the format to manage, the manager assumes
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
   * New instance of the model for the specified @p identifier. Ownership
   * is passed to the caller.
   * @param identifier The unique identifier of the format.
   * @return Instance of the format, nullptr if not found. Ownership passes to
   * the
   * caller.
   */
  ChargeModel* newModelFromIdentifier(const std::string& identifier) const;

  /**
   * Get a list of all loaded identifiers
   */
  std::vector<std::string> identifiers() const;

  /**
   * Get any errors that have been logged when loading models.
   */
  std::string error() const;

private:
  typedef std::vector<size_t> ChargeIdVector;
  typedef std::map<std::string, ChargeIdVector> ChargeIdMap;

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

  ChargeIdMap m_identifiers;

  std::string m_error;
};

} // namespace Calc
} // namespace Avogadro

#endif // AVOGADRO_CALC_CHARGEMANAGER_H
