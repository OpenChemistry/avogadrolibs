/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_CHARGEMODEL_H
#define AVOGADRO_CALC_CHARGEMODEL_H

#include "avogadrocalcexport.h"

#include <avogadro/core/array.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <string>
#include <vector>

namespace Avogadro {

namespace Calc {

/**
 * @class ChargeModel chargemodel.h <avogadro/calc/chargemodel.h>
 * @brief General API for charge / electrostatics models
 * @author Geoffrey R. Hutchison
 *
 * This serves as the common base class for electrostatics models.
 * Many use atomic point charges, but we also allow for custom models
 * for Slater / Gaussian distributions, distributed electrostatics,
 * use of quantum mechanics, etc.
 *
 * Key methods are to determine either atomic partial charges or
 * electrostatic potentials at particular points in space.
 *
 * There is a default implementation for the electrostatic potential
 * at points in space, based on the atomic partial charges. If you
 * implement a different mechanism, you should override this method.
 */

class AVOGADROCALC_EXPORT ChargeModel
{
public:
  ChargeModel();
  virtual ~ChargeModel();

  /**
   * Create a new instance of the model. Ownership passes to the
   * caller.
   */
  virtual ChargeModel* newInstance() const = 0;

  /**
   * @brief A unique identifier, used to retrieve models programmatically.
   * EEM2, NPA, etc. A runtime warning will be generated if the identifier
   * is not unique.
   */
  virtual std::string identifier() const = 0;

  /**
   * @brief A user-visible name of the model (e.g., "Natural Population
   * Analysis")
   */
  virtual std::string name() const = 0;

  /**
   * @brief Indicate if your method only treats a subset of elements
   * @return an element mask corresponding to the defined subset
   */
  virtual Core::Molecule::ElementMask elements() const = 0;

  /**
   * Set the dielectric constant for the model.
   * @param dielectric constant.
   */
  virtual void setDielectric(double dielectric) { m_dielectric = dielectric; };

  /**
   * @return The dielectric constant.
   */
  virtual float dielectric() const { return m_dielectric; }

  virtual MatrixX partialCharges(Core::Molecule& mol) const = 0;

  /**
   * @brief Calculate the electrostatic potential at a particular point in
   * space.
   * @param mol The molecule to calculate the potential for.
   * @param point The point in space to calculate the potential at.
   * @return The electrostatic potential at the point.
   */
  virtual double potential(Core::Molecule& mol, const Vector3& point) const;

  /**
   * @brief Calculate the electrostatic potential at multiple points
   * @param mol The molecule to calculate the potential for.
   * @param array The points in space to calculate the potential at.
   * @return The electrostatic potential at the points in an array.
   *
   * This method is used for batch calculation and defaults to simply
   * calculating each point at a time. Some methods work faster in batches.
   */
  virtual Core::Array<double> potentials(
    Core::Molecule& mol, const Core::Array<Vector3>& points) const;

protected:
  /**
   * @brief Append an error to the error string for the model.
   * @param errorString The error to be added.
   * @param newLine Add a new line after the error string?
   */
  void appendError(const std::string& errorString, bool newLine = true) const;

private:
  mutable std::string m_error;

  float m_dielectric;
};

} // namespace Calc
} // namespace Avogadro

#endif // AVOGADRO_CALC_CHARGEMODEL_H
