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

#include <cstddef>
#include <string>

namespace Avogadro::Calc {

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
  ChargeModel() = default;
  virtual ~ChargeModel() = default;

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
  virtual void setDielectric(float dielectric) { m_dielectric = dielectric; };

  /**
   * @return The dielectric constant.
   */
  virtual float dielectric() const { return m_dielectric; }

  virtual MatrixX partialCharges(Core::Molecule& mol) const = 0;

  virtual MatrixX partialCharges(const Core::Molecule& mol) const = 0;

  /**
   * @brief Calculate the dipole moment of the molecule.
   *
   * Defaults to using the partial charges and atomic positions
   * to calculate the net dipole moment.
   * @return The dipole moment vector of the molecule
   */
  virtual Vector3 dipoleMoment(const Core::Molecule& mol) const;

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
   * @param points The points in space to calculate the potential at.
   * @return The electrostatic potential at the points in an array.
   *
   * This method is used for batch calculation. The default implementation
   * evaluates the point-charge model directly (using the same math as
   * potential()), in parallel across the points. Subclasses that override
   * potential() should also override this method, since the default does not
   * call potential().
   */
  virtual Core::Array<double> potentials(
    Core::Molecule& mol, const Core::Array<Vector3>& points) const;

  /**
   * @brief Point-charge electrostatic potential at many points, in parallel.
   *
   * Computes sum(q[i] / |r[i] - point|) over the atoms (skipping distances of
   * 0.01 or less) divided by the dielectric constant, for each point. This is
   * what the default potentials() uses, and gives bit-identical results to
   * the default potential(). It has no shared state and does not use any
   * model, so it is safe to call from any thread.
   * @param charges The partial charge of each atom.
   * @param atomPositions The position of each atom.
   * @param atomCount The number of atoms (entries in both arrays).
   * @param points The points in space to calculate the potential at.
   * @param dielectric The dielectric constant; values that are not positive
   *        and finite are treated as 1.
   * @param maxThreads 0 chooses automatically from the hardware and the
   *        amount of work (small jobs stay on the calling thread). A positive
   *        value uses up to that many threads, whatever the amount of work.
   * @return The potentials, one per point.
   */
  static Core::Array<double> pointChargePotentials(
    const double* charges, const Vector3* atomPositions, std::size_t atomCount,
    const Core::Array<Vector3>& points, double dielectric,
    std::size_t maxThreads = 0);

  /**
   * @return true if potential() / potentials() are computed by something
   * other than the point-charge model on partialCharges() (for example an
   * external script). Such models can not be replaced by evaluating the
   * partial charges directly, and are not safe to call from another thread
   * while the model is in use elsewhere. The default is false.
   */
  virtual bool hasCustomPotentials() const { return false; }

protected:
  /**
   * @brief Append an error to the error string for the model.
   * @param errorString The error to be added.
   * @param newLine Add a new line after the error string?
   */
  void appendError(const std::string& errorString, bool newLine = true) const;

private:
  mutable std::string m_error;

  float m_dielectric = 1.0f;
};

} // namespace Avogadro::Calc

#endif // AVOGADRO_CALC_CHARGEMODEL_H
