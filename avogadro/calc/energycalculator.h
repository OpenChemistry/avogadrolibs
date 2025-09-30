/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_ENERGYCALCULATOR_H
#define AVOGADRO_CALC_ENERGYCALCULATOR_H

#include "avogadrocalcexport.h"

#include <avogadro/core/constraint.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/variantmap.h>
#include <avogadro/core/vector.h>

#include <cppoptlib/problem.h>

namespace Avogadro {
namespace Core {
class Molecule;
}

namespace Calc {

class AVOGADROCALC_EXPORT EnergyCalculator : public cppoptlib::Problem<Real>
{
public:
  EnergyCalculator() = default;
  ~EnergyCalculator() override = default;

  /**
   * Create a new instance of the model. Ownership passes to the
   * caller.
   */
  virtual EnergyCalculator* newInstance() const = 0;

  /**
   * @return a unique identifier for this calculator.
   */
  virtual std::string identifier() const = 0;

  /**
   * @return A short translatable name for this method (e.g., MMFF94, UFF, etc.)
   */
  virtual std::string name() const = 0;

  /**
   * @return a description of the method
   */
  virtual std::string description() const = 0;

  /**
   * Called to set the configuration (e.g., for a GUI options dialog)
   */
  virtual bool setConfiguration([[maybe_unused]] Core::VariantMap& config)
  {
    return true;
  }

  /**
   * @brief Indicate if your method only treats a subset of elements
   * @return an element mask corresponding to the defined subset
   */
  virtual Core::Molecule::ElementMask elements() const = 0;

  /**
   * @brief Indicate if your method can handle unit cells
   * @return true if unit cells are supported
   */
  virtual bool acceptsUnitCell() const { return false; }

  /**
   * @brief Indicate if your method can handle ions
   * Many methods only treat neutral systems, either
   * a neutral molecule or a neutral unit cell.
   *
   * @return true if ions are supported
   */
  virtual bool acceptsIons() const { return false; }

  /**
   * @brief Indicate if your method can handle radicals
   * Most methods only treat closed-shell molecules.
   * @return true if radicals are supported
   */
  virtual bool acceptsRadicals() const { return false; }

  /**
   * Calculate the gradients for this method, defaulting to numerical
   * finite-difference methods
   */
  void gradient(const TVector& x, TVector& grad) override;

  /**
   * Called to 'clean' gradients @param grad (e.g., for constraints)
   */
  void cleanGradients(TVector& grad);

  /**
   * Called to get the energies for the current set of constraints.
   * which should be added to the value() method for real energies
   * in derived classes
   * @return the sum of the constraint energies
   */
  Real constraintEnergies(const TVector& x);

  /**
   * Called to get the gradients for the current set of constraints.
   * which should be added to the gradient() method in derived classes.
   * @param x the current coordinates
   * @param grad the gradient vector to be updated with constraint gradients
   */
  void constraintGradients(const TVector& x, TVector& grad);

  /**
   * Called to get the constraints for this method.
   * @return the constraints for this method
   */
  std::vector<Core::Constraint> constraints() const;

  // Set the constraints for this method
  void setConstraints(const std::vector<Core::Constraint>& constraints);

  /**
   * Called to update the "frozen" mask (e.g., during editing)
   */
  void setMask(TVector mask) { m_mask = mask; }

  /**
   * @return the frozen atoms mask
   */
  TVector mask() const { return m_mask; }

  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(Core::Molecule* mol) = 0;

protected:
  /**
   * @brief Append an error to the error string for the model.
   * @param errorString The error to be added.
   * @param newLine Add a new line after the error string?
   */
  void appendError(const std::string& errorString, bool newLine = true) const;

  TVector m_mask; // optimize or frozen atom mask
  // Separate the constraints into different types
  // for speed and convenience.
  std::vector<Core::Constraint> m_distanceConstraints;
  std::vector<Core::Constraint> m_angleConstraints;
  std::vector<Core::Constraint> m_torsionConstraints;
  std::vector<Core::Constraint> m_outOfPlaneConstraints;

private:
  mutable std::string m_error;
};

} // end namespace Calc
} // end namespace Avogadro

#endif // AVOGADRO_CALC_ENERGYCALCULATOR_H
