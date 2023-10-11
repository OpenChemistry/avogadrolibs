/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_ENERGYCALCULATOR_H
#define AVOGADRO_CALC_ENERGYCALCULATOR_H

#include "avogadrocalcexport.h"

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
  EnergyCalculator() {}
  ~EnergyCalculator() {}

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
  virtual bool setConfiguration(Core::VariantMap& config) { return true; }

  /**
   * Calculate the gradients for this method, defaulting to numerical
   * finite-difference methods
   */
  virtual void gradient(const TVector& x, TVector& grad) override;

  /**
   * Called to 'clean' gradients @param grad (e.g., for constraints)
   */
  void cleanGradients(TVector& grad);

  /**
   * Called to update the "frozen" mask (e.g., during editing)
   */
  void setMask(TVector mask) { m_mask = mask; }

  /**
   * @return the frozen atoms mask
   */
  TVector mask() const { return m_mask; }

  void freezeAtom(Index atomId);
  void unfreezeAtom(Index atomId);

  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(Core::Molecule* mol) = 0;

protected:
  TVector m_mask; // optimize or frozen atom mask
};

} // end namespace Calc
} // end namespace Avogadro

#endif // AVOGADRO_CALC_ENERGYCALCULATOR_H
