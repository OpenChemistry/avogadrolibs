/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_LENNARDJONES_H
#define AVOGADRO_CALC_LENNARDJONES_H

#include "energycalculator.h"

namespace Avogadro {
namespace Core {
class Molecule;
}

namespace Calc {

class LennardJones : public EnergyCalculator
{
public:
  LennardJones();
  ~LennardJones();

  virtual std::string identifier() const override
  { return "LJ"; }

  virtual std::string name() const override
  { return "Lennard-Jones"; }

  virtual std::string description() const override
  { return "Universal Lennard-Jones potential"; }

  virtual Real value(const Eigen::VectorXd& x) override;
  virtual void gradient(const Eigen::VectorXd& x,
                        Eigen::VectorXd& grad) override;

  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(Core::Molecule* mol) override;

protected:
  Core::Molecule* m_molecule;
  Eigen::MatrixXd m_radii;
  bool m_vdw;
  Real m_depth;
  int m_exponent;
};

} // namespace Calc
} // namespace Avogadro

#endif // AVOGADRO_CALC_LENNARDJONES_H
