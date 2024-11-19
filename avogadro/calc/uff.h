/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_UFF_H
#define AVOGADRO_CALC_UFF_H

#include "avogadrocalcexport.h"

#include <avogadro/calc/energycalculator.h>

namespace Avogadro {
namespace Core {
class Molecule;
}

namespace Calc {

class UFFPrivate;

class AVOGADROCALC_EXPORT UFF : public EnergyCalculator
{
public:
  UFF();
  ~UFF();

  std::string identifier() const override { return "UFF"; }

  std::string name() const override { return "UFF"; }

  std::string description() const override { return "Universal Force Field"; }

  Core::Molecule::ElementMask elements() const override { return (m_elements); }

  Real value(const Eigen::VectorXd& x) override;
  void gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad) override;

  /**
   * Called when the current molecule changes.
   */
  void setMolecule(Core::Molecule* mol) override;

protected:
  Core::Molecule* m_molecule;

  Core::Molecule::ElementMask m_elements;

  // track the particular calculations for a molecule
  UFFPrivate* d;
};

} // namespace Calc
} // namespace Avogadro

#endif // AVOGADRO_CALC_LENNARDJONES_H