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
  ~UFF() override;

  UFF* newInstance() const override { return new UFF; }

  std::string identifier() const override { return "UFF"; }

  std::string name() const override { return "UFF"; }

  std::string description() const override { return "Universal Force Field"; }

  Core::Molecule::ElementMask elements() const override { return (m_elements); }

  Real value(const Eigen::VectorXd& x) override;
  void gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad) override;

  // handle both ions and radicals
  // (at least we will do what we can)
  bool acceptsIons() const override { return true; }
  bool acceptsRadicals() const override { return true; }
  bool acceptsUnitCell() const override { return true; }

  // components
  Real bondEnergy(const Eigen::VectorXd& x);
  Real angleEnergy(const Eigen::VectorXd& x);
  Real oopEnergy(const Eigen::VectorXd& x);
  Real torsionEnergy(const Eigen::VectorXd& x);
  Real vdwEnergy(const Eigen::VectorXd& x);

  void bondGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad);
  void angleGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad);
  void oopGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad);
  void torsionGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad);
  void vdwGradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad);

  /**
   * Called when the current molecule changes.
   */
  void setMolecule(Core::Molecule* mol) override;

protected:
  Core::Molecule* m_molecule;

  Core::Molecule::ElementMask m_elements;

  // track the particular calculations for a molecule
  UFFPrivate* d = nullptr;
};

} // namespace Calc
} // namespace Avogadro

#endif // AVOGADRO_CALC_UFF_H
