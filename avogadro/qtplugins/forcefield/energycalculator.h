/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_ENERGYCALCULATOR_H
#define AVOGADRO_ENERGYCALCULATOR_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/rwmolecule.h>

#include "cppoptlib/problem.h"

namespace Avogadro {
namespace QtGui {
class RWMolecule;
}

class EnergyCalculator
  : public QObject
  , public cppoptlib::Problem<Real>
{
  Q_OBJECT
public slots:
  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(QtGui::RWMolecule* mol) = 0;

public:
  EnergyCalculator(QObject* parent_ = 0)
    : QObject(parent_){};
  ~EnergyCalculator() {}

  /**
   * @return energy in kJ/mol for the current Molecule
   */
  virtual Real calculateEnergy() = 0;
  /**
   * @return energy in kJ/mol for the current Molecule and supplied positions
   */
  virtual Real calculateEnergy(const Core::Array<Vector3>& positions) = 0;

  virtual Real value(const TVector& x) override
  {
//    m_positions.data() = x.data();
    return calculateEnergy(m_positions);
  }

  /**
   * @return gradients for the current molecule
   */
  virtual Core::Array<Vector3> calculateGradients() = 0;
  /**
   * @return gradients for the current molecule at the supplied positions
   */
  virtual Core::Array<Vector3> calculateGradients(
    Core::Array<Vector3>& positions) = 0;

  virtual bool setConfiguration(Core::VariantMap& config) { return true; }

  virtual Core::VariantMap& configuration() { }

  Core::Array<Vector3> m_positions;
  Core::Array<Vector3> m_gradients;
};

} // namespace Avogadro

#endif // AVOGADRO_ENERGYCALCULATOR_H
