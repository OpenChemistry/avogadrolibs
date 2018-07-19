/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_LENNARDJONES_H
#define AVOGADRO_QTGUI_LENNARDJONES_H

#include "energycalculator.h"

namespace Avogadro {
namespace QtGui {
class RWMolecule;
}

class LennardJones : public EnergyCalculator
{
  Q_OBJECT

public:
  explicit LennardJones(QObject* parent_ = 0);
  ~LennardJones();

  virtual Real calculateEnergy() override;
  virtual Real calculateEnergy(
    const Core::Array<Vector3>& positions) override;

  virtual void calculateGradients() override;
  virtual void calculateGradients(
    Core::Array<Vector3>& positions,
    Core::Array<Vector3>& gradients) override;

public slots:
  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(QtGui::RWMolecule* mol) override;

protected:
  QtGui::RWMolecule* m_molecule;
  Eigen::MatrixXd m_radii;
  bool m_vdw;
  Real m_depth;
  unsigned int m_exponent;
};

} // namespace Avogadro

#endif // AVOGADRO_QTGUI_LENNARDJONES_H
