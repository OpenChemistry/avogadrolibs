/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_LENNARDJONES_H
#define AVOGADRO_QTGUI_LENNARDJONES_H

#include "energycalculator.h"

namespace Avogadro {
namespace QtGui {
class Molecule;
}

class LennardJones : public EnergyCalculator
{
  Q_OBJECT

public:
  explicit LennardJones(QObject* parent_ = 0);
  ~LennardJones();

  virtual QString name() const override
  { return tr("Lennard-Jones"); }

  virtual QString description() const override
  { return tr("Universal Lennard-Jones potential"); }

  virtual Real value(const Eigen::VectorXd& x) override;
  virtual void gradient(const Eigen::VectorXd& x,
                        Eigen::VectorXd& grad) override;

public slots:
  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(QtGui::Molecule* mol) override;

protected:
  QtGui::Molecule* m_molecule;
  Eigen::MatrixXd m_radii;
  bool m_vdw;
  Real m_depth;
  int m_exponent;
};

} // namespace Avogadro

#endif // AVOGADRO_QTGUI_LENNARDJONES_H
