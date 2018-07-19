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
class Molecule;
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
  virtual void setMolecule(QtGui::Molecule* mol) = 0;

public:
  EnergyCalculator(QObject* parent_ = 0)
    : QObject(parent_){};
  ~EnergyCalculator() {}

  /**
   * Called to set the configuration (e.g., from a GUI options dialog)
   */
  virtual bool setConfiguration(Core::VariantMap& config) { return true; }

  virtual void gradient(const TVector &x, TVector &grad) override;

  /**
   * Called to 'clean' gradients @param grad (e.g., for constraints)
   */
  void cleanGradients(TVector &grad);
};

} // namespace Avogadro

#endif // AVOGADRO_ENERGYCALCULATOR_H
