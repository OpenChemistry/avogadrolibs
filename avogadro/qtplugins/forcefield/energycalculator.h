/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_ENERGYCALCULATOR_H
#define AVOGADRO_ENERGYCALCULATOR_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <cppoptlib/problem.h>

namespace Avogadro {
namespace QtGui {
class Molecule;
}

class EnergyCalculator
  : public QObject
  , public cppoptlib::Problem<Real>
{
  Q_OBJECT
public:
  EnergyCalculator(QObject* parent_ = 0)
    : QObject(parent_){};
  ~EnergyCalculator() { }

  /**
   * @return A short translatable name for this method (e.g., MMFF94, UFF, etc.)
   */
  virtual QString name() const = 0;

  /**
   * @return a description of the method
   */
  virtual QString description() const = 0;

  /**
   * Called to set the configuration (e.g., from a GUI options dialog)
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

  void freezeAtom(Index atomId);
  void unfreezeAtom(Index atomId);

public slots:
  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(QtGui::Molecule* mol) = 0;

protected:
  TVector   m_mask; // optimize or frozen atom mask
};

} // namespace Avogadro

#endif // AVOGADRO_ENERGYCALCULATOR_H
