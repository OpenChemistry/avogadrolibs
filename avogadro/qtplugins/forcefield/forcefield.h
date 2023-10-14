/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_FORCEFIELD_H
#define AVOGADRO_QTPLUGINS_FORCEFIELD_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMultiMap>
#include <QtCore/QStringList>

class QAction;
class QDialog;

namespace Avogadro {

namespace Calc {
class EnergyCalculator;
}

namespace QtPlugins {

/**
 * @brief The Forcefield class implements the extension interface for
 *  forcefield (and other) optimization
 * @author Geoffrey R. Hutchison
 */
class Forcefield : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  enum Minimizer
  {
    SteepestDescent = 0,
    ConjugateGradients,
    LBFGS,
    FIRE,
  };

  explicit Forcefield(QObject* parent = 0);
  ~Forcefield() override;

  QString name() const override { return tr("Forcefield optimization"); }

  QString description() const override
  {
    return tr("Forcefield minimization, including scripts");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  /**
   * Scan for new scripts in the Forcefield directories.
   */
  void refreshScripts();
  void registerScripts();
  void unregisterScripts();

private slots:
  void energy();
  void optimize();
  void freezeSelected();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule = nullptr;

  // defaults
  Minimizer m_minimizer = LBFGS;
  unsigned int m_maxSteps = 250;
  unsigned int m_nSteps = 5;
  double m_tolerance = 1.0e-6;
  double m_gradientTolerance = 1.0e-4;
  Calc::EnergyCalculator *m_method = nullptr;

  QList<Calc::EnergyCalculator*> m_scripts;
};

}
}

#endif // AVOGADRO_QTPLUGINS_FORCEFIELD_H
