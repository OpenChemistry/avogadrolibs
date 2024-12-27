/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
  It links to the Open Babel library, which is released under the GNU GPL v2.
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OBENERGY_H
#define AVOGADRO_QTPLUGINS_OBENERGY_H

#include <avogadro/calc/energycalculator.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QString>

namespace Avogadro {

namespace QtPlugins {

class OBEnergy : public Avogadro::Calc::EnergyCalculator
{
  Q_DECLARE_TR_FUNCTIONS(OBEnergy)

public:
  OBEnergy(const std::string& method = "");
  ~OBEnergy() override;

  std::string method() const { return m_identifier; }
  void setupProcess();

  Calc::EnergyCalculator* newInstance() const override;

  std::string identifier() const override { return m_identifier; }
  std::string name() const override { return m_name; }
  std::string description() const override
  {
    return m_description.toStdString();
  }

  Core::Molecule::ElementMask elements() const override { return (m_elements); }

  // This will check if the molecule is valid for this script
  // and then start the external process
  void setMolecule(Core::Molecule* mol) override;
  // energy
  Real value(const Eigen::VectorXd& x) override;
  // gradient (which may be unsupported and fall back to numeric)
  void gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad) override;

  bool acceptsIons() const override { return true; }
  // UFF can handle radicals
  bool acceptsRadicals() const override;

private:
  class Private;

  Core::Molecule* m_molecule;
  Private* d;

  Core::Molecule::ElementMask m_elements;
  std::string m_identifier;
  std::string m_name;
  QString m_description;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OBENERGY_H
