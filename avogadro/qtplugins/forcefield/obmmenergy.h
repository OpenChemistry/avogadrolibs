/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OBMMENERGY_H
#define AVOGADRO_QTPLUGINS_OBMMENERGY_H

#include <avogadro/calc/energycalculator.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QProcess>
#include <QtCore/QString>
#include <QtCore/QTemporaryFile>

class QJsonObject;

namespace Avogadro {

namespace Io {
class FileFormat;
}

namespace QtPlugins {

class OBMMEnergy : public Avogadro::Calc::EnergyCalculator
{
  Q_DECLARE_TR_FUNCTIONS(OBMMEnergy)

public:
  /** Formats that may be written to the script's input. */
  enum Format
  {
    NotUsed,
    Cjson,
    Cml,
    Mdl, // sdf
    Pdb,
    Xyz
  };

  OBMMEnergy(const std::string& method = "");
  ~OBMMEnergy() override;

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

  /**
   * @brief Synchronous use of the QProcess.
   */
  QByteArray writeAndRead(const QByteArray& input);

private:
  Core::Molecule* m_molecule;
  Io::FileFormat* m_inputFormat;
  QProcess* m_process;
  QString m_executable;

  Core::Molecule::ElementMask m_elements;
  std::string m_identifier;
  std::string m_name;
  QString m_description;

  QTemporaryFile m_tempFile;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OBMMENERGY_H
