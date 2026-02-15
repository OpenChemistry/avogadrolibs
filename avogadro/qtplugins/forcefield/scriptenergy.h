/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SCRIPTENERGY_H
#define AVOGADRO_QTPLUGINS_SCRIPTENERGY_H

#include <avogadro/calc/energycalculator.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QString>
#include <QtCore/QTemporaryFile>
#include <QtCore/QVariantMap>

class QJsonObject;

namespace Avogadro {

namespace Io {
class FileFormat;
}

namespace QtGui {
class PythonScript;
}

namespace QtPlugins {

class ScriptEnergy : public Avogadro::Calc::EnergyCalculator
{
  Q_DECLARE_TR_FUNCTIONS(ScriptEnergy)

public:
  /** Formats that may be written to the script's input. */
  enum Format
  {
    NotUsed,
    Cjson,
    Cml,
    Mdl,
    Pdb,
    Sdf,
    Xyz
  };

  ScriptEnergy(const QString& scriptFileName = "");
  ~ScriptEnergy() override;

  /**
   * Configure the interpreter for package-based (pixi) execution.
   */
  void setPackageInfo(const QString& packageDir, const QString& command,
                      const QString& identifier);

  /**
   * Populate metadata fields from a QVariantMap (e.g. from pyproject.toml)
   * instead of calling the script with --metadata.
   */
  void readMetaData(const QVariantMap& metadata);

  QString scriptFilePath() const;

  Format inputFormat() const { return m_inputFormat; }
  bool isValid() const { return m_valid; }

  Calc::EnergyCalculator* newInstance() const override;

  std::string identifier() const override { return m_identifier; }
  std::string name() const override { return m_name; }
  std::string description() const override { return m_description; }

  Core::Molecule::ElementMask elements() const override { return m_elements; }
  bool supportsGradients() const { return m_gradients; }
  bool acceptsIons() const override { return m_ions; }
  bool acceptsRadicals() const override { return m_radicals; }
  bool acceptsUnitCell() const override { return m_unitCells; }

  // This will check if the molecule is valid for this script
  // and then start the external process
  void setMolecule(Core::Molecule* mol) override;
  // energy
  Real value(const Eigen::VectorXd& x) override;
  // gradient (which may be unsupported and fall back to numeric)
  void gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad) override;

private:
  static Format stringToFormat(const std::string& str);
  static Io::FileFormat* createFileFormat(Format fmt);
  void resetMetaData();
  void readMetaData();
  bool parseString(const QJsonObject& ob, const QString& key, std::string& str);
  void processElementString(const QString& str);
  bool parseElements(const QJsonObject& ob);
  void copyMetaDataFrom(const ScriptEnergy& other);

private:
  QtGui::PythonScript* m_interpreter;
  Format m_inputFormat;
  Core::Molecule* m_molecule;

  // what's supported by this script
  Core::Molecule::ElementMask m_elements;
  bool m_valid;
  bool m_gradients;
  bool m_ions;
  bool m_radicals;
  bool m_unitCells;

  std::string m_identifier;
  std::string m_name;
  std::string m_description;
  QString m_formatString;
  QTemporaryFile m_tempFile;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SCRIPTENERGY_H
