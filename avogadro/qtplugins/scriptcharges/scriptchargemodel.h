/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SCRIPTCHARGEMODEL_H
#define AVOGADRO_QTPLUGINS_SCRIPTCHARGEMODEL_H

#include <avogadro/calc/chargemodel.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QString>
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

class ScriptChargeModel : public Avogadro::Calc::ChargeModel
{
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

  ScriptChargeModel(const QString& scriptFileName = "");
  ~ScriptChargeModel() override;

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

  ChargeModel* newInstance() const override;

  std::string identifier() const override { return m_identifier; }

  std::string name() const override { return m_name; }

  Core::Molecule::ElementMask elements() const override { return m_elements; }

  MatrixX partialCharges(Core::Molecule& mol) const override;
  MatrixX partialCharges(const Core::Molecule& mol) const override;

  double potential(Core::Molecule& mol, const Vector3& point) const override;

  bool supportsCharges() const { return m_partialCharges; }

  bool supportsElectrostatics() const { return m_electrostatics; }

  Core::Array<double> potentials(
    Core::Molecule& mol, const Core::Array<Vector3>& points) const override;

private:
  static Format stringToFormat(const std::string& str);
  static Io::FileFormat* createFileFormat(Format fmt);
  void resetMetaData();
  void readMetaData();
  bool parseString(const QJsonObject& ob, const QString& key, std::string& str);
  void processElementString(const QString& str);
  bool parseElements(const QJsonObject& ob);
  void copyMetaDataFrom(const ScriptChargeModel& other);

private:
  QtGui::PythonScript* m_interpreter;
  Format m_inputFormat;
  Core::Molecule::ElementMask m_elements;
  bool m_valid;
  bool m_partialCharges;
  bool m_electrostatics;

  std::string m_identifier;
  std::string m_name;
  std::string m_description;
  QString m_formatString;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SCRIPTCHARGEMODEL_H
