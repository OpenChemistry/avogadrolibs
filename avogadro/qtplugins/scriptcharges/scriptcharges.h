/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SCRIPTCHARGES_H
#define AVOGADRO_QTPLUGINS_SCRIPTCHARGES_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QVariant>

namespace Avogadro {

namespace Calc {
class ChargeModel;
}

namespace QtPlugins {

/**
 * @brief This extension registers ChargeModel electrostatics
 * implemented as external scripts.
 */
class ScriptCharges : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ScriptCharges(QObject* parent = nullptr);
  ~ScriptCharges() override;

  QString name() const override { return tr("Script Charge Models"); }

  QString description() const override
  {
    return tr("Load electrostatic models from external scripts.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  /**
   * Handle a feature registered by PackageManager.
   */
  void registerFeature(const QString& type, const QString& packageDir,
                       const QString& command, const QString& identifier,
                       const QVariantMap& metadata);

private:
  QList<Calc::ChargeModel*> m_models;

  void refreshModels();
  void unregisterModels();
  void registerModels();
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SCRIPTCHARGES_H
