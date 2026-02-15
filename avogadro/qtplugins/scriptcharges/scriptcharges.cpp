/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptcharges.h"

#include "scriptchargemodel.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>

#include <avogadro/qtgui/packagemanager.h>
#include <avogadro/qtgui/scriptloader.h>
#include <avogadro/qtgui/utilities.h>

#include <QtCore/QDebug>

namespace Avogadro::QtPlugins {

ScriptCharges::ScriptCharges(QObject* p) : ExtensionPlugin(p)
{
  refreshModels();

  // Connect to PackageManager for pyproject.toml-based packages
  auto* pm = QtGui::PackageManager::instance();
  connect(pm, &QtGui::PackageManager::featureRegistered, this,
          &ScriptCharges::registerFeature);
}

ScriptCharges::~ScriptCharges() {}

QList<QAction*> ScriptCharges::actions() const
{
  return QList<QAction*>();
}

QStringList ScriptCharges::menuPath(QAction*) const
{
  return QStringList();
}

void ScriptCharges::setMolecule(QtGui::Molecule*) {}

void ScriptCharges::refreshModels()
{
  unregisterModels();
  qDeleteAll(m_models);
  m_models.clear();

  QMultiMap<QString, QString> scriptPaths =
    QtGui::ScriptLoader::scriptList("charges");
  foreach (const QString& filePath, scriptPaths) {
    auto* model = new ScriptChargeModel(filePath);
    if (model->isValid())
      m_models.push_back(model);
    else
      delete model;
  }

  registerModels();
}

void ScriptCharges::unregisterModels()
{
  for (auto* model : m_models)
    Calc::ChargeManager::unregisterModel(model->identifier());
}

void ScriptCharges::registerModels()
{
  for (auto* model : m_models) {
    if (!Calc::ChargeManager::registerModel(model->newInstance())) {
      qDebug() << "Could not register model" << model->identifier().c_str()
               << "due to name conflict.";
    }
  }
}

void ScriptCharges::registerFeature(const QString& type,
                                    const QString& packageDir,
                                    const QString& command,
                                    const QString& identifier,
                                    const QVariantMap& metadata)
{
  if (type != QLatin1String("electrostatic-models"))
    return;

  auto* model = new ScriptChargeModel();
  model->setPackageInfo(packageDir, command, identifier);
  model->readMetaData(metadata);
  if (model->isValid()) {
    if (!Calc::ChargeManager::registerModel(model->newInstance())) {
      qDebug() << "Could not register charge model" << identifier
               << "due to name conflict.";
      delete model;
    } else {
      m_models.push_back(model);
    }
  } else {
    delete model;
  }
}

} // namespace Avogadro::QtPlugins
