/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptcharges.h"

#include "scriptchargemodel.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/calc/chargemodel.h>

#include <avogadro/qtgui/scriptloader.h>
#include <avogadro/qtgui/utilities.h>

#include <QtCore/QDebug>

namespace Avogadro::QtPlugins {

ScriptCharges::ScriptCharges(QObject* p) : ExtensionPlugin(p)
{
  refreshModels();
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

  QMap<QString, QString> scriptPaths =
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
  for (QList<Calc::ChargeModel*>::const_iterator it = m_models.constBegin(),
                                                 itEnd = m_models.constEnd();
       it != itEnd; ++it) {
    Calc::ChargeManager::unregisterModel((*it)->identifier());
  }
}

void ScriptCharges::registerModels()
{
  for (QList<Calc::ChargeModel*>::const_iterator it = m_models.constBegin(),
                                                 itEnd = m_models.constEnd();
       it != itEnd; ++it) {
    if (!Calc::ChargeManager::registerModel((*it)->newInstance()) ) {
      qDebug() << "Could not register model" << (*it)->identifier().c_str()
               << "due to name conflict.";
    }
  }
}

} // end namespace Avogadro
