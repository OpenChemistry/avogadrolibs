/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/scriptcharges/scriptcharges.h"


namespace Avogadro::QtPlugins {

class ScriptChargesFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit ScriptChargesFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new ScriptCharges(parent_);
    object->setObjectName("ScriptCharges");
    return object;
  }

  QString identifier() const override { return "ScriptCharges"; }

  QString description() const override { return "Scriptable electrostatics models"; }

};

} // namespace Avogadro::QtPlugins

#include "ScriptChargesPlugin.moc"
