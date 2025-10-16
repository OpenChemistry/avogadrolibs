/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/forcefield/forcefield.h"


namespace Avogadro::QtPlugins {

class ForcefieldFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit ForcefieldFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Forcefield(parent_);
    object->setObjectName("Forcefield");
    return object;
  }

  QString identifier() const override { return "Forcefield"; }

  QString description() const override { return "Force field optimization and dynamics"; }

};

} // namespace Avogadro::QtPlugins

#include "ForcefieldPlugin.moc"
