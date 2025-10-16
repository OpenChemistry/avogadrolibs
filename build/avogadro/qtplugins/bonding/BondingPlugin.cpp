/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/bonding/bonding.h"


namespace Avogadro::QtPlugins {

class BondingFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit BondingFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new Bonding(parent_);
    object->setObjectName("Bonding");
    return object;
  }

  QString identifier() const override { return "Bonding"; }

  QString description() const override { return "Perform bonding operations."; }

};

} // namespace Avogadro::QtPlugins

#include "BondingPlugin.moc"
